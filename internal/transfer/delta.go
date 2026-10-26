package transfer

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// 块级增量（delta）传输。
//
// 思路：接收端在发 HAVE 行时，顺带把**目标位置已有文件**的分块哈希发过去；
// 发送端对要发的每块算哈希，命中就直接发一条"引用指令"（只 8 字节偏移），
// 不传数据。
//
// 为什么这样设计而不是照搬 rsync 的滚动校验：
//   本项目的块边界本来就是固定的 4MB，每块自带 SHA-256，接收端也有现成的
//   整文件哈希校验。所以"按固定块比对"不需要新引入弱校验/滚动窗口，实现量
//   小一个数量级，也几乎不可能写错。
//
// 代价（必须说清楚）：
//   只识别**块对齐**的相同内容。若源文件在中间插入/删除字节，后续所有块
//   错位，全部要重传。rsync 的滚动校验正是为了处理这种情况。
//   覆盖的典型场景：原地覆盖修改（日志、数据库文件、镜像）、末尾追加。
//
// 兼容性：
//   HAVE 行扩展为 "HAVE <bits> [<reuse>]"。旧版发送端读到的整行会 base64
//   解码失败，位图为空，于是全量发送——行为正确，只是没有优化。
//   新版发送端遇到旧版接收端（无 reuse 段）同样全量发送。

const (
	// refFlag 标记"引用帧"：真实块号 = idx &^ refFlag，数据段是 8 字节源偏移。
	// 与零长度哨兵（idx=0xFFFFFFFF, len=0）不冲突：哨兵先按 len==0 判定。
	refFlag uint32 = 0x80000000
	// reuseMaxBlocks 限制单次协商的块数（16384 × 4MB = 64GB），
	// 避免 HAVE 行无限变长。
	reuseMaxBlocks = 16384
	// reuseMaxLine 是 HAVE 行的硬上限，超过就放弃增量（宁可全量也不能
	// 让一行撑爆内存）。
	reuseMaxLine = 8 << 20
)

// reuseEntry 是"目标已有文件里某个块"的描述。
type reuseEntry struct {
	H string `json:"h"` // 块 SHA-256（hex）
	O int64  `json:"o"` // 在该文件中的字节偏移
}

// reuseTable 是接收端发给发送端的重用表。
type reuseTable struct {
	Size   int64        `json:"s"` // 已有文件大小（仅用于日志/校验）
	Blocks []reuseEntry `json:"b"`
}

// buildReuseTable 扫描 path 的每个 chunk 大小的块并算 SHA-256。
//
// 返回 nil 表示没有可复用的数据（文件不存在/读失败/空文件）。
// 这是接收端的"读放大"：100MB 文件要读 100MB 算哈希。相比重传 100MB
// 走网络仍然划算（本地顺序读比过网快 1~2 个数量级），但会在慢磁盘上
// 体现为启动延迟。
func buildReuseTable(path string, chunk int) *reuseTable {
	if path == "" || chunk <= 0 {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	st, serr := f.Stat()
	if serr != nil || !st.Mode().IsRegular() || st.Size() == 0 {
		return nil
	}
	n := int((st.Size() + int64(chunk) - 1) / int64(chunk))
	if n > reuseMaxBlocks {
		return nil // 太大就放弃增量，避免协商行过长
	}
	buf := make([]byte, chunk)
	t := &reuseTable{Size: st.Size(), Blocks: make([]reuseEntry, 0, n)}
	for i := 0; i < n; i++ {
		off := int64(i) * int64(chunk)
		rd, rerr := f.ReadAt(buf, off)
		if rd == 0 {
			break
		}
		_ = rerr // 短读是正常的（最后一块），按 rd 截断即可
		sum := sha256.Sum256(buf[:rd])
		t.Blocks = append(t.Blocks, reuseEntry{H: hex.EncodeToString(sum[:]), O: off})
	}
	if len(t.Blocks) == 0 {
		return nil
	}
	return t
}

// encode 把重用表编码成可直接放进 HAVE 行的字符串（空表返回 ""）。
func (t *reuseTable) encode() string {
	if t == nil || len(t.Blocks) == 0 {
		return ""
	}
	b, err := json.Marshal(t)
	if err != nil || len(b) > reuseMaxLine {
		return ""
	}
	return base64.StdEncoding.EncodeToString(b)
}

// decodeReuseTable 解析 HAVE 行里的重用段。任何异常都返回 nil（退化为全量）。
func decodeReuseTable(s string) *reuseTable {
	if s == "" {
		return nil
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil
	}
	var t reuseTable
	if err := json.Unmarshal(raw, &t); err != nil {
		return nil
	}
	return &t
}

// index 建"哈希 → 偏移"查找表。
func (t *reuseTable) index() map[string]int64 {
	if t == nil {
		return nil
	}
	m := make(map[string]int64, len(t.Blocks))
	for _, b := range t.Blocks {
		if _, dup := m[b.H]; !dup {
			m[b.H] = b.O
		}
	}
	return m
}

// WriteRefFrame 发一条"引用帧"：告诉接收端第 idx 块的内容取自它自己
// 已有文件的 srcOffset 处，无需传输数据本身。
//
// 校验和仍按现有约定覆盖数据段（这 8 字节偏移），所以 ReadFrame 无需改动。
func WriteRefFrame(w io.Writer, idx int64, srcOffset int64) error {
	hdr := make([]byte, headerLen)
	copy(hdr, Magic)
	binary.BigEndian.PutUint32(hdr[4:8], uint32(idx)|refFlag)
	binary.BigEndian.PutUint64(hdr[8:16], 8)
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	var body [8]byte
	binary.BigEndian.PutUint64(body[:], uint64(srcOffset))
	if _, err := w.Write(body[:]); err != nil {
		return err
	}
	sum := sha256.Sum256(body[:])
	_, err := w.Write(sum[:])
	return err
}

// isRefFrame 判断某帧是否为引用帧。
func isRefFrame(idx int64) bool {
	return idx >= 0 && uint32(idx)&refFlag != 0
}

// refOffset 从引用帧的数据段取出源偏移。
func refOffset(data []byte) (int64, error) {
	if len(data) != 8 {
		return 0, fmt.Errorf("引用帧长度应为 8，实际 %d", len(data))
	}
	return int64(binary.BigEndian.Uint64(data)), nil
}

// blockHash 返回一个块内容的 SHA-256（hex），用于和重用表比对。
func blockHash(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
