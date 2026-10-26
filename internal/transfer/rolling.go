package transfer

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"sort"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// rsync 风格的滚动校验增量（参考 rsync 的 checksum.c / match.c 思路）
//
// 为什么需要它：上一版的块级增量按**固定 4MB 边界**比对，所以
//   - 中间插入/删除 1 个字节 → 后续全部错位 → 退化为全量（实测 105MB）
//   - 原地改 4KB → 最小单位是 4MB，仍要传 4MB
// rsync 用「弱校验（可滚动）+ 强校验」在**任意偏移**上找匹配，两个问题
// 一起解决：错位的块也能被找到，且块可以很小（本例 4~128KB 自适应）。
//
// 算法要点（与 rsync 一致）：
//   弱校验  weak = (b<<16)|a，其中 a=Σx_i，b=Σ(n-i)*x_i（均 mod 2^16）
//   滚动    a' = a - x_out + x_in ;  b' = b - n*x_out + a'
//   强校验  SHA-256 截断 8 字节（rsync 用 MD5，这里沿用项目既有的 SHA-256）
// 滑动窗口在「新文件」上逐字节推进，命中弱校验后再用强校验确认，避免误匹配。
// ---------------------------------------------------------------------------

const (
	// 块大小自适应范围。太小学验开销大、协商表变长；太大又失去细粒度优势。
	sigMinBlock = 4 << 10
	sigMaxBlock = 128 << 10
	// sigMaxBlocks 控制协商行的上限：块数固定，块大小随文件变大，
	// 这样协商量有上界（≈ maxBlocks×12 字节），不会被超大文件拖爆。
	sigMaxBlocks = 8192
	// segFlag 标记"分段帧"：内容 = 若干「从本机旧文件拷贝」+「内联字面量」。
	segFlag uint32 = 0x40000000
	// strongLen 是强校验截断长度。
	strongLen = 8
	// weakMask 用于 16 位滚动运算。
	weakMask = 0xffff
)

// chooseBlockSize 按文件大小挑块大小（向下取到 2 的幂，便于对齐）。
//
// 目标是让块数不超过 sigMaxBlocks，同时块尽量小以保留细粒度。
func chooseBlockSize(size int64) int {
	if size <= 0 {
		return sigMinBlock
	}
	want := size / sigMaxBlocks
	b := int64(sigMinBlock)
	for b < want && b < sigMaxBlock {
		b <<= 1
	}
	if b > sigMaxBlock {
		b = sigMaxBlock
	}
	return int(b)
}

// weakSum 从头计算窗口的弱校验（O(n)）。
func weakSum(window []byte) uint32 {
	var a, b uint32
	n := uint32(len(window))
	for _, c := range window {
		a += uint32(c)
		b += n * uint32(c) // 权重递减：第一个字节权重 n
		n--
	}
	return (b&weakMask)<<16 | (a & weakMask)
}

// rollWeak 把窗口右移一个字节：移出 out，移入 in。
//
// 这是算法的核心，也是最容易写错的地方——测试里用「逐位置重算」做对拍。
func rollWeak(weak uint32, out, in byte, n int) uint32 {
	a := weak & weakMask
	b := (weak >> 16) & weakMask
	a = (a - uint32(out) + uint32(in)) & weakMask
	b = (b - uint32(n)*uint32(out) + a) & weakMask
	return b<<16 | a
}

// sigBlock 是旧文件一个块的校验信息。
type sigBlock struct {
	weak   uint32
	strong [strongLen]byte
}

// blockSig 是接收端发来的「旧文件分块签名」。
type blockSig struct {
	BlockSize int
	Count     int
	Blocks    []sigBlock
}

// buildSignature 扫描 path，按 blockSize 生成签名（只取完整块）。
//
// 只取完整块是为了简化：最后不足一块的尾巴不参与匹配，最多损失一个块
// 大小的复用机会（对 4MB 块来说可忽略，对 128KB 块来说也可接受）。
func buildSignature(path string, blockSize int) (*blockSig, error) {
	if blockSize <= 0 {
		return nil, fmt.Errorf("块大小非法: %d", blockSize)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	count := int(st.Size() / int64(blockSize))
	if count <= 0 {
		return nil, fmt.Errorf("文件不足一块")
	}
	if count > sigMaxBlocks {
		count = sigMaxBlocks
	}
	sig := &blockSig{BlockSize: blockSize, Count: count, Blocks: make([]sigBlock, 0, count)}
	buf := make([]byte, blockSize)
	for i := 0; i < count; i++ {
		if _, err := io.ReadFull(f, buf); err != nil {
			return nil, err
		}
		var sb sigBlock
		sb.weak = weakSum(buf)
		copy(sb.strong[:], strongSum(buf))
		sig.Blocks = append(sig.Blocks, sb)
	}
	return sig, nil
}

// encode 序列化为一行可放进 HAVE 行的文本。
//
// 布局：base64( [4B blockSize][4B count][count×(4B weak + 8B strong)] )
func (s *blockSig) encode() string {
	if s == nil || s.Count == 0 {
		return ""
	}
	raw := make([]byte, 8+len(s.Blocks)*(4+strongLen))
	binary.BigEndian.PutUint32(raw[0:4], uint32(s.BlockSize))
	binary.BigEndian.PutUint32(raw[4:8], uint32(len(s.Blocks)))
	off := 8
	for _, b := range s.Blocks {
		binary.BigEndian.PutUint32(raw[off:off+4], b.weak)
		copy(raw[off+4:off+4+strongLen], b.strong[:])
		off += 4 + strongLen
	}
	return base64.StdEncoding.EncodeToString(raw)
}

// decodeSignature 解析签名；任何异常返回 nil（退化为全量，不能出错）。
func decodeSignature(str string) *blockSig {
	if str == "" {
		return nil
	}
	raw, err := base64.StdEncoding.DecodeString(str)
	if err != nil || len(raw) < 8 {
		return nil
	}
	bs := int(binary.BigEndian.Uint32(raw[0:4]))
	count := int(binary.BigEndian.Uint32(raw[4:8]))
	if bs <= 0 || bs > 64<<20 || count <= 0 || count > sigMaxBlocks {
		return nil
	}
	if len(raw) < 8+count*(4+strongLen) {
		return nil
	}
	sig := &blockSig{BlockSize: bs, Count: count, Blocks: make([]sigBlock, count)}
	off := 8
	for i := 0; i < count; i++ {
		sig.Blocks[i].weak = binary.BigEndian.Uint32(raw[off : off+4])
		copy(sig.Blocks[i].strong[:], raw[off+4:off+4+strongLen])
		off += 4 + strongLen
	}
	return sig
}

// strongSum 返回强校验（SHA-256 截断）。
func strongSum(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:strongLen]
}

// sigIndex 是「弱校验 → 候选块下标」的查找表。
//
// 弱校验会碰撞，所以一个 weak 可能对应多个块，逐个用强校验确认。
type sigIndex struct {
	blockSize int
	count     int
	byWeak    map[uint32][]int32
	blocks    []sigBlock
}

func (s *blockSig) index() *sigIndex {
	if s == nil {
		return nil
	}
	ix := &sigIndex{blockSize: s.BlockSize, count: s.Count, blocks: s.Blocks,
		byWeak: make(map[uint32][]int32, len(s.Blocks))}
	for i, b := range s.Blocks {
		ix.byWeak[b.weak] = append(ix.byWeak[b.weak], int32(i))
	}
	return ix
}

// segOp 是分段帧里的一条指令。
//
//	opCopy：从接收端旧文件的 SrcOff 处拷 Len 字节
//	opLit ：内联 Len 字节字面量
type segOp struct {
	op     byte
	srcOff int64
	length int    // 拷贝/字面量的字节数
	lit    []byte // 仅 opLit 使用
}

const (
	opCopy byte = 0
	opLit  byte = 1
)

// buildSegOps 用滑动窗口把 data（发送端源文件的一个完整分块）表达为
// 「拷贝旧文件片段 + 内联字面量」的序列。
//
// 命中后一次跳过整个块（这是效率的关键：未改动区域每 B 字节才做一次
// 校验，而不是每个字节都做）。只有真正改动过的区域才逐字节滚动。
func (ix *sigIndex) buildSegOps(data []byte) []segOp {
	if ix == nil || ix.blockSize <= 0 || ix.count == 0 || len(data) == 0 {
		return nil
	}
	B := ix.blockSize
	if len(data) < B {
		return nil
	}
	ops := make([]segOp, 0, 16)
	litStart := 0 // 尚未处理成字面量的起点

	flushLit := func(end int) {
		if end > litStart {
			ops = append(ops, segOp{op: opLit, length: end - litStart, lit: data[litStart:end]})
		}
	}

	// 初始窗口
	weak := weakSum(data[:B])
	p := 0
	for p+B <= len(data) {
		if cands, ok := ix.byWeak[weak]; ok {
			sum := strongSum(data[p : p+B])
			for _, bi := range cands {
				if string(ix.blocks[bi].strong[:]) != string(sum) {
					continue
				}
				// 命中：先把之前的字面量吐出去，再记一条拷贝指令
				flushLit(p)
				off := int64(bi) * int64(B)
				// 合并相邻拷贝：连续匹配到的块在旧文件里也是连续的，
				// 合成一条指令即可。不合并的话，一个未改动的 4MB 分块要发
				// 256 条 13 字节指令（3.3KB），而合并后只要 13 字节——
				// 实测这一步把「原地改 4KB」的传输量从 117KB 降到 4KB 量级。
				if len(ops) > 0 && ops[len(ops)-1].op == opCopy &&
					ops[len(ops)-1].srcOff+int64(ops[len(ops)-1].length) == off {
					ops[len(ops)-1].length += B
				} else {
					ops = append(ops, segOp{op: opCopy, srcOff: off, length: B})
				}
				litStart = p + B
				p += B
				if p+B <= len(data) {
					weak = weakSum(data[p : p+B])
				}
				goto next
			}
		}
		// 未命中：滚动一个字节
		if p+1+B <= len(data) {
			weak = rollWeak(weak, data[p], data[p+B], B)
		}
		p++
	next:
	}
	flushLit(len(data))
	return ops
}

// encodeSegOps 编码分段帧负载，同时给出负载大小（用于判断值不值得）。
func encodeSegOps(chunk []byte, ops []segOp) []byte {
	// 头部：重建后分块的 SHA-256（32 字节），接收端据此校验重建结果
	sum := sha256.Sum256(chunk)
	hdr := sum[:]
	out := make([]byte, 0, 32+len(ops)*13)
	out = append(out, hdr[:]...)
	var tmp [8]byte
	for _, o := range ops {
		out = append(out, o.op)
		switch o.op {
		case opCopy:
			binary.BigEndian.PutUint64(tmp[:], uint64(o.srcOff))
			out = append(out, tmp[:8]...)
			binary.BigEndian.PutUint32(tmp[:4], uint32(o.length))
			out = append(out, tmp[:4]...)
		case opLit:
			binary.BigEndian.PutUint32(tmp[:4], uint32(len(o.lit)))
			out = append(out, tmp[:4]...)
			out = append(out, o.lit...)
		}
	}
	return out
}

// WriteSegFrame 写一条分段帧。
func WriteSegFrame(w io.Writer, idx int64, payload []byte) error {
	hdr := make([]byte, headerLen)
	copy(hdr, Magic)
	binary.BigEndian.PutUint32(hdr[4:8], uint32(idx)|segFlag)
	binary.BigEndian.PutUint64(hdr[8:16], uint64(len(payload)))
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	if _, err := w.Write(payload); err != nil {
		return err
	}
	sum := sha256.Sum256(payload)
	_, err := w.Write(sum[:])
	return err
}

// isSegFrame 判断是否为分段帧。
func isSegFrame(idx int64) bool {
	return idx >= 0 && uint32(idx)&segFlag != 0
}

// decodeSegOps 解析负载并重建分块内容，同时校验重建结果的 SHA-256。
func decodeSegOps(payload []byte, chunkLen int, openOld func() (io.ReaderAt, func(), error)) ([]byte, error) {
	if len(payload) < 32 {
		return nil, fmt.Errorf("分段帧过短: %d", len(payload))
	}
	var want [32]byte
	copy(want[:], payload[:32])
	body := payload[32:]
	out := make([]byte, 0, chunkLen)
	var old io.ReaderAt
	var closeOld func()
	defer func() {
		if closeOld != nil {
			closeOld()
		}
	}()
	for len(body) > 0 {
		op := body[0]
		body = body[1:]
		switch op {
		case opCopy:
			if len(body) < 12 {
				return nil, fmt.Errorf("拷贝指令截断")
			}
			off := int64(binary.BigEndian.Uint64(body[0:8]))
			n := int(binary.BigEndian.Uint32(body[8:12]))
			body = body[12:]
			if n < 0 || off < 0 {
				return nil, fmt.Errorf("拷贝参数非法 off=%d n=%d", off, n)
			}
			if len(out)+n > chunkLen {
				return nil, fmt.Errorf("拷贝超出分块长度")
			}
			if old == nil {
				r, cf, err := openOld()
				if err != nil {
					return nil, fmt.Errorf("打开旧文件失败: %w", err)
				}
				old, closeOld = r, cf
			}
			buf := make([]byte, n)
			if _, err := old.ReadAt(buf, off); err != nil {
				return nil, fmt.Errorf("读旧文件 off=%d n=%d: %w", off, n, err)
			}
			out = append(out, buf...)
		case opLit:
			if len(body) < 4 {
				return nil, fmt.Errorf("字面量指令截断")
			}
			n := int(binary.BigEndian.Uint32(body[0:4]))
			body = body[4:]
			if n < 0 || len(body) < n || len(out)+n > chunkLen {
				return nil, fmt.Errorf("字面量长度非法 n=%d", n)
			}
			out = append(out, body[:n]...)
			body = body[n:]
		default:
			return nil, fmt.Errorf("未知指令 %d", op)
		}
	}
	if len(out) != chunkLen {
		return nil, fmt.Errorf("重建长度不符：%d != %d", len(out), chunkLen)
	}
	got := sha256.Sum256(out)
	if got != want {
		return nil, fmt.Errorf("重建分块哈希不符")
	}
	return out, nil
}

// sortedNeighbors 是给调试/日志用的稳定输出。
func (ix *sigIndex) sortedNeighbors() []int {
	if ix == nil {
		return nil
	}
	out := make([]int, 0, len(ix.byWeak))
	for k := range ix.byWeak {
		out = append(out, int(k))
	}
	sort.Ints(out)
	return out
}

// sigCache 让同一 grant 的多条并行流共享一份签名索引。
//
// 为什么需要：接收端把签名放在 HAVE 行里，而 HAVE 是**每条流各发一次**的。
// 实测 4 条流 × 102KB 签名 = 410KB 下行，比 rsync 的校验量还大，"只改 4KB"
// 的场景总过网反而输了。所以只让第一条流携带签名，其余流用占位符，发送端
// 从缓存里取。
type sigCacheEntry struct {
	ix *sigIndex
	at time.Time
}

var (
	sigCacheMu sync.Mutex
	sigCache   = map[string]sigCacheEntry{}
)

// putSigIndex 记录某 grant 的签名索引，并顺手清理 5 分钟前的旧条目
// （避免长期运行累积；每个任务只占一条）。
func putSigIndex(grantID string, ix *sigIndex) {
	sigCacheMu.Lock()
	defer sigCacheMu.Unlock()
	now := time.Now()
	for k, v := range sigCache {
		if now.Sub(v.at) > 5*time.Minute {
			delete(sigCache, k)
		}
	}
	sigCache[grantID] = sigCacheEntry{ix: ix, at: now}
}

// getSigIndex 取某 grant 的签名索引；wait>0 时轮询等待（其余流可能比
// 携带签名的那条先读到 HAVE）。
func getSigIndex(grantID string, wait time.Duration) *sigIndex {
	deadline := time.Now().Add(wait)
	for {
		sigCacheMu.Lock()
		v, ok := sigCache[grantID]
		sigCacheMu.Unlock()
		if ok {
			return v.ix
		}
		if time.Now().After(deadline) {
			return nil
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// hasCap 判断能力列表里是否含某项。
func hasCap(caps []string, want string) bool {
	for _, c := range caps {
		if c == want {
			return true
		}
	}
	return false
}
