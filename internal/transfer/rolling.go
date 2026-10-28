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
	// segGiveUpRun 是"判定这段内容全新"的连续未匹配字节数。
	//
	// 没有它时，内容全新的区域会逐字节滚动，每字节一次 map 查找：实测
	// 200MB 随机数据、前 100MB 可复用，planSegChunks 要 **5.4 秒**，而这
	// 5.4 秒完全挡在数据发送之前——用户感知为"增量反而更慢"。
	//
	// 阈值取 16 个校验块：连续 256KB（16KB×16）找不到匹配就断定是新内容。
	// 内容"错位但存在"不会触发——错位后仍会持续命中，计数每次命中清零。
	// 实测 64 块阈值下 200MB 仍需 2.4s（新块各要空滚 1MB），降到 16 块后
	// 空扫量减少 4 倍。
	segGiveUpRun = 16
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

// segScanState 是**跨分块**的滚动扫描状态。
//
// 为什么需要它：每个 4MB 分块若独立扫描，错位时块内首尾各有一段凑不出
// 完整校验块（最多 2×块大小）只能当字面量发。实测「中间插 1 字节」因此
// 要传 461KB。把扫描状态跨块延续、并允许拷贝指令在块边界切开续写，
// 这部分浪费就没了。
type segScanState struct {
	p     int64 // 下一个待检查的输出偏移
	litAt int64 // 当前待发字面量的起始输出偏移
	// pendOff/pendLen 是"上一块末尾被截断的那次拷贝还剩多少"。
	//
	// 没有它的话，跨块状态是无效的：续上来的 p 落在块中间，窗口不再对齐
	// 任何校验块，只能逐字节滚到下一个块边界再重新匹配——实测"前视+跨块
	// 状态"与"仅前视"的字面量完全相同（7680 vs 7680），正是这个原因。
	pendOff int64
	pendLen int64
}

// scanChunk 为输出区间 [chunkStart, chunkEnd) 生成指令，使用从 chunkStart
// 开始的数据（末尾需带最多 blockSize-1 字节的前瞻，供跨界窗口使用）。
//
// 返回的 lit 切片指向 data，调用方须在复用 data 之前完成编码。
func (ix *sigIndex) scanChunk(data []byte, chunkStart, chunkEnd int64, st *segScanState) []segOp {
	if ix == nil || ix.blockSize <= 0 || ix.count == 0 || len(data) == 0 || chunkEnd <= chunkStart {
		return nil
	}
	B := int64(ix.blockSize)
	ops := make([]segOp, 0, 8)

	litFrom := chunkStart
	flushLit := func(to int64) {
		if to > litFrom {
			ops = append(ops, segOp{
				op:     opLit,
				length: int(to - litFrom),
				lit:    data[litFrom-chunkStart : to-chunkStart],
			})
		}
	}
	// 相邻拷贝合并：连续命中的内容在旧文件里也是连续的，合成一条即可。
	// 不合并的话一个未改动的 4MB 分块要发 256 条 13 字节指令。
	addCopy := func(off int64, n int) {
		if n <= 0 {
			return
		}
		if len(ops) > 0 {
			last := &ops[len(ops)-1]
			if last.op == opCopy && last.srcOff+int64(last.length) == off {
				last.length += n
				return
			}
		}
		ops = append(ops, segOp{op: opCopy, srcOff: off, length: n})
	}

	p := st.p
	if p < chunkStart {
		p = chunkStart
	}
	// 连续未匹配字节数：超过阈值就认定这段是全新内容，剩余部分整体当
	// 字面量，避免在必然无匹配的区域空转（见 segGiveUpRun 的说明）。
	miss := 0
	availEnd := chunkStart + int64(len(data)) // 可用数据的绝对结束位置
	if p+B > availEnd {
		// 数据不足以形成一个窗口：整段当字面量
		st.p, st.litAt = chunkEnd, chunkEnd
		flushLit(chunkEnd)
		return ops
	}
	// 先续上一块被截断的拷贝：这类续写是块内任意偏移，只能靠状态传递。
	if st.pendLen > 0 {
		for st.pendLen > 0 && p < chunkEnd {
			take := chunkEnd - p
			if take > st.pendLen {
				take = st.pendLen
			}
			addCopy(st.pendOff, int(take))
			p += take
			st.pendOff += take
			st.pendLen -= take
			litFrom = p
		}
		if p >= chunkEnd {
			flushLit(chunkEnd)
			st.p, st.litAt = chunkEnd, chunkEnd
			return ops
		}
	}
	if p+B > availEnd {
		flushLit(chunkEnd)
		st.p, st.litAt = chunkEnd, chunkEnd
		return ops
	}
	weak := weakSum(data[p-chunkStart : p-chunkStart+B])

	for p < chunkEnd && p+B <= availEnd {
		idx := p - chunkStart
		if cands, ok := ix.byWeak[weak]; ok {
			sum := strongSum(data[idx : idx+B])
			matched := false
			for _, bi := range cands {
				if string(ix.blocks[bi].strong[:]) != string(sum) {
					continue
				}
				flushLit(p)
				// 拷贝可以跨出本分块：只在边界处截断，下一块接着续。
				take := chunkEnd - p
				if take > B {
					take = B
				}
				srcOff := int64(bi) * int64(B)
				addCopy(srcOff, int(take))
				if take < B {
					// 本块放不下整块：剩下部分留给下一块续写
					st.pendOff = srcOff + take
					st.pendLen = B - take
				}
				p += take
				litFrom = p
				matched = true
				miss = 0
				break
			}
			if matched {
				if p < chunkEnd && p+B <= availEnd {
					weak = weakSum(data[p-chunkStart : p-chunkStart+B])
				}
				continue
			}
		}
		// 未命中：滚动一个字节
		if p+1 < chunkEnd && p+1+B <= availEnd {
			weak = rollWeak(weak, data[p-chunkStart], data[p+1-chunkStart+B-1], int(B))
		}
		p++
		miss++
		if miss >= int(int64(segGiveUpRun)*B) {
			// 这一整段都找不到匹配：剩余部分全是字面量，直接跳出。
			// 注意只跳本分块，跨块状态仍正常交接。
			break
		}
	}
	flushLit(chunkEnd)
	st.p, st.litAt = chunkEnd, chunkEnd
	return ops
}

// buildSegOps 对单个数据块做扫描（无跨块状态）。保留给测试与单块场景。
func (ix *sigIndex) buildSegOps(data []byte) []segOp {
	st := &segScanState{}
	return ix.scanChunk(data, 0, int64(len(data)), st)
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

// ---------------------------------------------------------------------------
// 整文件预扫描（planSegChunks）
//
// 为什么必须"整文件一次扫完"而不是每流各扫各的：
// 跨分块连续扫描依赖**相邻分块首尾相接**。但多流传输是把分块按 idx%n 交错
// 分给各流的（流 r 处理 r, r+n, r+2n…），每条流看到的相邻块之间隔着 n 个块，
// 状态续写必然错位。实测症状：4 流 × 100MB 的「插入 1 字节」场景，第 12~15
// 块重建哈希全部不符（正好是每条流第 4 个块），接收端正确拒绝并丢文件。
//
// 所以扫描只做一次、覆盖整个文件，产物是一张「块号 → 编码后的分段负载」表，
// 各流只负责查表发送。
// ---------------------------------------------------------------------------

// segPlanMaxBytes 限制预扫描占用内存：全部字面量的最坏情况不应把整文件
// 读进内存。超过就放弃分段帧（退回普通帧），与"编码不比原文小就不发"的
// 判断口径一致。
const segPlanMaxBytes = 32 << 20

// planSegChunks 从头到尾连续扫描文件，返回每个分块的分段负载。
//
// 只有编码后小于原文的分块才会进结果；返回 nil 表示放弃（总量超限）。
func planSegChunks(f *os.File, ix *sigIndex, size int64) map[int64][]byte {
	if ix == nil || size <= 0 || ix.blockSize <= 0 || ix.count == 0 {
		return nil
	}
	B := int64(ix.blockSize)
	chunk := int64(ChunkSize)
	// 单块加前视：扫描窗口可跨出块尾
	buf := make([]byte, chunk+B)
	st := &segScanState{}
	out := make(map[int64][]byte)
	var kept int64

	for idx := int64(0); idx*chunk < size; idx++ {
		base := idx * chunk
		want := chunk
		if base+want > size {
			want = size - base
		}
		n, err := f.ReadAt(buf[:want], base)
		if n <= 0 {
			_ = err
			break
		}
		data := buf[:n]
		cn := n
		if look := int(B) - 1; look > 0 && cn+look <= len(buf) {
			if ln, _ := f.ReadAt(buf[cn:cn+look], base+int64(cn)); ln > 0 {
				cn += ln
			}
		}
		ops := ix.scanChunk(buf[:cn], base, base+int64(n), st)
		if len(ops) == 0 {
			continue
		}
		payload := encodeSegOps(data, ops)
		if len(payload) >= n {
			continue // 不如直接发原文
		}
		kept += int64(len(payload))
		if kept > segPlanMaxBytes {
			return nil // 放弃：占用过大，整体退回普通帧
		}
		// payload 是 encodeSegOps 新分配的切片，但 ops 里的 lit 指向 buf，
		// 已在本轮编码完成，无需保留。
		out[idx] = payload
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// planCacheEntry 让同一 grant 的多条并行流共享一次预扫描结果。
type planCacheEntry struct {
	once sync.Once
	plan map[int64][]byte
	at   time.Time
}

var (
	planCacheMu sync.Mutex
	planCache   = map[string]*planCacheEntry{}
)

// getSegPlan 返回某 grant 的分段计划，只构建一次（多流并发安全）。
func getSegPlan(grantID string, build func() map[int64][]byte) map[int64][]byte {
	planCacheMu.Lock()
	now := time.Now()
	for k, v := range planCache {
		if now.Sub(v.at) > 10*time.Minute {
			delete(planCache, k)
		}
	}
	e, ok := planCache[grantID]
	if !ok {
		e = &planCacheEntry{at: now}
		planCache[grantID] = e
	}
	planCacheMu.Unlock()
	e.once.Do(func() { e.plan = build() })
	return e.plan
}
