package transfer

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"sync"
)

// —— rsync 式增量同步（delta transfer，M2.8）——
//
// 接收端把**目的端已有文件**按 DeltaBlock 逐块算 (弱和, 强和) 清单，
// 经 BASE 行发给发送端；发送端用滚动弱和在**自己的文件**里滑动匹配
//（任意偏移，不要求块对齐），命中处发 COPY 指令（从接收端 basis 的
// 对应区间复制），未命中处发字面量。接收端按配方重建后仍走原校验
// 链：逐帧哈希（线上完整性）+ 整文件 SHA-256 对清单（内容正确性）。
// 因此 delta 不引入新的信任假设：basis 损坏 → 匹配不上 → 退化为
// 字面量全传（自愈）；配方被篡改 → 重建哈希不符 → 拒绝落盘。
//
// 并行化（M2.8b）：basis 求和与源文件扫描按 CPU 数分片——滚动扫描
// 单线程是 ffΔ 的最大 CPU 项（64MB ≈ 1s）。分片边界牺牲 ≤2W 字节
// 的匹配机会（W=64KB），换 K 倍吞吐。

// DeltaBlock 增量匹配块大小：64KB。粒度越细配方越省、清单越大；
// 64KB 对 1GB basis 的清单约 20KB，单字节改动最多重传 64KB。
const DeltaBlock = 64 << 10

// 帧复用约定：idx=-2 字面量帧，idx=-3 COPY 帧，idx=-1 完成哨兵（原有）。
const (
	frameDeltaLiteral = int64(-2)
	frameDeltaCopy    = int64(-3)
)

// blockSum 单块校验和：弱和用于快速窗口匹配，强和确认（8B 截断）。
type blockSum struct {
	Weak   uint32
	Strong [8]byte
}

// rollingSum 是 adler32 变体的滚动窗口和（rsync weaksum 同型）：
// s1 = 1+Σb，s2 = Σ(前缀和) 的等价累积（init/slide 自洽）。
type rollingSum struct {
	w    int
	s1   uint32 // 1 + Σb (mod 65521)
	s2   uint32
	size int
}

const adlerMod = 65521

func newRollingSum(w int) *rollingSum { return &rollingSum{w: w, s1: 1} }

// init 填入完整窗口并返回弱和。
func (r *rollingSum) init(win []byte) uint32 {
	r.s1, r.s2, r.size = 1, 0, len(win)
	for _, b := range win {
		r.s1 = (r.s1 + uint32(b)) % adlerMod
		r.s2 = (r.s2 + r.s1) % adlerMod
	}
	return r.value()
}

func (r *rollingSum) value() uint32 { return r.s2<<16 | r.s1 }

// slide 窗口右移一字节：移出 out，移入 in。O(1)。
func (r *rollingSum) slide(out, in byte) uint32 {
	r.s1 = (r.s1 + adlerMod - uint32(out)%adlerMod + uint32(in)) % adlerMod
	r.s2 = (r.s2 + adlerMod*2 - uint32(r.size)*uint32(out)%adlerMod + r.s1 - 1) % adlerMod
	return r.value()
}

func strongSum(b []byte) [8]byte {
	s := sha256.Sum256(b)
	var out [8]byte
	copy(out[:], s[:8])
	return out
}

// BasisSums 串行求和（io.Reader 版，单测与小于 8MB 的文件用）。
func BasisSums(f io.Reader) ([]blockSum, error) {
	var out []blockSum
	br := bufio.NewReader(f)
	buf := make([]byte, DeltaBlock)
	for {
		n, err := io.ReadFull(br, buf)
		if n > 0 {
			rs := newRollingSum(DeltaBlock)
			out = append(out, blockSum{Weak: rs.init(buf[:n]), Strong: strongSum(buf[:n])})
		}
		if err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break
			}
			return nil, err
		}
	}
	return out, nil
}

// BasisSumsFile 并行求和：K 个 worker 各管一段连续块区间（块边界全局
// 对齐），结果直接落位。大于 8MB 才启用并行。
func BasisSumsFile(f *os.File) ([]blockSum, error) {
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	size := st.Size()
	if size < 8<<20 {
		return BasisSums(f)
	}
	k := runtime.NumCPU()
	if k > 8 {
		k = 8
	}
	if k < 2 {
		return BasisSums(f)
	}
	nBlocks := (size + DeltaBlock - 1) / DeltaBlock
	sums := make([]blockSum, nBlocks)
	blocksPerWorker := (nBlocks + int64(k) - 1) / int64(k)
	errs := make(chan error, k)
	var wg sync.WaitGroup
	for w := 0; w < k; w++ {
		lo := int64(w) * blocksPerWorker * DeltaBlock
		hi := lo + blocksPerWorker*DeltaBlock
		if hi > size {
			hi = size
		}
		if lo >= hi {
			continue
		}
		wg.Add(1)
		go func(lo, hi int64) {
			defer wg.Done()
			buf := make([]byte, DeltaBlock)
			for off := lo; off < hi; off += DeltaBlock {
				n := DeltaBlock
				if size-off < int64(n) {
					n = int(size - off)
				}
				if _, err := f.ReadAt(buf[:n], off); err != nil {
					errs <- err
					return
				}
				rs := newRollingSum(DeltaBlock)
				sums[off/DeltaBlock] = blockSum{Weak: rs.init(buf[:n]), Strong: strongSum(buf[:n])}
			}
		}(lo, hi)
	}
	wg.Wait()
	select {
	case err := <-errs:
		return nil, err
	default:
	}
	return sums, nil
}

// encodeBasis / parseBasis：BASE 行负载（JSON；64KB 块下 1GB basis
// 约 20KB 行，bufio ReadString 可承载，可读性优先）。
func encodeBasis(sums []blockSum) ([]byte, error) { return json.Marshal(sums) }

func parseBasis(b []byte) ([]blockSum, error) {
	var sums []blockSum
	if err := json.Unmarshal(b, &sums); err != nil {
		return nil, err
	}
	return sums, nil
}

// basisIndex 弱和 → 候选块号（弱和碰撞用强和逐一确认）。只读共享，
// 并行扫描安全。
type basisIndex struct {
	sums  []blockSum
	full  map[uint32][]int32    // 完整块（长度 = DeltaBlock）
	short map[[2]uint32][]int32 // 短块按 (长度, 弱和) 索引（basis 尾块）
}

func newIndex(sums []blockSum, basisSize int64) *basisIndex {
	x := &basisIndex{sums: sums, full: map[uint32][]int32{}, short: map[[2]uint32][]int32{}}
	nFull := int(basisSize / DeltaBlock)
	for i, s := range sums {
		if i < nFull {
			x.full[s.Weak] = append(x.full[s.Weak], int32(i))
		} else {
			l := uint32(basisSize - int64(nFull)*DeltaBlock)
			x.short[[2]uint32{l, s.Weak}] = append(x.short[[2]uint32{l, s.Weak}], int32(i))
		}
	}
	return x
}

// hit 确认窗口是否真匹配某 basis 块：弱和命中后做强和确认。
func (x *basisIndex) hit(cands []int32, win []byte) (int32, bool) {
	st := strongSum(win)
	for _, c := range cands {
		if x.sums[c].Strong == st {
			return c, true
		}
	}
	return 0, false
}

// recipeEmitter 配方回吐：字面量 / COPY 指令。实现方负责写流、加密
// 与限速。
type recipeEmitter interface {
	literal(b []byte) error
	copy(off, length int64) error
}

// maxLiteral 单帧字面量上限（与 ChunkSize 帧校验兼容）。
const maxLiteral = ChunkSize - 4096

// scanRange 扫描源文件的 [start, end) 区间产出配方事件。
// 分段滑窗（4MiB 段，窗口为切片，无逐字节 memmove），段间携带 W-1
// 字节重扫。finalTail=true 时（区间终点=文件真尾）对末尾短块做
// basis 短块匹配；否则末尾残余全部记字面量（并行分片的中段边界
// 不跨段匹配，损失 ≤2W 字节/边界）。
func scanRange(ctx context.Context, f *os.File, start, end int64, x *basisIndex, em recipeEmitter, finalTail bool) error {
	if end <= start {
		return nil
	}
	W := DeltaBlock
	lit := make([]byte, 0, maxLiteral)
	flush := func() error {
		for len(lit) > 0 {
			n := len(lit)
			if n > maxLiteral {
				n = maxLiteral
			}
			if err := em.literal(lit[:n]); err != nil {
				return err
			}
			lit = lit[n:] // 前移视图：[:n] 在 n==len 时是空操作（曾致死循环）
		}
		lit = lit[:0]
		return nil
	}

	seg := make([]byte, ChunkSize)
	carry := []byte{}
	pos := start // 已处理完（不含 carry）的文件偏移
	for pos < end {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		n := int64(len(seg))
		if end-pos < n {
			n = end - pos
		}
		if _, err := f.ReadAt(seg[:n], pos); err != nil {
			return err
		}
		data := append(append([]byte{}, carry...), seg[:n]...)
		i := int64(0) // data 内游标
		li := int64(0)
		if int64(len(data)) >= int64(W) {
			rs := newRollingSum(W)
			weak := rs.init(data[:W])
			for {
				if cands, ok := x.full[weak]; ok {
					if blk, ok2 := x.hit(cands, data[i:i+int64(W)]); ok2 {
						lit = append(lit, data[li:i]...)
						if err := flush(); err != nil {
							return err
						}
						if err := em.copy(int64(blk)*int64(W), int64(W)); err != nil {
							return err
						}
						i += int64(W)
						li = i
						if i+int64(W) > int64(len(data)) {
							break
						}
						weak = rs.init(data[i : i+int64(W)])
						continue
					}
				}
				i++
				if i+int64(W) > int64(len(data)) {
					break
				}
				weak = rs.slide(data[i-1], data[i+int64(W)-1])
			}
		}
		isLastSeg := pos+n >= end
		if finalTail && isLastSeg {
			// 真文件尾：末尾 W-1 字节重扫短块匹配，其余发射
			keepFrom := int64(len(data)) - int64(W-1)
			if keepFrom < li {
				keepFrom = li
			}
			if keepFrom > li {
				lit = append(lit, data[li:keepFrom]...)
			}
			carry = append([]byte{}, data[keepFrom:]...)
		} else {
			// 中段：本段全部发射（并行边界不跨段匹配）
			if int64(len(data)) > li {
				lit = append(lit, data[li:]...)
			}
			carry = carry[:0]
		}
		if err := flush(); err != nil {
			return err
		}
		pos += n
	}
	// finalTail：carry 即真文件尾（长度 < W），试 basis 短块匹配
	if finalTail && len(carry) > 0 {
		rs := newRollingSum(DeltaBlock)
		weak := rs.init(carry)
		if cands, ok := x.short[[2]uint32{uint32(len(carry)), weak}]; ok {
			if blk, ok2 := x.hit(cands, carry); ok2 {
				if err := em.copy(int64(blk)*DeltaBlock, int64(len(carry))); err != nil {
					return err
				}
				return nil
			}
		}
		lit = append(lit, carry...)
	}
	return flush()
}

// recipeEvent 并行扫描的事件暂存：字面量切片引用 worker 私有缓冲。
type recipeEvent struct {
	lit     []byte
	off, ln int64
	isCopy  bool
}

// collector 把扫描事件缓存进定长通道（背压控制内存：K×64 事件上限）。
type collector struct {
	ch   chan recipeEvent
	ctxv context.Context
}

func (c *collector) literal(b []byte) error {
	cp := append([]byte{}, b...)
	select {
	case c.ch <- recipeEvent{lit: cp}:
		return nil
	case <-c.ctxv.Done():
		return c.ctxv.Err()
	}
}

func (c *collector) copy(off, length int64) error {
	select {
	case c.ch <- recipeEvent{off: off, ln: length, isCopy: true}:
		return nil
	case <-c.ctxv.Done():
		return c.ctxv.Err()
	}
}

// buildRecipe 扫描源文件产出 delta 配方。≥16MB 时按 CPU 数并行分片，
// 每 worker 独立扫描、定长通道背压暂存，主协程按段序合并发射
//（顺序语义与串行一致）。
func buildRecipe(ctx context.Context, f *os.File, size int64, x *basisIndex, em recipeEmitter) error {
	if size == 0 {
		return nil
	}
	k := 1
	if size >= 16<<20 {
		k = runtime.NumCPU()
		if k > 8 {
			k = 8
		}
	}
	if k <= 1 {
		return scanRange(ctx, f, 0, size, x, em, true)
	}
	seg := (size + int64(k) - 1) / int64(k)
	chs := make([]chan recipeEvent, k)
	errs := make([]error, k)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	for w := 0; w < k; w++ {
		lo := int64(w) * seg
		hi := lo + seg
		if hi > size {
			hi = size
		}
		chs[w] = make(chan recipeEvent, 64)
		wg.Add(1)
		go func(w int, lo, hi int64) {
			defer wg.Done()
			defer close(chs[w])
			c := &collector{ch: chs[w], ctxv: ctx}
			if err := scanRange(ctx, f, lo, hi, x, c, w == k-1); err != nil {
				errs[w] = err
				cancel() // 一处失败：让其它 worker 尽快退出
			}
		}(w, lo, hi)
	}
	for w := 0; w < k; w++ { // 按段序合并：顺序语义与串行一致
		for ev := range chs[w] {
			var err error
			if ev.isCopy {
				err = em.copy(ev.off, ev.ln)
			} else {
				err = em.literal(ev.lit)
			}
			if err != nil {
				cancel()
				for w2 := w; w2 < k; w2++ { // 排空剩余通道防 worker 阻塞
					for range chs[w2] {
					}
				}
				wg.Wait()
				return err
			}
		}
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return ctx.Err()
}

// encodeCopyToken COPY 指令线格式：8B 偏移 + 8B 长度。
func encodeCopyToken(off, length int64) []byte {
	t := make([]byte, 16)
	binary.BigEndian.PutUint64(t[:8], uint64(off))
	binary.BigEndian.PutUint64(t[8:], uint64(length))
	return t
}

func decodeCopyToken(b []byte) (off, length int64, err error) {
	if len(b) != 16 {
		return 0, 0, fmt.Errorf("COPY 指令长度异常: %d", len(b))
	}
	return int64(binary.BigEndian.Uint64(b[:8])), int64(binary.BigEndian.Uint64(b[8:])), nil
}
