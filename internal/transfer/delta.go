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
// s1 = 1+Σb，s2 = Σ(后缀和)，滑动 O(1)。
type rollingSum struct {
	w    int
	s1   uint32 // 1 + Σb (mod 65521)
	s2   uint32 // Σ_{i}(w-i)*b[i] + w·1 的等价累积（init/slide 自洽）
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
// 推导：s2 = Σ_{k=1..w} (前 k 字节和)。滑出队头 out 使每个剩余前缀
// 和减 out，共 w 项；随后追加 in 相当于在末尾加新 s1。
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

// BasisSums 读 basis 全文，产出逐块 (weak, strong) 清单；末尾短块（<W）
// 也纳入——rsync 同样匹配文件尾部的短块。
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

// basisIndex 弱和 → 候选块号（弱和碰撞用强和逐一确认）。
type basisIndex struct {
	sums  []blockSum
	full  map[uint32][]int32     // 完整块（长度 = DeltaBlock）
	short map[[2]uint32][]int32  // 短块按 (长度, 弱和) 索引（basis 尾块）
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

// buildRecipe 扫描发送端文件产出 delta 配方。分段滑动：每次载入
// ChunkSize 段（4MiB），窗口在段内切片滑动（无逐字节 memmove），段间
// 携带末尾 W-1 字节重扫——匹配机会损失 < W/4MiB。尾部试 basis 短块。
func buildRecipe(ctx context.Context, f *os.File, size int64, x *basisIndex, em recipeEmitter) error {
	if size == 0 {
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
	pos := int64(0) // 文件中 seg 起点之前已处理完（不含 carry）的偏移
	for pos < size {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		n := int64(len(seg))
		if size-pos < n {
			n = size - pos
		}
		if _, err := f.ReadAt(seg[:n], pos); err != nil {
			return err
		}
		data := append(append([]byte{}, carry...), seg[:n]...)
		base := pos - int64(len(carry)) // data[0] 对应的文件偏移
		i := 0                          // data 内游标
		li := 0                         // 未发射字面量起点
		if len(data) >= W {
			rs := newRollingSum(W)
			weak := rs.init(data[:W])
			for {
				if cands, ok := x.full[weak]; ok {
					if blk, ok2 := x.hit(cands, data[i:i+W]); ok2 {
						lit = append(lit, data[li:i]...)
						if err := flush(); err != nil {
							return err
						}
						if err := em.copy(int64(blk)*int64(W), int64(W)); err != nil {
							return err
						}
						i += W
						li = i
						if i+W > len(data) {
							break
						}
						weak = rs.init(data[i : i+W])
						continue
					}
				}
				i++
				if i+W > len(data) {
					break
				}
				weak = rs.slide(data[i-1], data[i+W-1])
			}
		}
		// 未发射部分：除 carry（末尾 W-1，下轮重扫）外全部记字面量
		keepFrom := len(data) - (W - 1)
		if keepFrom < li {
			keepFrom = li
		}
		if keepFrom > li {
			lit = append(lit, data[li:keepFrom]...)
		}
		carry = append([]byte{}, data[keepFrom:]...)
		if err := flush(); err != nil {
			return err
		}
		pos += n
		_ = base
	}
	// 文件尾：最后一段已并入 carry 循环处理；此处 carry 即真正的尾部
	//（长度 < W），试 basis 短块匹配
	if len(carry) > 0 {
		rs := newRollingSum(DeltaBlock)
		weak := rs.init(carry)
		matched := false
		if cands, ok := x.short[[2]uint32{uint32(len(carry)), weak}]; ok {
			if blk, ok2 := x.hit(cands, carry); ok2 {
				if err := em.copy(int64(blk)*DeltaBlock, int64(len(carry))); err != nil {
					return err
				}
				matched = true
			}
		}
		if !matched {
			lit = append(lit, carry...)
		}
	}
	return flush()
}

// maxLiteral 单帧字面量上限（与 ChunkSize 帧校验兼容）。
const maxLiteral = ChunkSize - 4096

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
