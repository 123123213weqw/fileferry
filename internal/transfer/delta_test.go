package transfer

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// TestRollingSumSlide 滑动 N 次后的弱和必须与整窗重算一致。
func TestRollingSumSlide(t *testing.T) {
	data := make([]byte, 4096)
	rand.Read(data)
	W := 512
	for start := 0; start+W+W <= len(data); start++ {
		rs := newRollingSum(W)
		got := rs.init(data[start : start+W])
		// 滑动 W 次（从 start 到 start+W）
		for k := 0; k < W; k++ {
			got = rs.slide(data[start+k], data[start+W+k])
		}
		want := newRollingSum(W).init(data[start+W : start+2*W])
		if got != want {
			t.Fatalf("滑动后弱和不一致 @%d: %d != %d", start+W, got, want)
		}
	}
}

// recEmi 记录型配方发射器，并支持按 basis 应用。
type recEmi struct {
	lits   [][]byte
	copies [][2]int64
}

func (r *recEmi) literal(b []byte) error {
	cp := append([]byte{}, b...)
	r.lits = append(r.lits, cp)
	return nil
}
func (r *recEmi) copy(off, length int64) error {
	r.copies = append(r.copies, [2]int64{off, length})
	return nil
}

func (r *recEmi) apply(basis []byte) []byte {
	var out []byte
	ci := 0
	for _, l := range r.lits {
		out = append(out, l...)
		// lits 与 copies 严格交替：每个 literal 后跟一个 copy（若有）
		if ci < len(r.copies) {
			c := r.copies[ci]
			ci++
			out = append(out, basis[c[0]:c[0]+c[1]]...)
		}
	}
	if ci < len(r.copies) {
		// 尾部短块匹配：只有 copy 没有前置 literal
		for ; ci < len(r.copies); ci++ {
			c := r.copies[ci]
			out = append(out, basis[c[0]:c[0]+c[1]]...)
		}
	}
	return out
}

// TestDeltaRecipeReconstruct 构造 8MB basis + 三处编辑（中部替换、
// 中部插入、尾部追加）的源文件，配方重建必须逐字节还原源文件，
// 且 COPY 覆盖大部分数据（省传输量）。
func TestDeltaRecipeReconstruct(t *testing.T) {
	basis := make([]byte, 8*1024*1024)
	rand.Read(basis)
	// 源 = basis 的编辑版：[0,2MB) + NEW(64KB) + [2MB+64KB, 6MB) + NEW2(1KB) + [6MB, 8MB) + TAIL(1MB)
	newData := make([]byte, 64*1024)
	rand.Read(newData)
	newData2 := make([]byte, 1024)
	rand.Read(newData2)
	tail := make([]byte, 1024*1024)
	rand.Read(tail)
	var src []byte
	src = append(src, basis[:2*1024*1024]...)
	src = append(src, newData...)
	src = append(src, basis[2*1024*1024+64*1024:6*1024*1024]...)
	src = append(src, newData2...)
	src = append(src, basis[6*1024*1024:]...)
	src = append(src, tail...)

	dir := t.TempDir()
	bf := filepath.Join(dir, "basis")
	sf := filepath.Join(dir, "src")
	os.WriteFile(bf, basis, 0o600)
	os.WriteFile(sf, src, 0o600)

	bfile, _ := os.Open(bf)
	sums, err := BasisSums(bfile)
	bfile.Close()
	if err != nil {
		t.Fatal(err)
	}
	sfile, _ := os.Open(sf)
	defer sfile.Close()
	st, _ := sfile.Stat()
	em := &recEmi{}
	if err := buildRecipe(context.Background(), sfile, st.Size(), newIndex(sums, int64(len(basis))), em); err != nil {
		t.Fatal(err)
	}
	got := em.apply(basis)
	if !bytes.Equal(got, src) {
		t.Fatalf("配方重建不一致: got %d bytes, want %d", len(got), len(src))
	}
	// 省传输量断言：COPY 覆盖字节 ≈ 6MB+（原 basis 大段），
	// 字面量 ≈ 64KB+1KB+1MB+边界 ≈ 1.1MB
	var copyBytes int64
	for _, c := range em.copies {
		copyBytes += c[1]
	}
	var litBytes int64
	for _, l := range em.lits {
		litBytes += int64(len(l))
	}
	if copyBytes < 6*1024*1024 {
		t.Fatalf("COPY 覆盖 %d 字节，未达预期的 ~6MB（增量匹配失效）", copyBytes)
	}
	if litBytes > 1400*1024 {
		t.Fatalf("字面量 %d 字节，超过预期的 ~1.1MB（匹配碎裂）", litBytes)
	}
	t.Logf("COPY=%dKB lits=%dKB（源 %dKB）", copyBytes/1024, litBytes/1024, len(src)/1024)
}

// TestDeltaRecipeNoMatch 源与 basis 完全不同：全部字面量，重建=源文件。
func TestDeltaRecipeNoMatch(t *testing.T) {
	basis := make([]byte, 300*1024)
	rand.Read(basis)
	src := make([]byte, 250*1024)
	rand.Read(src)
	dir := t.TempDir()
	bf, sf := filepath.Join(dir, "b"), filepath.Join(dir, "s")
	os.WriteFile(bf, basis, 0o600)
	os.WriteFile(sf, src, 0o600)
	bf2, _ := os.Open(bf)
	sums, _ := BasisSums(bf2)
	bf2.Close()
	sfile, _ := os.Open(sf)
	defer sfile.Close()
	st, _ := sfile.Stat()
	em := &recEmi{}
	if err := buildRecipe(context.Background(), sfile, st.Size(), newIndex(sums, int64(len(basis))), em); err != nil {
		t.Fatal(err)
	}
	if got := em.apply(basis); !bytes.Equal(got, src) {
		t.Fatalf("无匹配场景重建不一致: %d vs %d", len(got), len(src))
	}
}

// TestBasisSumsShortTail 末尾短块进入清单（长度记入 short 索引）。
func TestBasisSumsShortTail(t *testing.T) {
	basis := make([]byte, DeltaBlock+1234) // 1 完整块 + 1234B 短块
	rand.Read(basis)
	br := bytes.NewReader(basis)
	sums, err := BasisSums(br)
	if err != nil {
		t.Fatal(err)
	}
	if len(sums) != 2 {
		t.Fatalf("块数 %d != 2", len(sums))
	}
	x := newIndex(sums, int64(len(basis)))
	tail := basis[DeltaBlock:]
	if cands, ok := x.short[[2]uint32{1234, newRollingSum(DeltaBlock).init(tail)}]; !ok {
		t.Fatal("短块弱和未入索引")
	} else if _, ok2 := x.hit(cands, tail); !ok2 {
		t.Fatal("短块强和未确认")
	}
	_ = io.Discard
}
