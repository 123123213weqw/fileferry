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

// recEmi 记录型配方发射器：统一事件序列（COPY 前可有 0..N 个字面量帧），
// apply 按事件顺序重建——与线上协议语义一致。
type recEmi struct {
	events []ev
}

type ev struct {
	lit      []byte
	off, len int64
	isCopy   bool
}

func (r *recEmi) literal(b []byte) error {
	cp := append([]byte{}, b...)
	r.events = append(r.events, ev{lit: cp})
	return nil
}
func (r *recEmi) copy(off, length int64) error {
	r.events = append(r.events, ev{off: off, len: length, isCopy: true})
	return nil
}

func (r *recEmi) apply(basis []byte) []byte {
	var out []byte
	for _, e := range r.events {
		if e.isCopy {
			out = append(out, basis[e.off:e.off+e.len]...)
		} else {
			out = append(out, e.lit...)
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
	var copyBytes, litBytes int64
	for _, e := range em.events {
		if e.isCopy {
			copyBytes += e.len
		} else {
			litBytes += int64(len(e.lit))
		}
	}
	if copyBytes < 6*1024*1024 {
		t.Fatalf("COPY 覆盖 %d 字节，未达预期的 ~6MB（增量匹配失效）", copyBytes)
	}
	if litBytes > 1400*1024 {
		t.Fatalf("字面量 %d 字节，超过预期的 ~1.1MB（匹配碎裂）", litBytes)
	}
	t.Logf("COPY=%dKB lits=%dKB（源 %dKB）", copyBytes/1024, litBytes/1024, len(src)/1024)
}

// TestDeltaRecipeParallel 并行扫描（≥16MB 走多 worker 路径）：编辑点
// 精确落在分片边界上，重建必须与串行语义逐字节一致，且 COPY 仍然
// 覆盖绝大多数数据（边界不吞掉大段匹配）。
func TestDeltaRecipeParallel(t *testing.T) {
	seg := 16 << 20 // 默认并行分片大小
	basis := make([]byte, seg*2+3*1024*1024)
	rand.Read(basis)
	var src []byte
	src = append(src, basis[:seg-100*1024]...)
	e1 := make([]byte, 200*1024)
	rand.Read(e1)
	src = append(src, e1...)                              // 编辑跨越 seg 边界
	src = append(src, basis[seg+100*1024:2*seg]...)
	e2 := make([]byte, 64*1024)
	rand.Read(e2)
	src = append(src, e2...)                              // 第二边界附近
	src = append(src, basis[2*seg:]...)

	dir := t.TempDir()
	bf, sf := filepath.Join(dir, "b"), filepath.Join(dir, "s")
	os.WriteFile(bf, basis, 0o600)
	os.WriteFile(sf, src, 0o600)
	bfile, _ := os.Open(bf)
	sums, err := BasisSumsFile(bfile) // 并行求和路径
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
	if got := em.apply(basis); !bytes.Equal(got, src) {
		t.Fatalf("并行重建不一致: got %d want %d", len(got), len(src))
	}
	var copyBytes, litBytes int64
	for _, e := range em.events {
		if e.isCopy {
			copyBytes += e.len
		} else {
			litBytes += int64(len(e.lit))
		}
	}
	if copyBytes < int64(len(basis))-2*1024*1024 {
		t.Fatalf("COPY 覆盖 %d 字节过少（并行边界吞掉大段匹配）", copyBytes)
	}
	t.Logf("并行: 源 %dKB COPY=%dKB lit=%dKB", len(src)/1024, copyBytes/1024, litBytes/1024)
}

// TestDeltaAppendOnly 追加型文件（tail/日志同步）：旧版前缀完全不变、
// 尾部追加新内容——快速路径应整段 COPY + 尾部字面量，且事件数极少
//（每 64KB 一个 COPY），重建逐字节一致。并行路径（≥16MB）同样覆盖。
func TestDeltaAppendOnly(t *testing.T) {
	basis := make([]byte, 20<<20) // >16MB：触发并行分片
	rand.Read(basis)
	appendix := make([]byte, 3<<20)
	rand.Read(appendix)
	src := append(append([]byte{}, basis...), appendix...)

	dir := t.TempDir()
	bf, sf := filepath.Join(dir, "b"), filepath.Join(dir, "s")
	os.WriteFile(bf, basis, 0o600)
	os.WriteFile(sf, src, 0o600)
	bfile, _ := os.Open(bf)
	sums, err := BasisSumsFile(bfile)
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
	if got := em.apply(basis); !bytes.Equal(got, src) {
		t.Fatalf("追加场景重建不一致: got %d want %d", len(got), len(src))
	}
	var copyBytes, litBytes int64
	nEvents := 0
	for _, e := range em.events {
		nEvents++
		if e.isCopy {
			copyBytes += e.len
		} else {
			litBytes += int64(len(e.lit))
		}
	}
	if copyBytes != int64(len(basis)) {
		t.Fatalf("COPY=%d 字节 != basis %d（前缀未变应全部命中）", copyBytes, len(basis))
	}
	if litBytes != int64(len(appendix)) {
		t.Fatalf("字面量=%d 字节 != 追加 %d", litBytes, len(appendix))
	}
	// 事件数上界：每 64KB 至多一个 COPY + 尾部若干字面量帧
	maxEv := len(basis)/(64<<10) + len(appendix)/(4<<20) + 8
	if nEvents > maxEv {
		t.Fatalf("事件数 %d 远超上界 %d（快速路径未生效，落入滑窗碎片）", nEvents, maxEv)
	}
	t.Logf("追加场景：basis %dKB 全 COPY + 尾部 %dKB 字面量，事件 %d 个", len(basis)/1024, len(appendix)/1024, nEvents)
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
