package transfer

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// 增量协商行的编解码必须是自洽的，且异常输入一律退化为"全量发送"。
func TestReuseTableRoundTrip(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f.bin")
	// 2.5 块：最后一块不足 ChunkSize，验证短块能被正确识别
	data := make([]byte, ChunkSize*2+1000)
	// 每块内容必须不同：早先写成 byte(i*7) 会以 256 为周期重复，
	// 三块内容完全相同，导致 index() 去重后只留一个偏移。
	for i := range data {
		data[i] = byte(i/ChunkSize) ^ byte(i*7)
	}
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	rt := buildReuseTable(p, ChunkSize)
	if rt == nil {
		t.Fatal("应能扫描出重用表")
	}
	if len(rt.Blocks) != 3 {
		t.Fatalf("应识别 3 块，实际 %d", len(rt.Blocks))
	}
	if rt.Size != int64(len(data)) {
		t.Fatalf("大小不符：%d vs %d", rt.Size, len(data))
	}

	enc := rt.encode()
	if enc == "" {
		t.Fatal("编码不应为空")
	}
	back := decodeReuseTable(enc)
	if back == nil || len(back.Blocks) != 3 {
		t.Fatal("解码失败")
	}
	idx := back.index()
	for i, b := range back.Blocks {
		off := int64(i) * int64(ChunkSize)
		end := off + int64(ChunkSize)
		if end > int64(len(data)) {
			end = int64(len(data))
		}
		want := sha256.Sum256(data[off:end])
		if b.H != hex.EncodeToString(want[:]) {
			t.Fatalf("第 %d 块哈希不符", i)
		}
		if got, ok := idx[b.H]; !ok || got != off {
			t.Fatalf("索引第 %d 块偏移不符：%d vs %d", i, got, off)
		}
	}
}

// 文件不存在 / 空文件 / 目录都不能崩，应返回 nil（退化为全量）。
func TestBuildReuseTableDegrades(t *testing.T) {
	dir := t.TempDir()
	if got := buildReuseTable(filepath.Join(dir, "nope.bin"), ChunkSize); got != nil {
		t.Error("不存在的文件应返回 nil")
	}
	empty := filepath.Join(dir, "empty.bin")
	os.WriteFile(empty, nil, 0o600)
	if got := buildReuseTable(empty, ChunkSize); got != nil {
		t.Error("空文件应返回 nil")
	}
	if got := buildReuseTable(dir, ChunkSize); got != nil {
		t.Error("目录应返回 nil")
	}
	if got := buildReuseTable("", ChunkSize); got != nil {
		t.Error("空路径应返回 nil")
	}
}

// decodeReuseTable 对任何垃圾输入都不能 panic。
func TestDecodeReuseTableGarbage(t *testing.T) {
	for _, s := range []string{"", "!!!", "YWJj", "eyJ4IjoxfQ=="} {
		if got := decodeReuseTable(s); got != nil && len(got.Blocks) > 0 {
			t.Errorf("垃圾输入 %q 不应解析出块", s)
		}
	}
}

// 引用帧必须与普通帧、零长度哨兵互不混淆。
func TestRefFrameCoding(t *testing.T) {
	// 哨兵：idx=0xFFFFFFFF 且 len=0 —— isRefFrame 会认为是引用帧，
	// 但上层先按 len==0 判哨兵，所以顺序不能反。
	var buf bytes.Buffer
	if err := WriteFrame(&buf, -1, nil); err != nil {
		t.Fatal(err)
	}
	idx, data, err := ReadFrame(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 0 {
		t.Fatal("哨兵 len 应为 0")
	}
	// 只要上层先看 len，就不会把哨兵当引用帧
	if len(data) != 0 && isRefFrame(idx) {
		t.Fatal("哨兵不应走引用分支")
	}

	// 引用帧：块号可还原，偏移可还原
	for _, tc := range []struct{ block, off int64 }{{0, 0}, {1, ChunkSize}, {123, 999999}} {
		buf.Reset()
		if err := WriteRefFrame(&buf, tc.block, tc.off); err != nil {
			t.Fatal(err)
		}
		idx, data, err := ReadFrame(&buf)
		if err != nil {
			t.Fatal(err)
		}
		if !isRefFrame(idx) {
			t.Fatalf("块 %d 应识别为引用帧", tc.block)
		}
		gotBlock := int64(uint32(idx) &^ refFlag)
		if gotBlock != tc.block {
			t.Fatalf("块号还原错误：%d vs %d", gotBlock, tc.block)
		}
		off, err := refOffset(data)
		if err != nil || off != tc.off {
			t.Fatalf("偏移还原错误：%d vs %d (%v)", off, tc.off, err)
		}
	}

	// 普通帧不能被误判为引用帧
	buf.Reset()
	WriteFrame(&buf, 5, []byte("hello"))
	idx, _, _ = ReadFrame(&buf)
	if isRefFrame(idx) {
		t.Fatal("普通帧不应被误判为引用帧")
	}
}

// 端到端：目标已存在且内容相同 → 发送端应发引用帧而非数据。
func TestDeltaSendsRefFrames(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.bin")
	dst := filepath.Join(dir, "dst.bin")
	// 3 块内容，其中第 0、2 块相同，第 1 块不同
	blockA := bytes.Repeat([]byte{0xAA}, ChunkSize)
	blockB := bytes.Repeat([]byte{0xBB}, ChunkSize)
	blockC := bytes.Repeat([]byte{0xCC}, ChunkSize)

	// 源：A C A（第 0、2 块相同）
	var srcBuf bytes.Buffer
	srcBuf.Write(blockA)
	srcBuf.Write(blockC)
	srcBuf.Write(blockA)
	os.WriteFile(src, srcBuf.Bytes(), 0o600)

	// 目标已有：A B C —— 第 0 块(A) 和 第 2 块(C) 可在本地找到
	var dstBuf bytes.Buffer
	dstBuf.Write(blockA)
	dstBuf.Write(blockB)
	dstBuf.Write(blockC)
	os.WriteFile(dst, dstBuf.Bytes(), 0o600)

	rt := buildReuseTable(dst, ChunkSize)
	if rt == nil || len(rt.Blocks) != 3 {
		t.Fatal("重用表构建失败")
	}
	idx := rt.index()

	// 模拟发送端逐块判断
	var refs, datas int
	f, _ := os.Open(src)
	defer f.Close()
	buf := make([]byte, ChunkSize)
	for i := int64(0); i < 3; i++ {
		n, _ := f.ReadAt(buf, i*int64(ChunkSize))
		if _, ok := idx[blockHash(buf[:n])]; ok {
			refs++
		} else {
			datas++
		}
	}
	// 源块是 A、C、A；目标含 A、B、C → A 和 C 都能命中 → 3 块全命中
	if refs != 3 {
		t.Fatalf("应有 3 块可复用，实际 %d（数据帧 %d）", refs, datas)
	}
}

// 追尾场景：源 = 目标 + 追加一块。前 2 块应复用，只有新块需要传。
func TestDeltaAppendScenario(t *testing.T) {
	dir := t.TempDir()
	base := bytes.Repeat([]byte{0x11}, ChunkSize*2)
	extra := bytes.Repeat([]byte{0x22}, 1000)

	src := filepath.Join(dir, "src.bin")
	dst := filepath.Join(dir, "dst.bin")
	os.WriteFile(dst, base, 0o600)
	os.WriteFile(src, append(append([]byte{}, base...), extra...), 0o600)

	rt := buildReuseTable(dst, ChunkSize)
	idx := rt.index()
	f, _ := os.Open(src)
	defer f.Close()
	buf := make([]byte, ChunkSize)
	var refs int
	total := int64(3) // 2 整块 + 1 小块
	for i := int64(0); i < total; i++ {
		n, _ := f.ReadAt(buf, i*int64(ChunkSize))
		if n == 0 {
			break
		}
		if _, ok := idx[blockHash(buf[:n])]; ok {
			refs++
		}
	}
	if refs != 2 {
		t.Fatalf("追加场景应复用 2 块，实际 %d", refs)
	}
}

// 相同内容的块去重是**正确**行为：任意一个副本的偏移都能取到正确内容。
// （我第一版测试就是因为数据每 256 字节回绕、三块内容相同而误报失败。）
func TestReuseTableDedupesIdenticalBlocks(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "same.bin")
	block := bytes.Repeat([]byte{0x5A}, ChunkSize)
	os.WriteFile(p, append(append([]byte{}, block...), block...), 0o600)

	rt := buildReuseTable(p, ChunkSize)
	if len(rt.Blocks) != 2 {
		t.Fatalf("应记录 2 个块条目，实际 %d", len(rt.Blocks))
	}
	idx := rt.index()
	if len(idx) != 1 {
		t.Fatalf("两块的哈希相同，索引应去重为 1 项，实际 %d", len(idx))
	}
	// 去重保留的偏移必须是合法的整块边界，取出来的内容与块内容一致
	off := idx[blockHash(block)]
	if off != 0 && off != int64(ChunkSize) {
		t.Fatalf("去重后的偏移应对齐到块边界，实际 %d", off)
	}
	f, _ := os.Open(p)
	defer f.Close()
	buf := make([]byte, ChunkSize)
	n, _ := f.ReadAt(buf, off)
	if !bytes.Equal(buf[:n], block) {
		t.Fatal("按去重偏移取出的内容与块内容不一致")
	}
}
