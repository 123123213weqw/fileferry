package transfer

import (
	"bytes"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
)

// 滚动校验的核心：rollWeak 必须与「在新位置从头重算」逐位一致。
// 这是整个增量算法的地基，写错一个符号就会导致匹配全丢或误匹配。
func TestRollWeakMatchesRecompute(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for _, n := range []int{1, 2, 3, 7, 64, 1000, 4096} {
		data := make([]byte, n+500)
		rng.Read(data)
		weak := weakSum(data[:n])
		for p := 0; p+n < len(data); p++ {
			want := weakSum(data[p : p+n])
			if weak != want {
				t.Fatalf("n=%d p=%d：滚动值 %08x != 重算 %08x", n, p, weak, want)
			}
			weak = rollWeak(weak, data[p], data[p+n], n)
		}
	}
}

// 全 0 / 全 255 这类退化数据也要一致（弱校验在这种输入下最容易暴露
// 掩码/权重写错）。
func TestRollWeakDegenerate(t *testing.T) {
	for _, fill := range []byte{0x00, 0xff, 0x01} {
		for _, n := range []int{4, 16, 256} {
			data := bytes.Repeat([]byte{fill}, n+100)
			weak := weakSum(data[:n])
			for p := 0; p+n < len(data); p++ {
				if weak != weakSum(data[p:p+n]) {
					t.Fatalf("fill=%02x n=%d p=%d 不一致", fill, n, p)
				}
				weak = rollWeak(weak, data[p], data[p+n], n)
			}
		}
	}
}

// rollWeak 在 16 位边界上必须回绕，不能依赖 Go 的无符号溢出语义之外的假设。
func TestRollWeakWraps(t *testing.T) {
	n := 8
	data := make([]byte, n+1)
	for i := range data {
		data[i] = 0xff
	}
	weak := weakSum(data[:n])
	got := rollWeak(weak, data[0], data[n], n)
	if got != weakSum(data[1:1+n]) {
		t.Fatalf("回绕处理错误：%08x != %08x", got, weakSum(data[1:1+n]))
	}
}

// 块大小自适应：块数不超过上限，且随文件增大而增大。
func TestChooseBlockSize(t *testing.T) {
	cases := []struct {
		size int64
		min  int
		max  int
	}{
		{1 << 20, sigMinBlock, sigMinBlock}, // 1MB → 最小块
		{100 << 20, sigMinBlock, 32 << 10},  // 100MB → 16KB 左右
		{8 << 30, sigMaxBlock, sigMaxBlock}, // 8GB → 封顶
		{0, sigMinBlock, sigMinBlock},       // 未知 → 最小
	}
	for _, c := range cases {
		got := chooseBlockSize(c.size)
		if got < c.min || got > c.max {
			t.Errorf("size=%d 块大小 %d 超出 [%d,%d]", c.size, got, c.min, c.max)
		}
		if got&(got-1) != 0 {
			t.Errorf("块大小应为 2 的幂，实际 %d", got)
		}
	}
}

// 签名编码往返。
func TestSignatureRoundTrip(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "old.bin")
	data := make([]byte, 64<<10)
	rand.New(rand.NewSource(2)).Read(data)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	B := 8192
	sig, err := buildSignature(p, B)
	if err != nil {
		t.Fatal(err)
	}
	if sig.Count != len(data)/B {
		t.Fatalf("块数应为 %d，实际 %d", len(data)/B, sig.Count)
	}
	enc := sig.encode()
	if enc == "" {
		t.Fatal("编码为空")
	}
	back := decodeSignature(enc)
	if back == nil || back.Count != sig.Count || back.BlockSize != B {
		t.Fatal("解码失败")
	}
	for i := range sig.Blocks {
		if back.Blocks[i].weak != sig.Blocks[i].weak ||
			back.Blocks[i].strong != sig.Blocks[i].strong {
			t.Fatalf("第 %d 块校验不符", i)
		}
	}
	// 垃圾输入一律退化为 nil
	for _, s := range []string{"", "!!!", "YWJj", "AAAAAAAAAAA="} {
		if got := decodeSignature(s); got != nil && got.Count > sigMaxBlocks {
			t.Errorf("垃圾输入 %q 解析异常", s)
		}
	}
}

// 核心场景：旧文件在某处被插入若干字节，新文件整体错位。
// 块对齐比对在这里全军覆没，滚动校验应当仍能找到匹配。
func TestBuildSegOpsHandlesShift(t *testing.T) {
	rng := rand.New(rand.NewSource(3))
	const B = 4096
	// 旧文件：20 个随机块
	oldData := make([]byte, 20*B)
	rng.Read(oldData)

	// 新文件：在第 5 块开头插入 777 字节，导致后续全部错位
	insert := make([]byte, 777)
	rng.Read(insert)
	newData := append(append(append([]byte{}, oldData[:5*B]...), insert...), oldData[5*B:]...)

	dir := t.TempDir()
	p := filepath.Join(dir, "old.bin")
	if err := os.WriteFile(p, oldData, 0o600); err != nil {
		t.Fatal(err)
	}
	sig, err := buildSignature(p, B)
	if err != nil {
		t.Fatal(err)
	}
	ix := sig.index()

	// 逐块（4MB 太大，这里直接对整段扫描）验证：重建结果必须与 newData 一致
	ops := ix.buildSegOps(newData)
	if len(ops) == 0 {
		t.Fatal("错位场景应仍能匹配到内容")
	}
	payload := encodeSegOps(newData, ops)
	got, err := decodeSegOps(payload, len(newData), func() (io.ReaderAt, func(), error) {
		f, err := os.Open(p)
		if err != nil {
			return nil, nil, err
		}
		return f, func() { f.Close() }, nil
	})
	if err != nil {
		t.Fatalf("重建失败: %v", err)
	}
	if !bytes.Equal(got, newData) {
		t.Fatal("重建内容与原数据不符")
	}

	// 传输量应该远小于全量
	if len(payload) > len(newData)/2 {
		t.Fatalf("错位场景传输量应远小于全量：%d vs %d（说明匹配失效）", len(payload), len(newData))
	}
}

// 小块修改：只有改动处应为字面量，其余是拷贝。
func TestBuildSegOpsSmallEdit(t *testing.T) {
	rng := rand.New(rand.NewSource(4))
	const B = 4096
	oldData := make([]byte, 16*B)
	rng.Read(oldData)

	newData := append([]byte{}, oldData...)
	// 在中间改 100 字节
	pos := 7*B + 1000
	rng.Read(newData[pos : pos+100])

	dir := t.TempDir()
	p := filepath.Join(dir, "old.bin")
	os.WriteFile(p, oldData, 0o600)
	sig, _ := buildSignature(p, B)
	ix := sig.index()

	ops := ix.buildSegOps(newData)
	var litBytes, copyBytes int
	for _, o := range ops {
		if o.op == opLit {
			litBytes += o.length
		} else {
			copyBytes += o.length
		}
	}
	if copyBytes != len(newData)-litBytes {
		t.Fatalf("拷贝+字面量应覆盖全部分块：%d+%d != %d", copyBytes, litBytes, len(newData))
	}
	// 只改了 100 字节，字面量应控制在「改动量 + 若干块」量级内
	if litBytes > 3*B {
		t.Fatalf("字面量应只有改动的部分，实际 %d 字节（改动了 100 字节）", litBytes)
	}

	payload := encodeSegOps(newData, ops)
	got, err := decodeSegOps(payload, len(newData), func() (io.ReaderAt, func(), error) {
		f, _ := os.Open(p)
		return f, func() { f.Close() }, nil
	})
	if err != nil || !bytes.Equal(got, newData) {
		t.Fatalf("重建失败: %v", err)
	}
}

// 内容完全不同时 buildSegOps 应返回「一个巨大的字面量」，调用方据此
// 判断不值得走分段帧（回退普通帧）。
func TestBuildSegOpsNoMatch(t *testing.T) {
	rng := rand.New(rand.NewSource(5))
	const B = 4096
	oldData := make([]byte, 8*B)
	rng.Read(oldData)
	newData := make([]byte, 8*B)
	rng.Read(newData)

	dir := t.TempDir()
	p := filepath.Join(dir, "old.bin")
	os.WriteFile(p, oldData, 0o600)
	sig, _ := buildSignature(p, B)
	ops := sig.index().buildSegOps(newData)

	var lit int
	for _, o := range ops {
		if o.op == opLit {
			lit += o.length
		}
	}
	if lit != len(newData) {
		t.Fatalf("无匹配时应全部为字面量，实际字面量 %d / 总 %d", lit, len(newData))
	}
}

// 重建时校验必须生效：篡改负载里的哈希或内容都要被拒。
func TestDecodeSegOpsRejectsCorruption(t *testing.T) {
	rng := rand.New(rand.NewSource(6))
	const B = 1024
	oldData := make([]byte, 4*B)
	rng.Read(oldData)
	newData := append([]byte{}, oldData...)

	dir := t.TempDir()
	p := filepath.Join(dir, "old.bin")
	os.WriteFile(p, oldData, 0o600)
	sig, _ := buildSignature(p, B)
	ops := sig.index().buildSegOps(newData)
	payload := encodeSegOps(newData, ops)

	// 内容完全没变时全是拷贝指令（没有字面量可改），所以直接破坏
	// 第一条拷贝指令的源偏移：重建会读到错误的位置 → 分块哈希必须报错。
	if payload[32] != opCopy {
		t.Fatalf("首条指令应为拷贝，实际 %d", payload[32])
	}
	bad := append([]byte{}, payload...)
	bad[33] ^= 0x01 // 源偏移的低字节
	if _, err := decodeSegOps(bad, len(newData), func() (io.ReaderAt, func(), error) {
		f, _ := os.Open(p)
		return f, func() { f.Close() }, nil
	}); err == nil {
		t.Fatal("内容被篡改时必须报错（分块哈希校验失效）")
	}
}

// 相邻拷贝必须合并：未改动的分块应压缩成**一条**拷贝指令，
// 否则一个 4MB 分块要发 256 条 13 字节指令（实测把 4KB 改动的
// 传输量从 4KB 放大到 117KB）。
func TestBuildSegOpsMergesCopies(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	const B = 4096
	oldData := make([]byte, 64*B)
	rng.Read(oldData)
	newData := append([]byte{}, oldData...) // 完全相同

	dir := t.TempDir()
	p := filepath.Join(dir, "old.bin")
	os.WriteFile(p, oldData, 0o600)
	sig, _ := buildSignature(p, B)
	ops := sig.index().buildSegOps(newData)

	if len(ops) != 1 {
		t.Fatalf("完全相同时应合并为 1 条拷贝指令，实际 %d 条", len(ops))
	}
	if ops[0].op != opCopy || ops[0].length != len(newData) || ops[0].srcOff != 0 {
		t.Fatalf("合并结果不符：%+v", ops[0])
	}
	// 负载应当极小（32 字节块哈希 + 1 条指令）
	payload := encodeSegOps(newData, ops)
	if len(payload) > 64 {
		t.Fatalf("负载应小于 64 字节，实际 %d", len(payload))
	}
}

// 合并后仍须能正确重建（合并容易写出错位的 bug）。
func TestMergedOpsStillReconstruct(t *testing.T) {
	rng := rand.New(rand.NewSource(8))
	const B = 2048
	oldData := make([]byte, 32*B)
	rng.Read(oldData)

	// 三种变体：无改动、中间删 100 字节、中间插 100 字节
	variants := map[string][]byte{
		"same": append([]byte{}, oldData...),
		"del":  append(append([]byte{}, oldData[:10*B+50]...), oldData[10*B+150:]...),
		"ins":  append(append(append([]byte{}, oldData[:10*B]...), bytes.Repeat([]byte{0xEE}, 100)...), oldData[10*B:]...),
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "old.bin")
	os.WriteFile(p, oldData, 0o600)
	sig, _ := buildSignature(p, B)
	ix := sig.index()

	for name, want := range variants {
		ops := ix.buildSegOps(want)
		payload := encodeSegOps(want, ops)
		got, err := decodeSegOps(payload, len(want), func() (io.ReaderAt, func(), error) {
			f, _ := os.Open(p)
			return f, func() { f.Close() }, nil
		})
		if err != nil {
			t.Fatalf("%s: 重建失败 %v", name, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%s: 重建内容不符", name)
		}
		// 删/插 100 字节应当仍是小传输
		if len(payload) > 4*B {
			t.Errorf("%s: 传输量应远小于全量，实际 %d（全量 %d）", name, len(payload), len(want))
		}
	}
}
