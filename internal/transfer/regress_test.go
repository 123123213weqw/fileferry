package transfer

import (
	"bufio"
	"context"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"fileferry/internal/api"
	"fileferry/internal/ca"
)

// pipeOpener 用 net.Pipe 造一条流，把 SendFileRange 与接收侧直接接起来。
func pipeOpener(conn net.Conn) StreamOpener {
	used := false
	return func() (Stream, func(), error) {
		if used {
			return nil, nil, os.ErrClosed
		}
		used = true
		return conn, func() {}, nil
	}
}

// recvAsDst 复刻 HandleStream：先读 "FFJ1" 头与 grant 行，再交给 RecvStream。
func recvAsDst(conn net.Conn, grant *api.TransferGrant, roots *x509.CertPool) {
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		return
	}
	br := bufio.NewReader(conn)
	if _, err := br.ReadString('\n'); err != nil {
		return
	}
	RecvStream(br, conn, grant, roots)
}

func newGrant(t *testing.T, src, dst, dstPath string) *api.TransferGrant {
	t.Helper()
	g := &api.TransferGrant{
		ID: "xfer-" + t.Name(), Src: api.NodeID(src), Dst: api.NodeID(dst),
		SrcPath:   "/somewhere/source.bin",
		Hops:      []api.Hop{{NodeID: api.NodeID(src)}, {NodeID: api.NodeID(dst), Addr: "127.0.0.1:1"}},
		ChunkSize: ChunkSize, Streams: 1,
		ExpiresAt: time.Now().Add(time.Minute),
		DstPath:   dstPath,
	}
	return g
}

// 回归：空文件必须立刻完成（之前 expected 被钳成 1，收发两端卡 10 分钟）。
func TestRegressEmptyFileCompletes(t *testing.T) {
	root, err := ca.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sign, _ := grantKeys(t)
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "empty.bin")
	if err := os.WriteFile(srcPath, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	srcTLS := clientTLSFor(t, root, "src")
	grant := newGrant(t, "src", "dst", filepath.Join(dir, "out", "empty.bin"))
	sign(grant)

	cli, srv := net.Pipe()
	go func() {
		SendFileRange(context.Background(), srcPath, pipeOpener(cli), srcTLS, grant, 0, -1)
		cli.Close()
	}()
	done := make(chan struct{})
	go func() { recvAsDst(srv, grant, root.Pool()); close(done) }()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("空文件 10 秒仍未完成（回归）")
	}
	st, err := os.Stat(grant.DstPath)
	if err != nil {
		t.Fatalf("空文件未落盘：%v", err)
	}
	if st.Size() != 0 {
		t.Fatalf("空文件大小应为 0，实际 %d", st.Size())
	}
}

// 回归：目标写成"已存在的目录"时应自动补源文件名（README 的示例用法）。
func TestRegressDirectoryDestination(t *testing.T) {
	root, err := ca.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sign, _ := grantKeys(t)
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "data.bin")
	payload := []byte("directory destination works")
	if err := os.WriteFile(srcPath, payload, 0o644); err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(dir, "out")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatal(err)
	}
	srcTLS := clientTLSFor(t, root, "src")
	// 故意把目标写成已存在的目录（不带结尾斜杠）
	grant := newGrant(t, "src", "dst", outDir)
	grant.SrcPath = srcPath // 真实 flow 里 grant.SrcPath 就是源文件路径
	sign(grant)

	cli, srv := net.Pipe()
	go func() {
		SendFileRange(context.Background(), srcPath, pipeOpener(cli), srcTLS, grant, 0, -1)
		cli.Close()
	}()
	done := make(chan struct{})
	go func() { recvAsDst(srv, grant, root.Pool()); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("目录目标超时")
	}
	got, err := os.ReadFile(filepath.Join(outDir, "data.bin"))
	if err != nil {
		t.Fatalf("未按源文件名落盘：%v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("内容不符：%q", got)
	}
}

// 回归：manifest 的哈希必须与 grant 里被签名的摘要一致。
func TestRegressManifestBoundToGrant(t *testing.T) {
	root, err := ca.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "f.bin")
	if err := os.WriteFile(p, []byte("real-content"), 0o644); err != nil {
		t.Fatal(err)
	}
	srcTLS := clientTLSFor(t, root, "src")
	mf, err := BuildManifest("xfer-1", p, srcTLS)
	if err != nil {
		t.Fatal(err)
	}

	// 未声明摘要：放行（单源正常路径）
	g := &api.TransferGrant{ID: "xfer-1", Src: "src", Dst: "dst"}
	if err := mf.Verify(g, root.Pool()); err != nil {
		t.Fatalf("未声明摘要时不应失败：%v", err)
	}
	// 摘要不符：必须拒绝
	g.FileSHA256 = strings.Repeat("a", 64)
	if err := mf.Verify(g, root.Pool()); err == nil {
		t.Fatal("摘要不符仍被接受（回归）")
	}
	// 大小不符：必须拒绝
	g.FileSHA256 = mf.SHA256
	g.FileSize = mf.Size + 1
	if err := mf.Verify(g, root.Pool()); err == nil {
		t.Fatal("大小不符仍被接受（回归）")
	}
	// 正确摘要：放行
	g.FileSize = mf.Size
	if err := mf.Verify(g, root.Pool()); err != nil {
		t.Fatalf("正确摘要被拒：%v", err)
	}
}

// 回归：白名单不能再被同前缀的兄弟目录 / 软链接绕过。
func TestRegressPathGuard(t *testing.T) {
	base := t.TempDir()
	allowed := filepath.Join(base, "allowed")
	if err := os.MkdirAll(allowed, 0o755); err != nil {
		t.Fatal(err)
	}
	guard, err := NewPathGuard([]string{allowed})
	if err != nil {
		t.Fatal(err)
	}
	// 前缀兄弟目录：必须拒绝
	if guard(filepath.Join(base, "allowed-evil", "x.bin")) {
		t.Fatal("同前缀兄弟目录被放行（回归）")
	}
	// 白名单内：放行
	if !guard(filepath.Join(allowed, "sub", "ok.bin")) {
		t.Fatal("白名单内路径被误拒")
	}
	// 相对穿越：拒绝
	if guard(filepath.Join(allowed, "..", "escape.bin")) {
		t.Fatal(".. 穿越被放行（回归）")
	}
	// 软链接逃逸：指向白名单外的目录，必须拒绝
	outside := filepath.Join(base, "outside")
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(allowed, "link")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("本环境不支持符号链接：%v", err)
	}
	if guard(filepath.Join(link, "pwn.bin")) {
		t.Fatal("软链接逃逸被放行（回归）")
	}
}

// 回归：inbox: 映射不能被 .. 穿越。
func TestRegressInboxTraversal(t *testing.T) {
	dataDir := "/var/lib/ff"
	for _, bad := range []string{
		"inbox:../../etc/cron.d/x",
		"inbox:..",
		"inbox:./../outside.bin",
		"inbox:/etc/passwd",
		"inbox:",
	} {
		if p, err := SafeInboxPath(dataDir, bad); err == nil {
			t.Fatalf("%q 未被拒绝，映射到 %q（回归）", bad, p)
		}
	}
	got, err := SafeInboxPath(dataDir, "inbox:report.pdf")
	if err != nil {
		t.Fatalf("正常取件名被误拒：%v", err)
	}
	if got != filepath.Join(dataDir, "inbox", "report.pdf") {
		t.Fatalf("映射结果不符：%s", got)
	}
}

// 回归：块号越界必须被拒绝（否则能在超大偏移建稀疏文件耗尽磁盘）。
func TestRegressChunkIndexBound(t *testing.T) {
	g := &recvGroup{expected: 2, got: map[int64]bool{}}
	tmp, err := os.CreateTemp(t.TempDir(), ".ff-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmp.Name())
	g.tmp = tmp
	g.tmpName = tmp.Name()

	var buf strings.Builder
	if err := WriteFrame(&buf, 99, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := g.feed(strings.NewReader(buf.String()), nil); err == nil {
		t.Fatal("越界块号被接受（回归）")
	}
}

// 回归：多流共用同一把密钥（controller 对密钥是一次性发放）。
func TestRegressSharedDeckeyAcrossStreams(t *testing.T) {
	mat := make([]byte, 32+7)
	for i := range mat {
		mat[i] = byte(i)
	}
	calls := 0
	SetKeyFetcher(func(grantID string) ([]byte, error) {
		calls++
		if calls > 1 {
			return nil, os.ErrNotExist // controller 侧一次性已删
		}
		return mat, nil
	})
	defer SetKeyFetcher(nil)

	SetPathGuard(func(string) bool { return true })
	defer SetPathGuard(nil)

	g := &api.TransferGrant{
		ID: "get-1", Src: "s", Dst: "d", Enc: true,
		ChunkSize: ChunkSize, ExpiresAt: time.Now().Add(time.Minute),
		DstPath: filepath.Join(t.TempDir(), "o.bin"),
	}
	mf := &Manifest{GrantID: "get-1", Size: 8, SHA256: strings.Repeat("c", 64)}

	first, err := groupFor(g, mf)
	if err != nil {
		t.Fatalf("第一条流建组失败：%v", err)
	}
	second, err := groupFor(g, mf)
	if err != nil {
		t.Fatalf("第二条流建组失败（回归：密钥未在组级共享）：%v", err)
	}
	if first != second {
		t.Fatal("两条流应复用同一个接收组")
	}
	if calls != 1 {
		t.Fatalf("取密钥次数应为 1，实际 %d", calls)
	}
	if first.deckey == nil || second.deckey == nil {
		t.Fatal("解密器未共享")
	}
	// 清理
	first.tmp.Close()
	os.Remove(first.tmpName)
	recvMu.Lock()
	delete(recvGroups, g.ID)
	recvMu.Unlock()
}

// 回归：源端不得改写 grant 的 DstPath（否则目的端验签必然失败，
// ff share / ff get 完全不可用）。这里验证：
//  1. 映射只在接收端发生，grant 结构本身不变
//  2. 转发的是原始 grant，签名仍然有效
func TestRegressInboxMappingReceiverOnly(t *testing.T) {
	root, err := ca.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sign, verify := grantKeys(t)
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "payload.bin")
	if err := os.WriteFile(srcPath, []byte("shared-bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	srcTLS := clientTLSFor(t, root, "alpha") // CN 必须等于 grant.Src

	grant := newGrant(t, "alpha", "beta", "inbox:payload.bin")
	grant.SrcPath = srcPath
	grant.ID = "get-1"
	sign(grant)

	// 接收端注入 inbox 根
	recvRoot := filepath.Join(dir, "beta")
	if err := os.MkdirAll(recvRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	SetInboxRoot(recvRoot)
	SetPathGuard(func(string) bool { return true })
	defer func() {
		SetInboxRoot("")
		SetPathGuard(nil)
	}()

	cli, srv := net.Pipe()
	go func() {
		// 源端只读 grant 的 DstPath 做校验，绝不改写
		if !strings.HasPrefix(grant.DstPath, "inbox:") {
			t.Errorf("源端不应改写 DstPath")
		}
		SendFileRange(context.Background(), srcPath, pipeOpener(cli), srcTLS, grant, 0, -1)
		cli.Close()
	}()
	// 接收端拿到的是 JSON 解码后的独立副本（真实是另一台机器）
	wire, _ := json.Marshal(grant)
	var recvGrant api.TransferGrant
	if err := json.Unmarshal(wire, &recvGrant); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { recvAsDst(srv, &recvGrant, root.Pool()); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("取件码传输超时（回归：inbox 映射位置）")
	}

	want := filepath.Join(recvRoot, "inbox", "payload.bin")
	got, err := os.ReadFile(want)
	if err != nil {
		t.Fatalf("未落到 inbox：%v", err)
	}
	if string(got) != "shared-bytes" {
		t.Fatalf("内容不符：%q", got)
	}
	// 转发用的 grant 结构必须保持原样，签名才有效
	if !verify(grant) {
		t.Fatal("grant 签名在传输后失效")
	}
	if grant.DstPath != "inbox:payload.bin" {
		t.Fatalf("源端 grant 被就地改写成了 %q", grant.DstPath)
	}
	if recvGrant.DstPath != want {
		t.Fatalf("接收端映射结果 %q，期望 %q", recvGrant.DstPath, want)
	}
}
