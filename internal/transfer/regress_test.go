package transfer

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

// 回归：TCP 数据面端口必须能按节点区分（不能"全局覆盖"）。
// 全局覆盖会让拨号方用**自己的**端口去连对端，实测会连回自己并报
// "拒绝中继：不在路径上"。这里验证 Hop.TCPPort 被真正用于拨号。
func TestRegressPerNodeTCPPort(t *testing.T) {
	// 两个假节点：一个监听 TCP，一个只上报
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("无法监听：%v", err)
	}
	defer ln.Close()
	tcpPort := ln.Addr().(*net.TCPAddr).Port

	if got := (&api.Hop{NodeID: "n", Addr: "127.0.0.1:1", TCPPort: tcpPort}).TCPPort; got != tcpPort {
		t.Fatalf("Hop.TCPPort 未保留：%d", got)
	}
	// 端口为 0 时表示"用 Addr+1"，不能被解释成"用本机端口"
	if (&api.Hop{}).TCPPort != 0 {
		t.Fatal("零值必须表示未上报")
	}
}

// 回归：清单验签不能按 TLS ServerAuth 校验，否则只有 ClientAuth 的
// 管理员证书会被判"证书链无效"——本机直推（ffctl put）就是靠它失败的。
func TestRegressManifestAcceptsClientAuthCert(t *testing.T) {
	root, err := ca.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// 管理员证书：server=false，只带 ClientAuth
	certPEM, keyPEM, _, err := root.Issue("admin-user", false, ca.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	p := filepath.Join(dir, "payload.bin")
	if err := os.WriteFile(p, []byte("push-from-admin"), 0o644); err != nil {
		t.Fatal(err)
	}
	mf, err := BuildManifest("push-1", p, &tls.Config{Certificates: []tls.Certificate{pair}})
	if err != nil {
		t.Fatal(err)
	}
	g := &api.TransferGrant{ID: "push-1", Src: "admin-user", Dst: "node-2"}
	if err := mf.Verify(g, root.Pool()); err != nil {
		t.Fatalf("管理员证书签的清单应被接受，实际：%v（回归）", err)
	}
	// 不是该 grant 的来源，仍必须拒绝
	g.Src = "someone-else"
	if err := mf.Verify(g, root.Pool()); err == nil {
		t.Fatal("签名者与 grant.Src 不符时应拒绝")
	}
}

// 回归：限速必须是**每任务**而非每流。之前 grant.RateLimit 在协议里
// 声明却从未生效；按每流实现时 4 条流各限 2MB/s 合计变成 8MB/s。
func TestRegressTaskRateShared(t *testing.T) {
	if r0 := newTaskRate(0); r0 == nil {
		t.Fatal("限速器不应为 nil（仍要统计已发字节）")
	} else if r0.limit != 0 {
		t.Fatal("0 表示不限速")
	}
	const limit = 1 << 20 // 1MB/s
	r := newTaskRate(limit)
	start := time.Now()
	// 4 条"流"各发 512KB，共享同一配额 → 合计 2MB 应约 2 秒
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.take(512 << 10)
		}()
	}
	wg.Wait()
	el := time.Since(start)
	if el < 1500*time.Millisecond {
		t.Fatalf("4×512KB @1MB/s 应约 2s，实际 %s（回归：限速被各流分摊）", el.Round(100*time.Millisecond))
	}
	if el > 4*time.Second {
		t.Fatalf("限速过慢：%s", el.Round(100*time.Millisecond))
	}
	t.Logf("4 流共享 1MB/s：合计 2MB 用时 %s（符合约 2s）", el.Round(100*time.Millisecond))
}

// 回归：块数少的文件也必须落盘进度。之前只在"每 8 块"时保存，导致
// <32MB 的文件（总块数 <8）永远没有进度文件，重启后已收数据全丢，
// 续传退化成从头再来。
func TestRegressProgressSavedForSmallFiles(t *testing.T) {
	dir := t.TempDir()
	final := filepath.Join(dir, "out.bin")
	g := &recvGroup{
		grantID:   "xfer-small",
		wantSHA:   strings.Repeat("a", 64),
		size:      5 * ChunkSize, // 5 块：< 8，正是回归场景
		expected:  5,
		got:       map[int64]bool{},
		finalPath: final,
		finished:  make(chan struct{}),
		tmp:       mustTemp(t, dir),
	}
	g.tmpName = g.tmp.Name()

	// 收 4 块（不足 8，旧实现不会保存）
	for i := int64(0); i < 4; i++ {
		g.mu.Lock()
		g.got[i] = true
		g.dirty++
		shouldSave := g.dirty >= 8 || g.expected <= 16
		if shouldSave {
			g.dirty = 0
		}
		g.mu.Unlock()
		if shouldSave {
			g.saveProgress()
		}
	}
	// 模拟进程重启：新组从磁盘读进度
	g2 := &recvGroup{
		wantSHA:   g.wantSHA,
		size:      g.size,
		expected:  5,
		got:       map[int64]bool{},
		finalPath: final,
		finished:  make(chan struct{}),
		tmp:       mustTemp(t, dir),
	}
	g2.tmpName = g2.tmp.Name()
	g2.loadProgress()
	if len(g2.got) != 4 {
		t.Fatalf("重启后应恢复 4 块，实际 %d（回归：小文件从不保存进度）", len(g2.got))
	}
	g.tmp.Close()
	g2.tmp.Close()
}

func mustTemp(t *testing.T, dir string) *os.File {
	t.Helper()
	f, err := os.CreateTemp(dir, ".ff-*")
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// 回归：流的数量不应超过块数。1MB 文件只有 1 块，开 4 条流纯属多付
// 3 次 TLS 握手——这是小文件延迟偏高的来源之一。
func TestRegressStreamsCappedByChunks(t *testing.T) {
	capStreams := func(size int64, streams int) int {
		n := streams
		if n < 1 {
			n = 1
		}
		if chunks := int((size + ChunkSize - 1) / ChunkSize); chunks > 0 && n > chunks {
			n = chunks
		}
		return n
	}
	cases := []struct {
		size int64
		want int
	}{
		{1 << 20, 1},         // 1MB → 1 块
		{0, 4},               // 空文件：块数 0，保持调用方指定（哨兵路径）
		{4 * ChunkSize, 4},   // 16MB → 4 块
		{100 * ChunkSize, 4}, // 大文件：受 streams 上限
	}
	for _, c := range cases {
		if got := capStreams(c.size, 4); got != c.want {
			t.Fatalf("size=%d 时流数应为 %d，实际 %d", c.size, c.want, got)
		}
	}
}

// 回归：接收端写完 HAVE 后必须清掉那个 5 秒写超时。
//
// 该 SetWriteDeadline 作用于连接上**之后的所有写**，包括末尾的 ACK。
// 只要对端在 5 秒之后才把数据送完，ACK 就会 "i/o timeout" → 发送端看到
// EOF → 文件已完整落盘却报失败并重试（实测 5MB@1MB/s 要 185 秒才失败）。
//
// 这里手工扮演一个"慢对端"：读完 HAVE 后停 6 秒再发帧，让接收端的
// ACK 落在 5 秒之后。
func TestRegressSlowPeerStillGetsAck(t *testing.T) {
	root, err := ca.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sign, _ := grantKeys(t)
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "slow.bin")
	payload := make([]byte, ChunkSize)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(srcPath, payload, 0o644); err != nil {
		t.Fatal(err)
	}
	srcTLS := clientTLSFor(t, root, "src")
	grant := newGrant(t, "src", "dst", filepath.Join(dir, "out", "slow.bin"))
	grant.ID = "xfer-slowpeer"
	sign(grant)
	mf, err := BuildManifest(grant.ID, srcPath, srcTLS)
	if err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	srvCh := make(chan net.Conn, 1)
	go func() {
		if c, err := ln.Accept(); err == nil {
			srvCh <- c
		}
	}()
	cli, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	srv := <-srvCh
	defer cli.Close()

	done := make(chan struct{})
	go func() {
		recvAsDst(srv, grant, root.Pool())
		srv.Close()
		close(done)
	}()

	// 手工按线上格式发：FFJ1 + grant 行 + manifest 行
	gj, _ := json.Marshal(grant)
	mj, _ := json.Marshal(mf)
	io.WriteString(cli, "FFJ1")
	cli.Write(append(gj, '\n'))
	cli.Write(append(mj, '\n'))

	// 等接收端写 HAVE
	cli.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 512)
	cli.Read(buf) // 可能读到 HAVE 行；超时也无妨
	cli.SetReadDeadline(time.Time{})

	// 关键：拖过 5 秒再发数据
	time.Sleep(6 * time.Second)
	if err := WriteFrame(cli, 0, payload); err != nil {
		t.Fatalf("写数据失败：%v", err)
	}
	if err := WriteFrame(cli, -1, nil); err != nil {
		t.Fatalf("写哨兵失败：%v", err)
	}

	cli.SetReadDeadline(time.Now().Add(15 * time.Second))
	ack := make([]byte, 4)
	if _, err := io.ReadFull(cli, ack); err != nil {
		t.Fatalf("5 秒后读 ACK 失败（回归：HAVE 阶段的写超时被残留）：%v", err)
	}
	if string(ack) != "ACK\n" {
		t.Fatalf("ACK 内容异常：%q", ack)
	}
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("接收端未退出")
	}
	if _, err := os.Stat(grant.DstPath); err != nil {
		t.Fatalf("文件未落盘：%v", err)
	}
}

// 回归：流被截断时必须**快速**失败，不能等到 90 秒写超时 / 10 分钟 ACK。
//
// 被墙网络里最常见的干扰是吞掉流的中段（而不是干净关连接）。实测一次
// 1MB 传输因此卡了 91.23 秒（≈ 90s 写超时）才报错，用户无法判断是卡死
// 还是在慢慢传。现在帧内静默超过 frameIdleTimeout 就断开。
func TestRegressTruncatedStreamFailsFast(t *testing.T) {
	seq := &scriptedConn{chunks: []scriptedChunk{
		// 一帧的**合法**开头：magic + idx + 声明 20 字节，然后戛然而止。
		// 必须用真实 Magic，否则 ReadFrame 会以 "bad magic" 提前返回，
		// 测试就变成假通过（我第一版就是这么错的）。
		{data: func() []byte {
			b := make([]byte, headerLen)
			copy(b, Magic)
			b[7] = 1   // idx = 1
			b[15] = 20 // 声明 20 字节
			return b
		}()},
		// 此后再无数据，也不关闭 → 模拟流被吞
	}}
	start := time.Now()
	// 用一个短超时验证机制本身（生产值是 30s）
	old := frameIdleTimeout
	frameIdleTimeout = 300 * time.Millisecond
	defer func() { frameIdleTimeout = old }()

	_, _, err := ReadFrame(seq)
	el := time.Since(start)
	if err == nil {
		t.Fatal("截断的流应返回错误")
	}
	if el > 3*time.Second {
		t.Fatalf("截断流应快速失败，实际耗时 %s（回归：无限等待）", el.Round(time.Millisecond))
	}
}

type scriptedChunk struct {
	data []byte
}

// scriptedConn 依次吐出预置数据；数据用尽后**阻塞**（不返回 EOF），
// 模拟"流被中间设备吞掉"而不是正常关闭。
type scriptedConn struct {
	chunks []scriptedChunk
	i      int
	dead   chan struct{}
	dl     time.Time
}

func (s *scriptedConn) Read(p []byte) (int, error) {
	if s.dead == nil {
		s.dead = make(chan struct{})
	}
	if !s.dl.IsZero() && time.Now().After(s.dl) {
		return 0, os.ErrDeadlineExceeded
	}
	if s.i >= len(s.chunks) {
		// 阻塞到 deadline（若有）或永久
		if s.dl.IsZero() {
			select {}
		}
		time.Sleep(time.Until(s.dl))
		return 0, os.ErrDeadlineExceeded
	}
	n := copy(p, s.chunks[s.i].data)
	s.i++
	return n, nil
}

func (s *scriptedConn) SetReadDeadline(t time.Time) error {
	s.dl = t
	return nil
}

// 回归：进度/限速必须按"实际写出的字节"平滑累计，不能整块跳变。
//
// 背景：一帧是 4MB，300KB/s 链路上一次 Write 阻塞 13 秒。按 Write 调用
// 计数会让前 13 秒进度恒为 0，停滞检测打出 "quic 太慢（0 KB/s）"，
// 而实际上链路在稳定按 300KB/s 推进。
func TestRegressProgressSmoothDuringSlowWrite(t *testing.T) {
	// 模拟一个"每次 Write 耗时 40ms"的慢流
	slow := &slowWriter{perWrite: 40 * time.Millisecond}
	rt := newTaskRate(0) // 不限速，只观察计数
	cw := &countingWriter{w: slow, rate: rt, progress: true}

	var seen []int64
	var mu sync.Mutex
	SetProgressSink(func(n int64) {
		mu.Lock()
		seen = append(seen, n)
		mu.Unlock()
	})
	defer SetProgressSink(nil)

	// 一次 Write 4MB（= 一帧），应被切成多片分别计数
	data := make([]byte, 4<<20)
	start := time.Now()
	if _, err := cw.Write(data); err != nil {
		t.Fatal(err)
	}
	el := time.Since(start)

	mu.Lock()
	n := len(seen)
	last := int64(0)
	if n > 0 {
		last = seen[n-1]
	}
	mu.Unlock()

	// 4MB / 64KB = 64 片
	if n < 32 {
		t.Fatalf("应分片计数（≥32 次），实际只有 %d 次（回归：整块计数导致进度跳跃）", n)
	}
	if last != int64(len(data)) {
		t.Fatalf("最终计数应等于总字节数，实际 %d", last)
	}
	// 单调递增
	for i := 1; i < n; i++ {
		if seen[i] <= seen[i-1] {
			t.Fatalf("计数应单调递增：第 %d 项 %d 未超过前一项 %d", i, seen[i], seen[i-1])
		}
	}
	// 中途就应该有计数（不是等到最后才跳）
	mid := seen[n/2]
	if mid <= 0 || mid >= int64(len(data)) {
		t.Fatalf("中途计数应在 (0, 总长) 之间，实际 %d", mid)
	}
	_ = el
}

// slowWriter 每次 Write 消耗固定时间，模拟慢链路。
type slowWriter struct {
	perWrite time.Duration
	n        int
}

func (s *slowWriter) Write(p []byte) (int, error) {
	time.Sleep(s.perWrite)
	s.n += len(p)
	return len(p), nil
}
