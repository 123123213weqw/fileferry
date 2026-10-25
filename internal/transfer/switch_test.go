package transfer

import (
	"fmt"
	"crypto/tls"
	"net"
	"strconv"
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"fileferry/internal/api"
	"fileferry/internal/ca"
)


// waitForFile 轮询等待文件落盘（份额级 ACK 后 rename 是异步终态）。
func waitForFile(t *testing.T, path string) []byte {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(path); err == nil {
			return b
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("文件 10s 未落盘：%s", path)
	return nil
}

// TestSwitchTransfer 三节点交换台模式：源与目的之间没有任何直连边，
// 各自出站拨向交换台（DERP 式）配对对接，2 流并行 8MB 逐字节一致。
func TestSwitchTransfer(t *testing.T) {
	root, err := ca.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	verify := func(g *api.TransferGrant) bool { return g.Verify(pub) }

	swQ, stopSw := startNode(t, "sw", root, verify)
	defer stopSw()

	dir := t.TempDir()
	payload := make([]byte, 8*1024*1024)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	srcPath := filepath.Join(dir, "s.bin")
	dstPath := filepath.Join(dir, "out", "d.bin")
	os.WriteFile(srcPath, payload, 0o600)

	grant := &api.TransferGrant{
		ID: fmt.Sprintf("xfer-sw-%d", time.Now().UnixNano()), Src: "src", Dst: "dst", Mode: "switch", Streams: 2,
		Hops:    []api.Hop{{NodeID: "src"}, {NodeID: "sw", Addr: swQ, Proto: "quic"}, {NodeID: "dst"}},
		SrcPath: srcPath, DstPath: dstPath,
	}
	grant.Sign(priv)

	var wg sync.WaitGroup
	for i := 0; i < grant.Streams; i++ { // 目的端按并行数接入，一一配对
		wg.Add(1)
		go func() { // 每条连接：接入交换台，按 FFJ1 常规逻辑收份额
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			stream, closeConn, err := DialSwitch(ctx, swQ, "quic", clientTLSFor(t, root, "dst"), grant)
			if err != nil {
				t.Errorf("目的端接入交换台失败：%v", err)
				return
			}
			defer closeConn()
			head := make([]byte, 4)
			if _, err := io.ReadFull(stream, head); err != nil || string(head) != "FFJ1" {
				t.Errorf("期望 FFJ1 流：%v %q", err, head)
				return
			}
			br := bufio.NewReader(stream)
			line, err := br.ReadString('\n')
			if err != nil {
				t.Errorf("读 grant 行失败：%v", err)
				return
			}
			var gg api.TransferGrant
			if err := json.Unmarshal([]byte(line), &gg); err != nil {
				t.Errorf("grant 解析失败：%v", err)
				return
			}
			RecvStream(br, stream, &gg, clientTLSFor(t, root, "dst").RootCAs)
			CloseWrite(stream)
			io.ReadFull(stream, make([]byte, 1))
		}()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	swHop := api.Hop{NodeID: "sw", Addr: swQ, Proto: "quic"}
	if _, err := SendFile(ctx, srcPath, OpenerSwitch(ctx, swHop, clientTLSFor(t, root, "src"), grant), clientTLSFor(t, root, "src"), grant); err != nil {
		t.Fatalf("交换台模式发送失败：%v", err)
	}
	wg.Wait()

	got := waitForFile(t, dstPath)

	if !bytes.Equal(got, payload) {
		t.Fatalf("内容不一致：%d vs %d 字节", len(payload), len(got))
	}
}

// TestManifestTamper 清单防篡改：改一个字节的哈希，验签必须失败。
func TestManifestTamper(t *testing.T) {
	root, err := ca.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "f.bin")
	os.WriteFile(path, []byte("hello"), 0o600)
	tlsConf := clientTLSFor(t, root, "src")
	grant := &api.TransferGrant{ID: "x", Src: "src", Dst: "dst"}
	mf, err := BuildManifest(grant.ID, path, tlsConf)
	if err != nil {
		t.Fatal(err)
	}
	if err := mf.Verify(grant, root.Pool()); err != nil {
		t.Fatalf("合法清单不应失败：%v", err)
	}
	bad := *mf
	bad.SHA256 = "0000" + mf.SHA256[4:]
	if err := bad.Verify(grant, root.Pool()); err == nil {
		t.Fatal("篡改哈希的清单必须被拒绝")
	}
	bad2 := *mf
	other := &api.TransferGrant{ID: "y", Src: "src", Dst: "dst"}
	if err := bad2.Verify(other, root.Pool()); err == nil {
		t.Fatal("跨 grant 重用的清单必须被拒绝")
	}
}

// TestMultiSource 双源一目的：同一文件两份副本各发自己的块区间，
// 接收端稀疏写汇聚，逐字节一致。
func TestMultiSource(t *testing.T) {
	root, err := ca.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	verify := func(g *api.TransferGrant) bool { return g.Verify(pub) }

	s1Q, stop1 := startNode(t, "src1", root, verify)
	s2Q, stop2 := startNode(t, "src2", root, verify)
	dstQ, stopD := startNode(t, "dst", root, verify)
	defer stop1()
	defer stop2()
	defer stopD()

	dir := t.TempDir()
	payload := make([]byte, 10*1024*1024) // 10MB = 3 块（4MB 块）
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	// 两份副本（路径不同，内容相同）
	p1 := filepath.Join(dir, "copy1.bin")
	p2 := filepath.Join(dir, "copy2.bin")
	os.WriteFile(p1, payload, 0o600)
	os.WriteFile(p2, payload, 0o600)
	dstPath := filepath.Join(dir, "out", "d.bin")

	grant := &api.TransferGrant{
		ID: fmt.Sprintf("xfer-ms-%d", time.Now().UnixNano()), Src: "src1", Dst: "dst", Streams: 1,
		Hops:    []api.Hop{{NodeID: "src1"}, {NodeID: "dst", Addr: dstQ, Proto: "quic"}, {NodeID: "dst"}},
		SrcPath: p1, DstPath: dstPath,
		// 块 0-1 给 src1，块 2 给 src2（10MB/4MB=3 块）
		Sources: []api.SourceSpec{
			{NodeID: "src1", Addr: dstQ, Proto: "quic", Start: 0, End: 2},
			{NodeID: "src2", Addr: dstQ, Proto: "quic", Start: 2, End: 3},
		},
	}
	grant.Sign(priv)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() { // src2 发自己的区间
		defer wg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if _, err := SendFileRange(ctx, p2, OpenerDirect(ctx, grant.Hops[1], clientTLSFor(t, root, "src2")), clientTLSFor(t, root, "src2"), grant, 2, 3); err != nil {
			t.Errorf("src2 分片失败：%v", err)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if _, err := SendFileRange(ctx, p1, OpenerDirect(ctx, grant.Hops[1], clientTLSFor(t, root, "src1")), clientTLSFor(t, root, "src1"), grant, 0, 2); err != nil {
		t.Fatalf("src1 分片失败：%v", err)
	}
	wg.Wait()

	got := waitForFile(t, dstPath)

	if !bytes.Equal(got, payload) {
		t.Fatalf("多源汇聚不一致：%d vs %d 字节", len(payload), len(got))
	}
	_ = s1Q
	_ = s2Q
}

// TestParallelStreamsTCP 进程内 TCP 4 流并行——复现真机"多流卡死"
// 则为代码 bug；通过则指向环境（中间设备并发连接限制）。
func TestParallelStreamsTCP(t *testing.T) {
	root, err := ca.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sign, verify := grantKeys(t)

	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tcpPort := raw.Addr().(*net.TCPAddr).Port
	raw.Close()
	_, _, dstCert, err := root.Issue("dst", true, ca.RoleNode, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	serverTLS := &tls.Config{
		Certificates: []tls.Certificate{dstCert},
		ClientCAs:    root.Pool(),
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}
	tln, err := tls.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(tcpPort)), serverTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer tln.Close()
	go ServeTCP(tln, "dst", verify, clientTLSFor(t, root, "dst"))

	dir := t.TempDir()
	payload := make([]byte, 40*1024*1024)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	srcPath := filepath.Join(dir, "s.bin")
	dstPath := filepath.Join(dir, "d.bin")
	os.WriteFile(srcPath, payload, 0o600)

	grant := &api.TransferGrant{
		ID: fmt.Sprintf("xfer-ptest-%d", time.Now().UnixNano()), Src: "src", Dst: "dst", Streams: 4,
		Hops: []api.Hop{
			{NodeID: "src"},
			{NodeID: "dst", Addr: net.JoinHostPort("127.0.0.1", strconv.Itoa(tcpPort-1)), Proto: "tcp"},
		},
		SrcPath: srcPath, DstPath: dstPath,
	}
	sign(grant)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := SendFile(ctx, srcPath, OpenerDirect(ctx, grant.Hops[1], clientTLSFor(t, root, "src")), clientTLSFor(t, root, "src"), grant)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("TCP 4 流失败：%v", err)
		}
	case <-time.After(45 * time.Second):
		t.Fatal("TCP 4 流卡死（45 秒未完成）——真机问题进程内复现！")
	}
	got := waitForFile(t, dstPath)

	if !bytes.Equal(got, payload) {
		t.Fatalf("内容不一致：%d vs %d", len(payload), len(got))
	}
}

// TestResumeAfterInterrupt 断点续传：第一次传一半掐断（ctx 取消），
// 第二次新 grant 续传——接收端应跳过已收块并最终完整一致。
func TestResumeAfterInterrupt(t *testing.T) {
	root, err := ca.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sign, verify := grantKeys(t)
	dstQ, stopDst := startNode(t, "dst", root, verify)
	defer stopDst()

	dir := t.TempDir()
	payload := make([]byte, 8*1024*1024) // 2 块
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	srcPath := filepath.Join(dir, "s.bin")
	dstPath := filepath.Join(dir, "out", "d.bin")
	os.WriteFile(srcPath, payload, 0o600)

	// 第一次：单流传输，发完第 0 块后取消（模拟断网）
	g1 := &api.TransferGrant{
		ID: fmt.Sprintf("xfer-cut1-%d", time.Now().UnixNano()), Src: "src", Dst: "dst", Streams: 1,
		Hops:    []api.Hop{{NodeID: "src"}, {NodeID: "dst", Addr: dstQ, Proto: "quic"}},
		SrcPath: srcPath, DstPath: dstPath,
	}
	sign(g1)
	ctx1, cancel1 := context.WithCancel(context.Background())
	go func() {
		// 第 0 块落盘后掐断：轮询进度文件出现即取消
		for i := 0; i < 100; i++ {
			if _, err := os.Stat(dstPath + ".ffpart"); err == nil {
				// 等位图至少含 1 块
				time.Sleep(150 * time.Millisecond)
				cancel1()
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
	}()
	SendFile(ctx1, srcPath, OpenerDirect(ctx1, g1.Hops[1], clientTLSFor(t, root, "src")), clientTLSFor(t, root, "src"), g1) // 预期失败
	cancel1()

	// 第二次：新 grant（同目标路径+文件）续传
	g2 := &api.TransferGrant{
		ID: fmt.Sprintf("xfer-cut2-%d", time.Now().UnixNano()), Src: "src", Dst: "dst", Streams: 1,
		Hops:    []api.Hop{{NodeID: "src"}, {NodeID: "dst", Addr: dstQ, Proto: "quic"}},
		SrcPath: srcPath, DstPath: dstPath,
	}
	sign(g2)
	ctx2, cancel2 := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel2()
	if _, err := SendFile(ctx2, srcPath, OpenerDirect(ctx2, g2.Hops[1], clientTLSFor(t, root, "src")), clientTLSFor(t, root, "src"), g2); err != nil {
		t.Fatalf("续传失败：%v", err)
	}
	got := waitForFile(t, dstPath)
	if !bytes.Equal(got, payload) {
		t.Fatalf("续传后内容不一致：%d vs %d", len(payload), len(got))
	}
	// 进度文件应被清理
	if _, err := os.Stat(dstPath + ".ffpart"); !os.IsNotExist(err) {
		t.Fatal("完成后进度文件应清理")
	}
}

// TestEndToEndEncrypted 端到端加密传输：密钥经注入的专递/获取回调
// 传递，中继（若在路径上）只见密文；明文逐字节一致。
func TestEndToEndEncrypted(t *testing.T) {
	root, err := ca.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sign, verify := grantKeys(t)
	dstQ, stopDst := startNode(t, "dst", root, verify)
	defer stopDst()

	// 密钥专递：内存 map 模拟 controller
	var keyMu sync.Mutex
	keybox := map[string][]byte{}
	SetKeyDeliverer(func(id string, mat []byte) error {
		keyMu.Lock()
		keybox[id] = mat
		keyMu.Unlock()
		return nil
	})
	SetKeyFetcher(func(id string) ([]byte, error) {
		keyMu.Lock()
		defer keyMu.Unlock()
		m, ok := keybox[id]
		if !ok {
			return nil, fmt.Errorf("no key")
		}
		return m, nil
	})

	dir := t.TempDir()
	payload := make([]byte, 9*1024*1024)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	srcPath := filepath.Join(dir, "s.bin")
	dstPath := filepath.Join(dir, "d.bin")
	os.WriteFile(srcPath, payload, 0o600)

	grant := &api.TransferGrant{
		ID: fmt.Sprintf("xfer-enc-%d", time.Now().UnixNano()), Src: "src", Dst: "dst",
		Streams: 2, Enc: true,
		Hops:    []api.Hop{{NodeID: "src"}, {NodeID: "dst", Addr: dstQ, Proto: "quic"}},
		SrcPath: srcPath, DstPath: dstPath,
	}
	sign(grant)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := SendFile(ctx, srcPath, OpenerDirect(ctx, grant.Hops[1], clientTLSFor(t, root, "src")), clientTLSFor(t, root, "src"), grant); err != nil {
		t.Fatalf("加密传输失败：%v", err)
	}
	got := waitForFile(t, dstPath)
	if !bytes.Equal(got, payload) {
		t.Fatalf("解密后内容不一致：%d vs %d", len(payload), len(got))
	}
}

// TestConcurrentTransfers 并发回归：5 个不同 grant 同时传到同一目的
// ——复现压测的并发风暴（验签拒绝/broken pipe）。
func TestConcurrentTransfers(t *testing.T) {
	root, err := ca.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sign, verify := grantKeys(t)
	dstQ, stopDst := startNode(t, "dst", root, verify)
	defer stopDst()

	dir := t.TempDir()
	var wg sync.WaitGroup
	errs := make(chan error, 5)
	for i := 0; i < 5; i++ {
		payload := make([]byte, 8*1024*1024)
		if _, err := rand.Read(payload); err != nil {
			t.Fatal(err)
		}
		src := filepath.Join(dir, fmt.Sprintf("c%d.bin", i))
		os.WriteFile(src, payload, 0o600)
		grant := &api.TransferGrant{
			ID: fmt.Sprintf("xfer-conc-%d-%d", i, time.Now().UnixNano()),
			Src: "src", Dst: "dst", Streams: 4,
			Hops:    []api.Hop{{NodeID: "src"}, {NodeID: "dst", Addr: dstQ, Proto: "quic"}},
			SrcPath: src, DstPath: filepath.Join(dir, fmt.Sprintf("out%d", i), "d.bin"),
		}
		sign(grant)
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			if _, err := SendFile(ctx, src, OpenerDirect(ctx, grant.Hops[1], clientTLSFor(t, root, "src")), clientTLSFor(t, root, "src"), grant); err != nil {
				errs <- fmt.Errorf("并发任务失败: %w", err)
				return
			}
			deadline := time.Now().Add(20 * time.Second)
			for time.Now().Before(deadline) {
				if _, err := os.Stat(grant.DstPath); err == nil {
					return
				}
				time.Sleep(200 * time.Millisecond)
			}
			errs <- fmt.Errorf("文件未落盘: %s", grant.DstPath)
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
}
