package transfer

import (
	"fmt"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"fileferry/internal/api"
	"fileferry/internal/ca"
)

// startNode 起一个数据面节点：QUIC 监听（127.0.0.1 随机端口）+
// 按约定端口 +1 的 TCP 回退监听（被占用则跳过）。
func startNode(t *testing.T, id string, root *ca.CA, verify GrantVerifier) (quicAddr string, stop func()) {
	t.Helper()
	_, _, cert, err := root.Issue(id, true, ca.RoleNode, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	clientTLS := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      root.Pool(),
		MinVersion:   tls.VersionTLS13,
	}
	serverTLS := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    root.Pool(),
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}

	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	qln, err := quic.Listen(udp, serverTLS, &quic.Config{MaxIdleTimeout: 30 * time.Second})
	if err != nil {
		udp.Close()
		t.Fatal(err)
	}
	qport := udp.LocalAddr().(*net.UDPAddr).Port

	var tln net.Listener
	if raw, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(qport+1))); err == nil {
		tln = tls.NewListener(raw, serverTLS)
	}

	done := make(chan struct{})
	go func() { ServeQUIC(qln, id, verify, clientTLS); close(done) }()
	if tln != nil {
		go ServeTCP(tln, id, verify, clientTLS)
	}
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(qport)), func() {
		qln.Close()
		if tln != nil {
			tln.Close()
		}
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
	}
}

func clientTLSFor(t *testing.T, root *ca.CA, id string) *tls.Config {
	t.Helper()
	_, _, cert, err := root.Issue(id, true, ca.RoleNode, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: root.Pool(), MinVersion: tls.VersionTLS13}
}

// grantKeys 用一次性 ed25519 密钥签发并本地验签。
func grantKeys(t *testing.T) (sign func(*api.TransferGrant), verify GrantVerifier) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return func(g *api.TransferGrant) { g.Sign(priv) },
		func(g *api.TransferGrant) bool { return g.Verify(pub) }
}

// 并行多流直传：3 条连接交错分块，逐字节一致。
func TestParallelStreams(t *testing.T) {
	root, err := ca.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sign, verify := grantKeys(t)
	dstQ, stopDst := startNode(t, "dst", root, verify)
	defer stopDst()

	dir := t.TempDir()
	payload := make([]byte, 12*1024*1024) // 12MB，非整块数
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	srcPath := filepath.Join(dir, "src.bin")
	dstPath := filepath.Join(dir, "out", "dst.bin")
	os.WriteFile(srcPath, payload, 0o600)

	grant := &api.TransferGrant{
		ID: fmt.Sprintf("xfer-par-%d", time.Now().UnixNano()), Src: "src", Dst: "dst", Streams: 3,
		Hops:    []api.Hop{{NodeID: "src"}, {NodeID: "dst", Addr: dstQ, Proto: "quic"}},
		SrcPath: srcPath, DstPath: dstPath,
	}
	sign(grant)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := SendFile(ctx, srcPath, OpenerDirect(ctx, grant.Hops[1], clientTLSFor(t, root, "src")), clientTLSFor(t, root, "src"), grant); err != nil {
		t.Fatalf("并行发送失败：%v", err)
	}
	got := waitForFile(t, dstPath)

	if !bytes.Equal(got, payload) {
		t.Fatalf("内容不一致：源 %d 字节，目的 %d 字节", len(payload), len(got))
	}
}

// 源 -> 中继 -> 目的，全程 QUIC，9MB 逐字节一致。
func TestRelayTransferQUIC(t *testing.T) {
	root, err := ca.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sign, verify := grantKeys(t)

	relayQ, stopRelay := startNode(t, "relay", root, verify)
	dstQ, stopDst := startNode(t, "dst", root, verify)
	defer stopRelay()
	defer stopDst()

	dir := t.TempDir()
	payload := make([]byte, 9*1024*1024) // 9MB：2 整块 + 1 部分块
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	srcPath := filepath.Join(dir, "src.bin")
	dstPath := filepath.Join(dir, "out", "dst.bin")
	if err := os.WriteFile(srcPath, payload, 0o600); err != nil {
		t.Fatal(err)
	}

	grant := &api.TransferGrant{
		ID:      fmt.Sprintf("xfer-relay-%d", time.Now().UnixNano()),
		Src:     "src",
		Dst:     "dst",
		Hops:    []api.Hop{{NodeID: "src"}, {NodeID: "relay", Addr: relayQ, Proto: "quic"}, {NodeID: "dst", Addr: dstQ, Proto: "quic"}},
		SrcPath: srcPath,
		DstPath: dstPath,
	}
	sign(grant)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if _, err := SendFile(ctx, srcPath, OpenerDirect(ctx, grant.Hops[1], clientTLSFor(t, root, "src")), clientTLSFor(t, root, "src"), grant); err != nil {
		t.Fatalf("经中继发送失败：%v", err)
	}
	got := waitForFile(t, dstPath)

	if !bytes.Equal(got, payload) {
		t.Fatalf("内容不一致：源 %d 字节，目的 %d 字节", len(payload), len(got))
	}
}

// TCP 回退通道直传。
func TestDirectTransferTCP(t *testing.T) {
	root, err := ca.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sign, verify := grantKeys(t)

	// 先占一个 TCP 端口，再按“QUIC 端口+1”约定反推拨号地址：
	// 把 Hop.Addr 写成 tcpPort-1，DialStream 会拨 tcpPort-1+1
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
	payload := []byte("tcp fallback payload")
	srcPath := filepath.Join(dir, "s.bin")
	dstPath := filepath.Join(dir, "d.bin")
	os.WriteFile(srcPath, payload, 0o600)

	grant := &api.TransferGrant{
		ID: fmt.Sprintf("xfer-tcp-%d", time.Now().UnixNano()), Src: "src", Dst: "dst",
		Hops: []api.Hop{
			{NodeID: "src"},
			{NodeID: "dst", Addr: net.JoinHostPort("127.0.0.1", strconv.Itoa(tcpPort-1)), Proto: "tcp"},
		},
		SrcPath: srcPath, DstPath: dstPath,
	}
	sign(grant)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := SendFile(ctx, srcPath, OpenerDirect(ctx, grant.Hops[1], clientTLSFor(t, root, "src")), clientTLSFor(t, root, "src"), grant); err != nil {
		t.Fatalf("TCP 直传失败：%v", err)
	}
	got := waitForFile(t, dstPath)

	if !bytes.Equal(got, payload) {
		t.Fatal("内容不一致")
	}
}

// 不在签名路径上的节点必须拒绝中继——防开放代理。
func TestRelayRejectsUnknownNode(t *testing.T) {
	root, err := ca.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sign, verify := grantKeys(t)
	relayQ, stop := startNode(t, "innocent", root, verify)
	defer stop()

	dir := t.TempDir()
	srcPath := filepath.Join(dir, "real.bin")
	os.WriteFile(srcPath, []byte("data"), 0o600)

	grant := &api.TransferGrant{
		ID: "xfer-evil", Src: "a", Dst: "b",
		Hops: []api.Hop{
			{NodeID: "a"},
			{NodeID: "someoneelse", Addr: relayQ, Proto: "quic"}, // 冒名顶替的中继
			{NodeID: "b", Addr: "127.0.0.1:1", Proto: "quic"},
		},
		SrcPath: srcPath, DstPath: "/tmp/should-not-exist.bin",
	}
	sign(grant)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// innocent 节点验签通过但发现自己不在路径上，拒绝转发并断流，
	// 发送端应得到错误而非成功
	if _, err := SendFile(ctx, srcPath, OpenerDirect(ctx, grant.Hops[1], clientTLSFor(t, root, "a")), clientTLSFor(t, root, "a"), grant); err == nil {
		t.Fatal("不应成功：中继节点不在路径上，应拒绝且发送失败")
	}
}
