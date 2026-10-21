package transfer

import (
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
		ID: "xfer-sw", Src: "src", Dst: "dst", Mode: "switch", Streams: 2,
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
	if err := SendFile(ctx, srcPath, OpenerSwitch(ctx, swHop, clientTLSFor(t, root, "src"), grant), clientTLSFor(t, root, "src"), grant); err != nil {
		t.Fatalf("交换台模式发送失败：%v", err)
	}
	wg.Wait()

	got, err := os.ReadFile(dstPath)
	if err != nil {
		t.Fatalf("目的文件未落盘：%v", err)
	}
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
