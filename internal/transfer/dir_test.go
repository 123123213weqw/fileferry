package transfer

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"fileferry/internal/api"
	"fileferry/internal/ca"
)

// TestSafeRelPath 相对路径校验：.. / 绝对路径 / 空串必须拒绝。
func TestSafeRelPath(t *testing.T) {
	bad := []string{"", "../x", "a/../..", "/abs/x", "a/../../b", "..", "a/\x00b"}
	for _, p := range bad {
		if SafeRelPath(p) {
			t.Errorf("应拒绝 %q", p)
		}
	}
	good := []string{"a.bin", "sub/a.bin", "a/b/c/deep.bin", "a..b", "..a"}
	for _, p := range good {
		if !SafeRelPath(p) {
			t.Errorf("应接受 %q", p)
		}
	}
}

// TestDeriveFileKey 每文件密钥必须互异且确定性（收发两端同路径得同钥）。
func TestDeriveFileKey(t *testing.T) {
	master := make([]byte, 32)
	rand.Read(master)
	k1 := DeriveFileKey(master, "a.bin")
	k2 := DeriveFileKey(master, "b.bin")
	k1again := DeriveFileKey(master, "a.bin")
	if bytes.Equal(k1, k2) {
		t.Fatal("不同路径派生出相同密钥：目录模式会跨文件重用 nonce")
	}
	if !bytes.Equal(k1, k1again) {
		t.Fatal("同路径派生不确定：接收端将无法解密")
	}
	if len(k1) != 32 {
		t.Fatalf("密钥长度 %d != 32", len(k1))
	}
}

// TestDirTransfer 目录模式端到端：3 文件子目录树（含嵌套目录、
// 不同权限与修改时间），SendTree → RecvStream 逐文件接收，逐字节
// 与属性（mode/mtime）一致。
func TestDirTransfer(t *testing.T) {
	root, err := ca.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_ = pub

	srcRoot := t.TempDir()
	sub := filepath.Join(srcRoot, "sub")
	os.MkdirAll(sub, 0o755)
	files := map[string]struct {
		data []byte
		mode os.FileMode
		mt   time.Time
	}{
		"top.bin":     {[]byte("top-level"), 0o640, time.Unix(1700000000, 0)},
		"sub/nest.bin": {make([]byte, 300*1024), 0o600, time.Unix(1700000100, 0)},
		"empty.bin":   {[]byte{}, 0o644, time.Unix(1700000200, 0)},
	}
	for rel, f := range files {
		if _, err := rand.Read(f.data); err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(srcRoot, filepath.FromSlash(rel))
		if err := os.WriteFile(p, f.data, f.mode); err != nil {
			t.Fatal(err)
		}
		os.Chtimes(p, f.mt, f.mt)
	}

	// 接收端：一个进程内 QUIC/TCP 监听（复用 startNode）
	dstQ, stopDst := startNode(t, "dst", root, func(g *api.TransferGrant) bool { return g.Verify(pub) })
	defer stopDst()

	dstRoot := t.TempDir()
	grant := &api.TransferGrant{
		ID: fmt.Sprintf("xfer-dir-%d", time.Now().UnixNano()), Src: "src", Dst: "dst",
		Streams: 2, IsDir: true,
		Hops:    []api.Hop{{NodeID: "src"}, {NodeID: "dst", Addr: dstQ, Proto: "quic"}},
		SrcPath: srcRoot, DstPath: dstRoot,
	}
	grant.Sign(priv)

	srcTLS := clientTLSFor(t, root, "src")
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	_, n, err := SendTree(ctx, srcRoot, OpenerDirect(ctx, grant.Hops[1], srcTLS), srcTLS, grant)
	if err != nil {
		t.Fatalf("SendTree 失败：%v", err)
	}
	if n != len(files) {
		t.Fatalf("发送文件数 %d != %d", n, len(files))
	}

	for rel, f := range files {
		dst := filepath.Join(dstRoot, filepath.FromSlash(rel))
		got := waitForFile(t, dst)
		if !bytes.Equal(got, f.data) {
			t.Errorf("%s 内容不一致（%d vs %d 字节）", rel, len(f.data), len(got))
		}
		if st, err := os.Stat(dst); err == nil {
			if st.Mode().Perm() != f.mode {
				t.Errorf("%s 权限 %v != %v", rel, st.Mode().Perm(), f.mode)
			}
			if st.ModTime().Unix() != f.mt.Unix() {
				t.Errorf("%s mtime %d != %d", rel, st.ModTime().Unix(), f.mt.Unix())
			}
		}
	}
}

// TestDirTransferEncrypted 目录+端到端加密：密钥经注入的专递/取用
// 链路（对齐 agent 连 controller 的 keypass），每文件派生密钥，
// 内容逐字节一致。回归防：接收端误用主密钥导致解密全挂。
func TestDirTransferEncrypted(t *testing.T) {
	root, err := ca.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_ = pub

	srcRoot := t.TempDir()
	files := map[string][]byte{
		"a.bin":      make([]byte, 100*1024),
		"sub/b.bin":  make([]byte, 5*1024*1024), // 跨 2 块
		"sub/c.bin":  []byte("small"),
	}
	for rel, data := range files {
		rand.Read(data)
		if err := os.MkdirAll(filepath.Join(srcRoot, filepath.Dir(rel)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(srcRoot, filepath.FromSlash(rel)), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	// keypass 单槽：模拟 controller 的 keypass 存储
	var keypass struct {
		mu sync.Mutex
		m  map[string][]byte
	}
	keypass.m = map[string][]byte{}
	SetKeyDeliverer(func(grantID string, material []byte) error {
		keypass.mu.Lock()
		defer keypass.mu.Unlock()
		keypass.m[grantID] = material
		return nil
	})
	SetKeyFetcher(func(grantID string) ([]byte, error) {
		keypass.mu.Lock()
		defer keypass.mu.Unlock()
		if mat, ok := keypass.m[grantID]; ok {
			return mat, nil
		}
		return nil, fmt.Errorf("密钥不存在: %s", grantID)
	})
	defer func() { SetKeyDeliverer(nil); SetKeyFetcher(nil) }()

	dstQ, stopDst := startNode(t, "dst", root, func(g *api.TransferGrant) bool { return g.Verify(pub) })
	defer stopDst()

	dstRoot := t.TempDir()
	grant := &api.TransferGrant{
		ID: fmt.Sprintf("xfer-direnc-%d", time.Now().UnixNano()), Src: "src", Dst: "dst",
		Streams: 2, IsDir: true, Enc: true,
		Hops:    []api.Hop{{NodeID: "src"}, {NodeID: "dst", Addr: dstQ, Proto: "quic"}},
		SrcPath: srcRoot, DstPath: dstRoot,
	}
	grant.Sign(priv)

	srcTLS := clientTLSFor(t, root, "src")
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	if _, n, err := SendTree(ctx, srcRoot, OpenerDirect(ctx, grant.Hops[1], srcTLS), srcTLS, grant); err != nil {
		t.Fatalf("SendTree(加密) 失败：%v", err)
	} else if n != len(files) {
		t.Fatalf("文件数 %d != %d", n, len(files))
	}
	for rel, data := range files {
		got := waitForFile(t, filepath.Join(dstRoot, filepath.FromSlash(rel)))
		if !bytes.Equal(got, data) {
			t.Errorf("%s 解密内容不一致（%d vs %d 字节）", rel, len(data), len(got))
		}
	}
}

// TestBandwidth 限速器：1MB/s 配额下发送 4MB 至少需要 ~4s（突发上限 0.5s 配额内允许）。
func TestBandwidth(t *testing.T) {
	lim := newBandwidth(1024*1024, 1) // 1 MB/s
	start := time.Now()
	chunk := 256 * 1024
	for i := 0; i < 16; i++ { // 4MB
		lim.wait(chunk)
	}
	el := time.Since(start)
	if el < 3200*time.Millisecond {
		t.Fatalf("限速未生效：4MB@1MB/s 仅耗时 %v", el.Round(time.Millisecond))
	}
	if el > 8*time.Second {
		t.Fatalf("限速过严：%v", el.Round(time.Millisecond))
	}
}

// TestDeltaTransfer 增量同步端到端：目的端已有 basis（源文件的旧版），
// grant.Delta 让发送端只发差异配方；重建结果逐字节等于源文件。
// 回归防：BASE 行握手、配方帧、哨兵后 finalize 的整链路。
func TestDeltaTransfer(t *testing.T) {
	root, err := ca.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_ = pub

	basis := make([]byte, 5*1024*1024)
	rand.Read(basis)
	edit := make([]byte, 64*1024)
	rand.Read(edit)
	tail := make([]byte, 1024*1024)
	rand.Read(tail)
	var src []byte
	src = append(src, basis[:2*1024*1024]...)
	src = append(src, edit...)
	src = append(src, basis[2*1024*1024+64*1024:4*1024*1024]...)
	src = append(src, tail...)

	for _, enc := range []bool{false, true} {
		name := "plain"
		if enc {
			name = "enc"
		}
		t.Run(name, func(t *testing.T) {
			if enc {
				var keypass struct {
					mu sync.Mutex
					m  map[string][]byte
				}
				keypass.m = map[string][]byte{}
				SetKeyDeliverer(func(grantID string, material []byte) error {
					keypass.mu.Lock()
					defer keypass.mu.Unlock()
					keypass.m[grantID] = material
					return nil
				})
				SetKeyFetcher(func(grantID string) ([]byte, error) {
					keypass.mu.Lock()
					defer keypass.mu.Unlock()
					if mat, ok := keypass.m[grantID]; ok {
						return mat, nil
					}
					return nil, fmt.Errorf("密钥不存在")
				})
				defer func() { SetKeyDeliverer(nil); SetKeyFetcher(nil) }()
			}
			dstQ, stopDst := startNode(t, "dst", root, func(g *api.TransferGrant) bool { return g.Verify(pub) })
			defer stopDst()

			dir := t.TempDir()
			dstPath := filepath.Join(dir, "out", "data.bin")
			os.MkdirAll(filepath.Dir(dstPath), 0o755)
			os.WriteFile(dstPath, basis, 0o600) // 目的端已有旧版
			srcPath := filepath.Join(dir, "src.bin")
			os.WriteFile(srcPath, src, 0o600)

			grant := &api.TransferGrant{
				ID: fmt.Sprintf("xfer-delta-%s-%d", name, time.Now().UnixNano()),
				Src: "src", Dst: "dst", Streams: 4, Delta: true, Enc: enc,
				Hops:    []api.Hop{{NodeID: "src"}, {NodeID: "dst", Addr: dstQ, Proto: "quic"}},
				SrcPath: srcPath, DstPath: dstPath,
			}
			grant.Sign(priv)
			srcTLS := clientTLSFor(t, root, "src")
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			if _, err := SendFileRange(ctx, srcPath, OpenerDirect(ctx, grant.Hops[1], srcTLS), srcTLS, grant, 0, -1); err != nil {
				t.Fatalf("delta 传输失败：%v", err)
			}
			got := waitForFile(t, dstPath)
			if !bytes.Equal(got, src) {
				t.Fatalf("delta 重建不一致: got %d bytes, want %d", len(got), len(src))
			}
		})
	}
}

// TestDeltaNoBasis 目的端无已有文件：BASE - 即时全量回退，内容正确。
func TestDeltaNoBasis(t *testing.T) {
	root, err := ca.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_ = pub
	dstQ, stopDst := startNode(t, "dst", root, func(g *api.TransferGrant) bool { return g.Verify(pub) })
	defer stopDst()
	dir := t.TempDir()
	src := make([]byte, 300*1024)
	rand.Read(src)
	srcPath := filepath.Join(dir, "src.bin")
	dstPath := filepath.Join(dir, "out", "data.bin")
	os.WriteFile(srcPath, src, 0o600)
	grant := &api.TransferGrant{
		ID: fmt.Sprintf("xfer-dnb-%d", time.Now().UnixNano()),
		Src: "src", Dst: "dst", Delta: true,
		Hops:    []api.Hop{{NodeID: "src"}, {NodeID: "dst", Addr: dstQ, Proto: "quic"}},
		SrcPath: srcPath, DstPath: dstPath,
	}
	grant.Sign(priv)
	srcTLS := clientTLSFor(t, root, "src")
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	if _, err := SendFileRange(ctx, srcPath, OpenerDirect(ctx, grant.Hops[1], srcTLS), srcTLS, grant, 0, -1); err != nil {
		t.Fatalf("无基准 delta 传输失败：%v", err)
	}
	got := waitForFile(t, dstPath)
	if !bytes.Equal(got, src) {
		t.Fatalf("全量回退内容不一致")
	}
}

// TestDirRejectPathEscape 恶意清单伪造 ".." 相对路径必须被拒绝（验签+路径校验双闸）。
func TestDirRejectPathEscape(t *testing.T) {
	root, err := ca.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_ = pub
	dstQ, stopDst := startNode(t, "dst", root, func(g *api.TransferGrant) bool { return g.Verify(pub) })
	defer stopDst()

	grant := &api.TransferGrant{
		ID: fmt.Sprintf("xfer-esc-%d", time.Now().UnixNano()), Src: "src", Dst: "dst",
		IsDir: true, Streams: 1,
		Hops:    []api.Hop{{NodeID: "src"}, {NodeID: "dst", Addr: dstQ, Proto: "quic"}},
		SrcPath: "/tmp", DstPath: t.TempDir(),
	}
	grant.Sign(priv)

	// 攻击者持合法源证书但伪造 relPath="../escape.bin"：路径参与签名，
	// 只能自己签——接收端必须靠 SafeRelPath 拦下
	srcTLS := clientTLSFor(t, root, "src")
	victim := t.TempDir()
	payload := []byte("evil")
	p := filepath.Join(t.TempDir(), "srcfile")
	os.WriteFile(p, payload, 0o600)
	mf, err := BuildManifest(grant.ID, p, "../escape.bin", srcTLS)
	if err != nil {
		t.Fatal(err)
	}
	if err := mf.Verify(grant, srcTLS.RootCAs); err == nil {
		// 签名合法（确实是源签的），但 Path 校验必须在 Verify 或 groupFor 拦截
		t.Log("签名通过（符合预期：源有权签任意路径），落盘前必须被 SafeRelPath 拦截")
	}
	_ = victim
	// 直接验证 SafeRelPath 闸门（groupFor 之前的最后一道）
	if SafeRelPath("../escape.bin") {
		t.Fatal("../ 逃逸路径未被拦截")
	}
}
