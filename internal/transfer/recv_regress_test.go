package transfer

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"fileferry/internal/api"
)

func testGrant(id string) *api.TransferGrant {
	return &api.TransferGrant{
		ID:        id,
		Src:       "a",
		Dst:       "b",
		Mode:      "send",
		ChunkSize: ChunkSize,
		Streams:   1,
		ExpiresAt: time.Now().Add(time.Hour),
		Hops:      []api.Hop{{NodeID: "a"}, {NodeID: "b", Addr: "127.0.0.1:7800"}},
	}
}

// 回归：干净 EOF 必须被当作"这个份额没完成"，而不是"份额结束了"。
//
// 旧实现 `if err == io.EOF { return nil }`：块没齐也返回 nil，于是
// RecvStream 去等 g.finished，白等 10 分钟（发送端同时卡在 10 分钟 ACK 上）。
// "中继重启向接收端发正常 FIN"这种日常故障，本该秒级失败换路，实际变成
// 十分钟静默。
func TestFeedEarlyEOFIsFailure(t *testing.T) {
	dir := t.TempDir()
	tmp, err := os.CreateTemp(dir, ".ff-*")
	if err != nil {
		t.Fatal(err)
	}
	defer tmp.Close()
	g := &recvGroup{
		grantID:   "regress-eof",
		size:      3 * int64(ChunkSize),
		finalPath: filepath.Join(dir, "out.bin"),
		dstPath:   filepath.Join(dir, "out.bin"),
		tmp:       tmp,
		tmpName:   tmp.Name(),
		expected:  3,
		got:       map[int64]bool{},
		finished:  make(chan struct{}),
	}

	// 只给 1 块就 EOF（没有完成哨兵）
	var buf bytes.Buffer
	if err := WriteFrame(&buf, 0, []byte("only-one-chunk")); err != nil {
		t.Fatal(err)
	}
	err = g.feed(bufio.NewReader(&buf))
	if err == nil {
		t.Fatal("块没齐时 EOF 被当成成功：上层会白等 10 分钟")
	}
	t.Logf("OK：提前 EOF 报错 = %v", err)
}

// 回归：份额收齐后 EOF 仍应视为正常（不然多流并发会误报失败）。
func TestFeedEOFAfterAllBlocksIsOK(t *testing.T) {
	dir := t.TempDir()
	tmp, err := os.CreateTemp(dir, ".ff-*")
	if err != nil {
		t.Fatal(err)
	}
	defer tmp.Close()
	g := &recvGroup{
		grantID:   "regress-eof-ok",
		size:      1,
		finalPath: filepath.Join(dir, "out.bin"),
		dstPath:   filepath.Join(dir, "out.bin"),
		tmp:       tmp,
		tmpName:   tmp.Name(),
		expected:  1,
		got:       map[int64]bool{},
		finished:  make(chan struct{}),
	}
	var buf bytes.Buffer
	if err := WriteFrame(&buf, 0, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := g.feed(bufio.NewReader(&buf)); err != nil {
		t.Fatalf("块已收齐，EOF 不该报错：%v", err)
	}
}

// 回归：manifest 验签失败时 RecvStream 必须返回 error。
//
// 旧实现返回 void，交换台模式的 switchRecvShare 于是无条件 return nil，
// runSwitchRecv 的失败计数永远为 0，最后无条件打印"接收完成"——验签失败、
// 块不齐、哈希不符全都报成功，直接骗运维。
func TestRecvStreamReportsManifestRejection(t *testing.T) {
	grant := testGrant("regress-manifest")
	var buf bytes.Buffer
	bad := Manifest{GrantID: grant.ID, SHA256: "deadbeef", Size: 1, CertB64: "!!", SigB64: "!!"}
	b, _ := json.Marshal(bad)
	buf.Write(b)
	buf.WriteString("\n")

	err := RecvStream(bufio.NewReader(&buf), &nopStream{}, grant, nil)
	if err == nil {
		t.Fatal("清单验签失败却返回 nil：上层会把这次接收报成成功")
	}
	t.Logf("OK：验签失败上报 = %v", err)
}

// 回归：saveProgress 必须先把数据 Sync 再写位图，且位图要原子写。
//
// 旧实现直接 os.WriteFile 位图，此时数据可能还在 page cache：断电后位图
// 声称"块已收"、临时文件里却是空洞，续传接管后 len(got)==expected 立刻
// 成立，直接进 finalize → 全哈希不符 → 白跑一遍并硬失败。
func TestSaveProgressWritesAtomically(t *testing.T) {
	dir := t.TempDir()
	finalPath := filepath.Join(dir, "out.bin")
	tmp, err := os.CreateTemp(dir, ".ff-*")
	if err != nil {
		t.Fatal(err)
	}
	defer tmp.Close()

	g := &recvGroup{
		grantID:   "regress-progress",
		wantSHA:   "abc",
		size:      int64(ChunkSize),
		finalPath: finalPath,
		dstPath:   finalPath,
		tmp:       tmp,
		tmpName:   tmp.Name(),
		expected:  1,
		got:       map[int64]bool{0: true},
		finished:  make(chan struct{}),
	}
	g.saveProgress()

	b, err := os.ReadFile(g.partPath())
	if err != nil {
		t.Fatalf("位图没写出来：%v", err)
	}
	var p struct {
		Size    int64  `json:"size"`
		SHA256  string `json:"sha256"`
		TmpName string `json:"tmp"`
		Bits    []byte `json:"bits"`
	}
	if err := json.Unmarshal(b, &p); err != nil {
		t.Fatalf("位图不是完整 JSON（原子写失败？）：%v", err)
	}
	if len(p.Bits) == 0 || p.Bits[0] != 1 {
		t.Fatalf("位图内容错误：%v", p.Bits)
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if len(e.Name()) >= 8 && e.Name()[:8] == ".ffpart-" {
			t.Fatalf("原子写的临时文件残留：%s", e.Name())
		}
	}
}

// 回归：目标变了（size/sha 不同）时，旧位图与它记录的临时文件都要被清掉。
// 旧实现直接 return，放弃的任务在目的目录留下与源文件等大的 .ff-*。
func TestLoadProgressDiscardsStale(t *testing.T) {
	dir := t.TempDir()
	finalPath := filepath.Join(dir, "out.bin")
	staleTmp := filepath.Join(dir, ".ff-stale123")
	if err := os.WriteFile(staleTmp, make([]byte, 1024), 0o600); err != nil {
		t.Fatal(err)
	}
	tmp, err := os.CreateTemp(dir, ".ff-*")
	if err != nil {
		t.Fatal(err)
	}
	defer tmp.Close()

	g := &recvGroup{
		grantID:   "regress-stale",
		wantSHA:   "newsha",
		size:      999, // 与 sidecar 不符
		finalPath: finalPath,
		dstPath:   finalPath,
		tmp:       tmp,
		tmpName:   tmp.Name(),
		expected:  1,
		got:       map[int64]bool{},
		finished:  make(chan struct{}),
	}
	sidecar, _ := json.Marshal(map[string]any{
		"size": 111, "sha256": "oldsha", "tmp": staleTmp, "bits": []byte{1},
	})
	if err := os.WriteFile(g.partPath(), sidecar, 0o600); err != nil {
		t.Fatal(err)
	}

	g.loadProgress()

	if _, err := os.Stat(staleTmp); !os.IsNotExist(err) {
		t.Fatal("陈旧临时文件没被清理：放弃的任务会一直占着与源等大的空间")
	}
	if _, err := os.Stat(g.partPath()); !os.IsNotExist(err) {
		t.Fatal("陈旧 sidecar 没被清理")
	}
}

// 回归：伪造的 sidecar 不能让接收端删任意文件（TmpName 是不可信输入）。
func TestLoadProgressRefusesForeignTmpPath(t *testing.T) {
	dir := t.TempDir()
	victimDir := t.TempDir()
	victim := filepath.Join(victimDir, "victim.txt")
	if err := os.WriteFile(victim, []byte(" precious "), 0o600); err != nil {
		t.Fatal(err)
	}
	finalPath := filepath.Join(dir, "out.bin")
	tmp, err := os.CreateTemp(dir, ".ff-*")
	if err != nil {
		t.Fatal(err)
	}
	defer tmp.Close()
	g := &recvGroup{
		grantID:   "regress-foreign",
		wantSHA:   "newsha",
		size:      9,
		finalPath: finalPath,
		dstPath:   finalPath,
		tmp:       tmp,
		tmpName:   tmp.Name(),
		expected:  1,
		got:       map[int64]bool{},
		finished:  make(chan struct{}),
	}
	sidecar, _ := json.Marshal(map[string]any{
		"size": 1, "sha256": "x", "tmp": victim, "bits": []byte{1},
	})
	os.WriteFile(g.partPath(), sidecar, 0o600)
	g.loadProgress()
	if _, err := os.Stat(victim); err != nil {
		t.Fatalf("越界路径被删除了：sidecar 是不可信输入（%v）", err)
	}
}

// nopStream 是满足 Stream 接口的最小实现（测试只要读侧）。
type nopStream struct{ bytes.Buffer }

func (n *nopStream) Close() error { return nil }
