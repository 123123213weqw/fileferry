package api

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"
)

// TestGrantJSONRoundTrip 签名→JSON 编码→解码→验签必须一致——
// 真机投递链路（pending→心跳响应→agent）全部经过 JSON 往返。
func TestGrantJSONRoundTrip(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	g := TransferGrant{
		ID: "xfer-1", Src: "node-2", Dst: "node-4",
		Hops: []Hop{{NodeID: "node-2"}, {NodeID: "node-4", Addr: "1.2.3.4:7800", Proto: "tcp"}},
		Sources: []SourceSpec{
			{NodeID: "node-2", Addr: "1.2.3.4:7801", Proto: "tcp", Path: "/home/a/f.bin", Start: 0, End: 16},
			{NodeID: "node-3", Addr: "1.2.3.4:7801", Proto: "tcp", Path: "/home/b/f.bin", Start: 16, End: 25},
		},
		SrcPath: "/home/wzu/ff-share/replica100.bin", DstPath: "/home/xs/ff/recv/x.bin",
		FileSHA256: "abc123", FileSize: 104857600, ChunkSize: 4 << 20,
		Streams: 4, RateLimit: 0, ExpiresAt: time.Now().Add(30 * time.Minute).UTC(),
	}
	g.Sign(priv)
	b, err := json.Marshal(g)
	if err != nil {
		t.Fatal(err)
	}
	var g2 TransferGrant
	if err := json.Unmarshal(b, &g2); err != nil {
		t.Fatal(err)
	}
	if !g2.Verify(pub) {
		t.Fatalf("JSON 往返后验签失败！原始签名 %q", g.Sig)
		t.Logf("原始: %s", b)
		b2, _ := json.Marshal(g2)
		t.Logf("往返: %s", b2)
	}
}

// 回归：V2 长度前缀签名串必须不含分隔符歧义，且 V1 旧签名仍可验。
func TestGrantPayloadV2DistinguishesFields(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	mk := func(id, dst string) *TransferGrant {
		g := &TransferGrant{
			ID: id, Src: "s", Dst: NodeID(dst), Mode: "",
			Hops:    []Hop{{NodeID: "s"}, {NodeID: NodeID(dst), Addr: "1.2.3.4:7800"}},
			SrcPath: "/a|b", DstPath: "/c;d",
			ChunkSize: 4 << 20, Streams: 1,
			ExpiresAt: time.Now().Add(time.Hour).UTC(),
		}
		g.Sign(priv)
		return g
	}
	// 两个结构不同、但旧格式手拼可能撞串的 grant
	a := mk("x", "n1")
	b := mk("x|s|n1", "")
	if a.Sig == b.Sig {
		t.Fatal("不同结构产生了相同签名（分隔符歧义未被消除）")
	}
	if !a.Verify(pub) || !b.Verify(pub) {
		t.Fatal("V2 自验签失败")
	}

	// 篡改必须被发现
	legacy := mk("legacy-1", "n2")
	legacy.DstPath = "/etc/passwd"
	if legacy.Verify(pub) {
		t.Fatal("篡改后仍然验签通过")
	}

	// V1（裸分隔符手拼）已删除。用 V1 串签名必须**不被接受**：V1 允许
	// 构造"不同 JSON、同一签名串"的歧义（2 跳 ≡ 1 跳且 Addr 里塞 ';h:'），
	// 而 Sign 从来只签 V2/V3，所以这个分支只会被升级前的旧 controller 命中
	// —— 那种 controller 本来就在发可碰撞的授权，宁可失败关闭。
	legacyV1 := mk("legacy-v1", "n3")
	legacyV1.Sig = hex.EncodeToString(ed25519.Sign(priv, legacyV1.payloadV2()))
	if !legacyV1.Verify(pub) {
		t.Fatal("V2 签名不再被接受（升级前签发的 grant 会失效）")
	}
}

// 回归：磁盘水位必须参与负载评分。之前 LoadPct 只算 CPU/内存均值，
// 磁盘快满的节点照样被选成中继与目的端，写满后传输失败。
func TestLoadPctIncludesDisk(t *testing.T) {
	// 健康节点：CPU 10 / 内存 20 / 磁盘余量充足 → 仍是 15
	ok := Heartbeat{CPUPct: 10, MemPct: 20, DiskFreeBytes: 100 << 30}
	if got := ok.LoadPct(); got != 15 {
		t.Fatalf("健康节点负载应为 15，实际 %.1f", got)
	}
	// 磁盘只剩 200MB：水位应接近 90，压过 CPU/内存
	tight := Heartbeat{CPUPct: 10, MemPct: 20, DiskFreeBytes: 200 << 20}
	if got := tight.LoadPct(); got < 85 {
		t.Fatalf("磁盘余量 200MB 时负载应接近 90，实际 %.1f（回归：磁盘未参与）", got)
	}
	// 磁盘满：应到 100，超过 MaxLoadPct=80 → 不会被选为中继
	full := Heartbeat{DiskFreeBytes: 1}
	if got := full.LoadPct(); got < 99 {
		t.Fatalf("磁盘将满时负载应约 100，实际 %.1f", got)
	}
	// 未上报磁盘（旧 agent）时退回 CPU/内存均值，不能因此把节点判死
	legacy := Heartbeat{CPUPct: 10, MemPct: 20}
	if got := legacy.LoadPct(); got != 15 {
		t.Fatalf("未上报磁盘时应退回 CPU/内存均值，实际 %.1f", got)
	}
}

// 回归：V2 的签名串不含 Hop.TCPPort / SourceSpec.TCPPort / RateLimit，
// 而 agent 真的用 g.Hops[1].TCPPort 拨号、RateLimit 决定整任务配额。
// 于是"持 grant 的中继"可以带着合法签名把某一跳改指同主机另一个端口，
// 或把限速清零。V3 必须让这两类改写都失败。
func TestGrantSignatureCoversDialAndLimitFields(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	mk := func() *TransferGrant {
		g := &TransferGrant{
			ID: "xfer-1", Src: "a", Dst: "b", Mode: "send",
			FileSize:  1 << 20,
			ChunkSize: 4 << 20,
			Streams:   2,
			RateLimit: 1 << 20,
			ExpiresAt: time.Now().Add(time.Hour).UTC(),
			Hops:      []Hop{{NodeID: "a"}, {NodeID: "b", Addr: "10.0.0.9:7800", TCPPort: 7801}},
			Sources:   []SourceSpec{{NodeID: "c", Addr: "10.0.0.9:7900", Path: "/x", Start: 0, End: 1, TCPPort: 7901}},
		}
		g.Sign(priv)
		return g
	}

	g := mk()
	if !g.Verify(pub) {
		t.Fatal("未篡改的 grant 验签失败")
	}

	tamper := func(name string, f func(*TransferGrant)) {
		t.Helper()
		x := mk()
		f(x)
		if x.Verify(pub) {
			t.Fatalf("%s 被改写后仍验签通过：该字段没进签名", name)
		}
	}
	tamper("Hop.TCPPort（改指同主机另一端口）", func(g *TransferGrant) {
		g.Hops[1].TCPPort = 22
	})
	tamper("SourceSpec.TCPPort", func(g *TransferGrant) {
		g.Sources[0].TCPPort = 22
	})
	tamper("RateLimit（清零绕过限速）", func(g *TransferGrant) {
		g.RateLimit = 0
	})
	tamper("DstPath", func(g *TransferGrant) { g.DstPath = "/etc/passwd" })
	tamper("ExpiresAt（续命）", func(g *TransferGrant) {
		g.ExpiresAt = g.ExpiresAt.Add(24 * time.Hour)
	})

	// Proto 仍然刻意不进签名：混流会按流改写拨号协议，它只是路由提示。
	x := mk()
	x.Hops[1].Proto = "tcp"
	if !x.Verify(pub) {
		t.Fatal("Proto 本不该进签名（混流会按流改写）")
	}
}
