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

	// V1 兼容：用旧 payload 签名，新代码必须仍能验过
	legacy := mk("legacy-1", "n2")
	legacy.Sig = hex.EncodeToString(ed25519.Sign(priv, legacy.payload()))
	if !legacy.Verify(pub) {
		t.Fatal("旧版 V1 签名不再被接受（滚动升级会中断）")
	}
	// 篡改必须被发现
	legacy.DstPath = "/etc/passwd"
	if legacy.Verify(pub) {
		t.Fatal("篡改后仍然验签通过")
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
