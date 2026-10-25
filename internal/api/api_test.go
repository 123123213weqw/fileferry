package api

import (
	"crypto/ed25519"
	"crypto/rand"
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
		Hops:      []Hop{{NodeID: "node-2"}, {NodeID: "node-4", Addr: "1.2.3.4:7800", Proto: "tcp"}},
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
