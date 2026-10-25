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
