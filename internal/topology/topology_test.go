package topology

import (
	"testing"
	"time"

	"fileferry/internal/api"
)

func hb(id string, load float64, edges ...api.EdgeReport) api.Heartbeat {
	return api.Heartbeat{NodeID: id, CPUPct: load, MemPct: load, Edges: edges, TS: time.Now()}
}

func TestPathDirect(t *testing.T) {
	g := New()
	g.Apply(hb("a", 10, api.EdgeReport{To: "b", RTTms: 5}))
	g.Apply(hb("b", 10))
	if p := g.Path("a", "b"); len(p) != 2 || p[0] != "a" || p[1] != "b" {
		t.Fatalf("期望直连 [a b]，得到 %v", p)
	}
}

func TestPathRelayAvoidsOverloaded(t *testing.T) {
	g := New()
	// a 有两条到 c 的路：经 busy（rtt 1ms，负载 95%）或经 idle（rtt 5ms，负载 10%）
	g.Apply(hb("a", 10,
		api.EdgeReport{To: "busy", RTTms: 1},
		api.EdgeReport{To: "idle", RTTms: 5},
	))
	g.Apply(hb("busy", 95, api.EdgeReport{To: "c", RTTms: 1}))
	g.Apply(hb("idle", 10, api.EdgeReport{To: "c", RTTms: 5}))
	g.Apply(hb("c", 10))
	p := g.Path("a", "c")
	if len(p) != 3 || p[1] != "idle" {
		t.Fatalf("应绕开高负载中继经 idle，得到 %v", p)
	}
}

func TestPathRelayWhenNoDirect(t *testing.T) {
	g := New()
	// a、c 互不直连，只能经 bridge 跳板——自动串联的核心场景
	g.Apply(hb("a", 10, api.EdgeReport{To: "bridge", RTTms: 2}))
	g.Apply(hb("bridge", 30, api.EdgeReport{To: "c", RTTms: 3}))
	g.Apply(hb("c", 10))
	if p := g.Path("a", "c"); len(p) != 3 || p[1] != "bridge" {
		t.Fatalf("期望 [a bridge c]，得到 %v", p)
	}
}

func TestUnreachable(t *testing.T) {
	g := New()
	g.Apply(hb("a", 10))
	g.Apply(hb("b", 10))
	if p := g.Path("a", "b"); p != nil {
		t.Fatalf("应不可达，得到 %v", p)
	}
}

func TestStaleNodeExcluded(t *testing.T) {
	g := New()
	cur := time.Now()
	g.now = func() time.Time { return cur }
	g.Apply(hb("a", 10, api.EdgeReport{To: "b", RTTms: 5}))
	g.Apply(hb("b", 10))
	cur = cur.Add(2 * time.Minute)                          // 两人都超时
	g.Apply(hb("a", 10, api.EdgeReport{To: "b", RTTms: 5})) // 只有 a 续了心跳
	if p := g.Path("a", "b"); p != nil {
		t.Fatalf("离线节点应从图中消失，得到 %v", p)
	}
}

// 回归：实测吞吐必须参与选链。之前 Path() 只看 rtt×负载，pathBW 虽然
// 有回填但只用于交换台/多源评分，所以"rtt 短但实际很慢"的边仍然会被
// 优先选中。
func TestPathUsesMeasuredBandwidth(t *testing.T) {
	build := func() *Graph {
		g := New()
		now := time.Now()
		// src 经 fast 或 slow 到 dst，四条边 rtt 完全相同
		mk := func(id api.NodeID, edges []api.EdgeReport) api.Heartbeat {
			return api.Heartbeat{NodeID: id, Hostname: string(id), Addr: string(id) + ":1",
				Edges: edges, TS: now}
		}
		g.Apply(mk("src", []api.EdgeReport{
			{To: "fast", RTTms: 10, Proto: "quic"},
			{To: "slow", RTTms: 10, Proto: "quic"},
		}))
		g.Apply(mk("fast", []api.EdgeReport{{To: "dst", RTTms: 10, Proto: "quic"}}))
		g.Apply(mk("slow", []api.EdgeReport{{To: "dst", RTTms: 10, Proto: "quic"}}))
		g.Apply(mk("dst", nil))
		return g
	}
	g := build()

	relay := func(p []api.NodeID) string {
		if len(p) == 3 {
			return string(p[1])
		}
		return ""
	}

	// 没有实测值时两条等价：不该崩，且路径可用
	SetEdgeBW("src", "fast", 0)
	SetEdgeBW("src", "slow", 0)
	if p := g.Path("src", "dst"); len(p) < 2 {
		t.Fatalf("应能选出路径：%v", p)
	}

	// fast 实测 1MB/s、slow 200MB/s → 必须选 slow
	SetEdgeBW("src", "fast", 1)
	SetEdgeBW("src", "slow", 200)
	if got := relay(g.Path("src", "dst")); got == "fast" {
		t.Fatalf("实测慢的边仍被选中（回归：吞吐未参与选路）")
	}

	// 反转 → 必须选 fast
	SetEdgeBW("src", "fast", 200)
	SetEdgeBW("src", "slow", 1)
	if got := relay(g.Path("src", "dst")); got == "slow" {
		t.Fatalf("实测慢的边仍被选中")
	}

	SetEdgeBW("src", "fast", 0)
	SetEdgeBW("src", "slow", 0)
}
