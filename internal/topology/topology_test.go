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
	cur = cur.Add(2 * time.Minute) // 两人都超时
	g.Apply(hb("a", 10, api.EdgeReport{To: "b", RTTms: 5})) // 只有 a 续了心跳
	if p := g.Path("a", "b"); p != nil {
		t.Fatalf("离线节点应从图中消失，得到 %v", p)
	}
}
