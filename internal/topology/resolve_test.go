package topology

import (
	"testing"
	"time"

	"fileferry/internal/api"
)

// 造图：可控时钟，便于模拟心跳超时。
func mkGraph(now *time.Time) *Graph {
	g := New()
	g.now = func() time.Time { return *now }
	return g
}

func nodeHB(id, host, addr string) api.Heartbeat {
	return api.Heartbeat{NodeID: api.NodeID(id), Hostname: host, Addr: addr, TS: time.Now()}
}

// 名字解析是"省一轮往返"的关键：AI 只知道主机名/IP 时不必先查 status。
func TestResolveByNameHostIP(t *testing.T) {
	now := time.Now()
	g := mkGraph(&now)
	g.Apply(nodeHB("alpha", "web-01.example", "10.0.0.5:9443"))
	g.Apply(nodeHB("beta", "db-01.example", "10.0.0.9:9443"))

	cases := []struct {
		query string
		want  api.NodeID
	}{
		{"alpha", "alpha"},          // node_id 精确
		{"web-01.example", "alpha"}, // 主机名
		{"WEB-01.EXAMPLE", "alpha"}, // 大小写不敏感
		{"10.0.0.5", "alpha"},       // 纯 IP
		{"10.0.0.5:9443", "alpha"},  // IP:端口
		{"db-01.example", "beta"},   // 另一台
		{"10.0.0.9", "beta"},        // 另一台的 IP
	}
	for _, c := range cases {
		r := g.Resolve(c.query)
		if r.ID != c.want {
			t.Errorf("Resolve(%q) = %q，期望 %q", c.query, r.ID, c.want)
		}
		if !r.Online {
			t.Errorf("Resolve(%q) 应标记在线", c.query)
		}
	}
}

// 同名必须报歧义并给候选，不能随便挑一个：传错文件比报错更难排查。
func TestResolveAmbiguous(t *testing.T) {
	now := time.Now()
	g := mkGraph(&now)
	g.Apply(nodeHB("alpha", "same-host", "10.0.0.5:9443"))
	g.Apply(nodeHB("beta", "same-host", "10.0.0.5:9444"))

	for _, q := range []string{"same-host", "10.0.0.5"} {
		r := g.Resolve(q)
		if !r.Ambiguous {
			t.Fatalf("Resolve(%q) 应判为歧义，实际 ID=%q", q, r.ID)
		}
		if len(r.Candidates) != 2 {
			t.Fatalf("Resolve(%q) 应给 2 个候选，实际 %v", q, r.Candidates)
		}
		// 候选必须排序稳定，便于调用方复现
		if r.Candidates[0] != "alpha" || r.Candidates[1] != "beta" {
			t.Fatalf("候选应有序，实际 %v", r.Candidates)
		}
	}
}

// 离线节点不参与匹配。回归：停机后主机名曾被判成歧义（离线节点仍留在图里），
// 于是"唯一在线的那台"永远无法用主机名访问。
func TestResolveExcludesOffline(t *testing.T) {
	now := time.Now()
	g := mkGraph(&now)
	g.Apply(nodeHB("alpha", "same-host", "10.0.0.5:9443"))
	g.Apply(nodeHB("beta", "same-host", "10.0.0.5:9444"))

	// 让 beta 的心跳过期
	later := now.Add(HeartbeatTimeout + time.Second)
	g.now = func() time.Time { return later }
	// alpha 刚好刷新过，仍在超时窗口内
	g.Apply(nodeHB("alpha", "same-host", "10.0.0.5:9443"))
	g.now = func() time.Time { return later.Add(time.Second) }

	r := g.Resolve("same-host")
	if r.Ambiguous {
		t.Fatalf("离线节点不应参与匹配，实际仍报歧义 %v", r.Candidates)
	}
	if r.ID != "alpha" {
		t.Fatalf("应解析到仍在线的 alpha，实际 %q", r.ID)
	}
}

// 未知名返回空 ID（由调用方补候选列表），不能 panic。
func TestResolveUnknown(t *testing.T) {
	now := time.Now()
	g := mkGraph(&now)
	g.Apply(nodeHB("alpha", "h", "1.2.3.4:1"))
	for _, q := range []string{"", "  ", "nope", "9.9.9.9", "unknown:1234"} {
		r := g.Resolve(q)
		if r.ID != "" || r.Ambiguous {
			t.Errorf("Resolve(%q) 应返回空结果，实际 %+v", q, r)
		}
	}
	ids := g.OnlineIDs()
	if len(ids) != 1 || ids[0] != "alpha" {
		t.Fatalf("OnlineIDs 应为 [alpha]，实际 %v", ids)
	}
}

// Neighbors 用于把"为什么不连通"写进错误信息。
func TestNeighbors(t *testing.T) {
	now := time.Now()
	g := mkGraph(&now)
	g.Apply(nodeHB("alpha", "h", "1.2.3.4:1"))
	hbb := nodeHB("beta", "h2", "1.2.3.5:1")
	hbb.Edges = []api.EdgeReport{{To: "gamma"}, {To: "alpha"}, {To: "alpha"}}
	g.Apply(hbb)

	got := g.Neighbors("beta")
	if len(got) != 2 || got[0] != "alpha" || got[1] != "gamma" {
		t.Fatalf("Neighbors 应去重并排序为 [alpha gamma]，实际 %v", got)
	}
	if len(g.Neighbors("nosuch")) != 0 {
		t.Fatal("未知节点应返回空")
	}
}
