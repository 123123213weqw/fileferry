// Package topology 维护有向可达性图与实时负载，用 Dijkstra 为每次
// 传输选出"可达 × 低负载"的最优链路。可达性是有方向的：NAT 内的
// 机器出得去、进不来，图上只存在它指出的边——链路只需每跳的起点
// 主动连得到该跳终点即可成立。
package topology

import (
	"container/heap"
	"sync"
	"time"

	"fileferry/internal/api"
)

// MaxLoadPct：水位超过它的节点只做端点，不做中继。
const MaxLoadPct = 80

// HeartbeatTimeout：超过此时长没有心跳的节点视为离线，从图中消失。
const HeartbeatTimeout = 20 * time.Second

type node struct {
	hb   api.Heartbeat
	seen time.Time
}

type Graph struct {
	mu    sync.RWMutex
	nodes map[api.NodeID]*node
	now   func() time.Time // 可注入，测试用
}

func New() *Graph {
	return &Graph{nodes: make(map[api.NodeID]*node), now: time.Now}
}

// Apply 汇入一次心跳。节点存活与否以**到达时间**为准，不用心跳里
// 自带的时间戳（防止谎报），超过 HeartbeatTimeout 未收到即离线。
func (g *Graph) Apply(h api.Heartbeat) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.nodes[h.NodeID] = &node{hb: h, seen: g.now()}
}

// NodeIDs 返回当前在线的节点。
func (g *Graph) NodeIDs() []api.NodeID {
	g.mu.RLock()
	defer g.mu.RUnlock()
	var ids []api.NodeID
	for id, n := range g.nodes {
		if g.now().Sub(n.seen) < HeartbeatTimeout {
			ids = append(ids, id)
		}
	}
	return ids
}

// Snapshot 返回全图心跳快照，供 ffctl status 展示。
func (g *Graph) Snapshot() []api.Heartbeat {
	g.mu.RLock()
	defer g.mu.RUnlock()
	var out []api.Heartbeat
	for _, n := range g.nodes {
		if g.now().Sub(n.seen) < HeartbeatTimeout {
			out = append(out, n.hb)
		}
	}
	return out
}

// Peers 返回在线节点的 id 与数据面地址，随心跳响应下发，供互相探测。
func (g *Graph) Peers() []api.PeerInfo {
	g.mu.RLock()
	defer g.mu.RUnlock()
	var out []api.PeerInfo
	for id, n := range g.nodes {
		if g.now().Sub(n.seen) < HeartbeatTimeout {
			out = append(out, api.PeerInfo{ID: id, Addr: n.hb.Addr})
		}
	}
	return out
}

// Addr 返回在线节点的数据面地址，离线返回空串。
func (g *Graph) Addr(id api.NodeID) string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	n, ok := g.nodes[id]
	if !ok || g.now().Sub(n.seen) >= HeartbeatTimeout {
		return ""
	}
	return n.hb.Addr
}

type edge struct {
	to    api.NodeID
	rttMs float64
	proto string
}

// edgesFrom 返回 from 最新心跳里报告的出边。
// TODO(M3)：与主动探测结果合并，心跳里只带增量。
func (g *Graph) edgesFrom(from api.NodeID) []edge {
	g.mu.RLock()
	defer g.mu.RUnlock()
	n, ok := g.nodes[from]
	if !ok || g.now().Sub(n.seen) >= HeartbeatTimeout {
		return nil
	}
	out := make([]edge, 0, len(n.hb.Edges))
	for _, e := range n.hb.Edges {
		// 目的端必须在线，否则这条边是陈旧的
		if d, ok := g.nodes[e.To]; ok && g.now().Sub(d.seen) < HeartbeatTimeout {
			out = append(out, edge{to: e.To, rttMs: e.RTTms, proto: e.Proto})
		}
	}
	return out
}

// loadPct 返回节点当前负载水位（0-100），离线返回 +Inf 使其被绕开。
func (g *Graph) loadPct(id api.NodeID) float64 {
	g.mu.RLock()
	defer g.mu.RUnlock()
	n, ok := g.nodes[id]
	if !ok || g.now().Sub(n.seen) >= HeartbeatTimeout {
		return +Inf
	}
	return n.hb.LoadPct()
}

// Path 为一次传输选链，返回从 src 到 dst 的完整节点序列（含两端，
// 不含中继时就是 [src, dst]）。边权 = rtt × (1 + 中继负载/100)；
// 负载超过 MaxLoadPct 的节点不会被选为中继。不可达返回 nil。
func (g *Graph) Path(src, dst api.NodeID) []api.NodeID {
	if src == dst {
		return []api.NodeID{src}
	}
	dist := map[api.NodeID]float64{src: 0}
	prev := map[api.NodeID]api.NodeID{}
	done := map[api.NodeID]bool{}
	pq := &nodePQ{{id: src}}
	for pq.Len() > 0 {
		u := heap.Pop(pq).(*pqItem)
		if done[u.id] {
			continue
		}
		done[u.id] = true
		if u.id == dst {
			break
		}
		for _, e := range g.edgesFrom(u.id) {
			// 中继节点负载超限则整条边不进图；端点(dst)不检查负载
			if e.to != dst && g.loadPct(e.to) > MaxLoadPct {
				continue
			}
			w := e.rttMs * (1 + g.loadPct(e.to)/100)
			if d, ok := dist[e.to]; !ok || u.d+w < d {
				dist[e.to] = u.d + w
				prev[e.to] = u.id
				heap.Push(pq, &pqItem{id: e.to, d: u.d + w})
			}
		}
	}
	if _, ok := dist[dst]; !ok {
		return nil
	}
	// 回溯得到完整链
	path := []api.NodeID{dst}
	for cur := dst; cur != src; {
		cur = prev[cur]
		path = append([]api.NodeID{cur}, path...)
	}
	return path
}

// —— 小顶堆，标准实现 ——

const Inf = 1e18

type pqItem struct {
	id api.NodeID
	d  float64
}

type nodePQ []*pqItem

func (q nodePQ) Len() int            { return len(q) }
func (q nodePQ) Less(i, j int) bool  { return q[i].d < q[j].d }
func (q nodePQ) Swap(i, j int)       { q[i], q[j] = q[j], q[i] }
func (q *nodePQ) Push(x any)         { *q = append(*q, x.(*pqItem)) }
func (q *nodePQ) Pop() any {
	old := *q
	n := len(old)
	it := old[n-1]
	*q = old[:n-1]
	return it
}
