// Package topology 维护有向可达性图与实时负载，用 Dijkstra 为每次
// 传输选出"可达 × 低负载"的最优链路。可达性是有方向的：NAT 内的
// 机器出得去、进不来，图上只存在它指出的边——链路只需每跳的起点
// 主动连得到该跳终点即可成立。
package topology

import (
	"container/heap"
	"net"
	"sort"
	"strings"
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

// Remove 即刻将节点从图中剔除（吊销用）。
func (g *Graph) Remove(id api.NodeID) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.nodes, id)
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
			out = append(out, api.PeerInfo{ID: id, Addr: n.hb.Addr, TCPPort: n.hb.TCPPort})
		}
	}
	return out
}

// Addr 返回在线节点的数据面地址，离线返回空串。
// TCPPort 返回该节点上报的 TCP 数据面端口（0 = 未上报）。
func (g *Graph) TCPPort(id api.NodeID) int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	n, ok := g.nodes[id]
	if !ok || g.now().Sub(n.seen) >= HeartbeatTimeout {
		return 0
	}
	return n.hb.TCPPort
}

func (g *Graph) Addr(id api.NodeID) string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	n, ok := g.nodes[id]
	if !ok || g.now().Sub(n.seen) >= HeartbeatTimeout {
		return ""
	}
	return n.hb.Addr
}

// bwMu/bw 保存实测边吞吐（MB/s），键为 (from,to)。
// 由 controller 在收到 jobdone 后回填。
var (
	bwMu sync.RWMutex
	bw   = map[[2]api.NodeID]float64{}
)

// SetEdgeBW 记录一条边的实测吞吐（MB/s，<=0 表示清除）。
func SetEdgeBW(from, to api.NodeID, mbps float64) {
	bwMu.Lock()
	defer bwMu.Unlock()
	if mbps <= 0 {
		delete(bw, [2]api.NodeID{from, to})
		return
	}
	bw[[2]api.NodeID{from, to}] = mbps
}

// edgeBW 返回实测吞吐（0 = 未知）。
func edgeBW(from, to api.NodeID) float64 {
	bwMu.RLock()
	defer bwMu.RUnlock()
	return bw[[2]api.NodeID{from, to}]
}

// LoadPct 返回节点当前负载水位（0-100），离线返回 200（评分归零）。
func (g *Graph) LoadPct(id api.NodeID) float64 { return g.loadPct(id) }

// EdgeAlt 返回该边的副协议（混流用），无则空。
func (g *Graph) EdgeAlt(from, to api.NodeID) string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	n, ok := g.nodes[from]
	if !ok || g.now().Sub(n.seen) >= HeartbeatTimeout {
		return ""
	}
	for _, e := range n.hb.Edges {
		if e.To == to {
			return e.AltProto
		}
	}
	return ""
}

// EdgeDetail 是 from→to 这条出边的细节：拨号协议与实际拨通地址
// （打洞成功的边是公网映射）。不存在或陈旧时 ok=false。
func (g *Graph) EdgeDetail(from, to api.NodeID) (proto, addr string, ok bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	n, found := g.nodes[from]
	if !found || g.now().Sub(n.seen) >= HeartbeatTimeout {
		return "", "", false
	}
	for _, e := range n.hb.Edges {
		if e.To == to {
			return e.Proto, e.Addr, true
		}
	}
	return "", "", false
}

// Public 返回节点上报过的公网 NAT 映射（M6 打洞用），无则空。
// TODO(M6)：由 controller 的 UDP 回声口维护，存入心跳之外的表。
func (g *Graph) Public(id api.NodeID) string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	n, ok := g.nodes[id]
	if !ok || g.now().Sub(n.seen) >= HeartbeatTimeout {
		return ""
	}
	return n.hb.Public
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
// 不含中继时就是 [src, dst]）。
//
// 边权 = rtt × (1 + 目标负载/100) / 实测吞吐权重。
// 第三项来自 SetEdgeBW 回填的实测吞吐（见 controller 的 jobdone），
// 让"rtt 很短但实际很慢"的边（例如同机房但限速、或高丢包链路）
// 不再被优先选中。没有实测值时该项为 1，退化为纯 rtt。
//
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
			// 实测吞吐修正：100MB/s 的边权重减半，10MB/s 的边权重翻倍。
			// 没有实测值时 bwW=1，退化为纯 rtt×负载。
			bwW := 1.0
			if m := edgeBW(u.id, e.to); m > 0 {
				bwW = 50.0 / (m + 50.0) * 1.5 // m=50 → 0.75；m→0 → 1.5
				if bwW < 0.3 {
					bwW = 0.3
				}
			}
			w *= bwW
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

func (q nodePQ) Len() int           { return len(q) }
func (q nodePQ) Less(i, j int) bool { return q[i].d < q[j].d }
func (q nodePQ) Swap(i, j int)      { q[i], q[j] = q[j], q[i] }
func (q *nodePQ) Push(x any)        { *q = append(*q, x.(*pqItem)) }
func (q *nodePQ) Pop() any {
	old := *q
	n := len(old)
	it := old[n-1]
	*q = old[:n-1]
	return it
}

// ResolveResult 是一次"宽松名称解析"的结果。
//
// 存在的理由（token 成本）：AI/脚本通常只知道主机名或 IP，不知道 node_id。
// 之前必须先调一次 status 查名字再发传输——多一轮往返，而每一轮都要把
// 整段对话重新输入一遍，这才是真正贵的地方（实测 status 输出仅 ~35 token，
// 但一次往返的上下文重放开销远大于此）。
//
// 所以在**服务端**做解析：任何客户端（CLI/MCP/curl）都能直接写主机名。
type ResolveResult struct {
	ID api.NodeID // 命中时非空
	// Ambiguous 为 true 表示有多个候选（多个节点同名/同 IP），
	// Candidates 里给出可选 node_id，调用方无需再查一次。
	Ambiguous  bool
	Candidates []api.NodeID
	// Online 表示命中的节点当前在线（心跳未超时）。
	Online bool
}

// Resolve 把用户写的名字解析成 node_id。依次尝试：
//
//  1. node_id 精确匹配（正常路径，零开销）
//  2. 主机名（大小写不敏感；agent 上报的 os.Hostname()）
//  3. 地址：addr 的主机部分（支持 "10.0.0.5"、"10.0.0.5:9443"）
//
// 多个节点同名时返回 Ambiguous + 候选列表（而不是随便挑一个）：
// 传错文件比报错更难排查。
func (g *Graph) Resolve(name string) ResolveResult {
	name = strings.TrimSpace(name)
	if name == "" {
		return ResolveResult{}
	}
	g.mu.RLock()
	defer g.mu.RUnlock()

	// 1) 精确 node_id
	if n, ok := g.nodes[api.NodeID(name)]; ok {
		return ResolveResult{ID: n.hb.NodeID, Online: g.now().Sub(n.seen) < HeartbeatTimeout}
	}

	// 3) 去掉可能的端口，便于按 IP 匹配
	hostPart := name
	if h, _, err := net.SplitHostPort(name); err == nil {
		hostPart = h
	}

	var byHost, byAddr []api.NodeID
	lower := strings.ToLower(name)
	now := g.now()
	for _, n := range g.nodes {
		// 只考虑在线节点：已下线的节点仍留在图里直到被清理，若参与匹配
		// 会把"唯一的那台在线机器"误报成歧义（实测停机后主机名仍报 409）。
		if now.Sub(n.seen) >= HeartbeatTimeout {
			continue
		}
		if n.hb.Hostname != "" && strings.ToLower(n.hb.Hostname) == lower {
			byHost = append(byHost, n.hb.NodeID)
			continue
		}
		if n.hb.Addr != "" {
			h, _, err := net.SplitHostPort(n.hb.Addr)
			if err != nil {
				h = n.hb.Addr
			}
			if h == hostPart {
				byAddr = append(byAddr, n.hb.NodeID)
			}
		}
	}

	// 主机名优先于地址：一台机器多个网卡时地址可能变，主机名是它自报的身份
	for _, set := range [][]api.NodeID{byHost, byAddr} {
		switch len(set) {
		case 1:
			n := g.nodes[set[0]]
			return ResolveResult{ID: set[0], Online: g.now().Sub(n.seen) < HeartbeatTimeout}
		case 0:
			continue
		default:
			sort.Slice(set, func(i, j int) bool { return set[i] < set[j] })
			return ResolveResult{Ambiguous: true, Candidates: set}
		}
	}
	return ResolveResult{}
}

// OnlineIDs 返回当前在线节点名（按字典序），用于错误信息里提示可选项。
//
// 错误信息自带候选很重要：AI 拿到 "节点不存在" 只能再跑一次 status，
// 而 "节点不存在；在线: alpha, beta" 可以直接改写参数重试，省一轮往返。
func (g *Graph) OnlineIDs() []api.NodeID {
	g.mu.RLock()
	defer g.mu.RUnlock()
	out := make([]api.NodeID, 0, len(g.nodes))
	for id, n := range g.nodes {
		if g.now().Sub(n.seen) < HeartbeatTimeout {
			out = append(out, id)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Neighbors 返回某节点当前所有"出边"对端（已排序）。
//
// 用于把"为什么不通"写进错误信息：只回一句 "no reachable path" 的话，
// 调用方（尤其 AI）只能再查一次拓扑去猜，白白多一轮往返。
func (g *Graph) Neighbors(id api.NodeID) []string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	n, ok := g.nodes[id]
	if !ok {
		return nil
	}
	out := make([]string, 0, len(n.hb.Edges))
	seen := map[string]bool{}
	for _, e := range n.hb.Edges {
		s := string(e.To)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
