package main

import (
	"crypto/subtle"
	"encoding/json"
	"fileferry/internal/api"
	"fileferry/internal/ca"
	"fileferry/internal/topology"
	"fmt"
	"log"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"time"
)

func (c *controller) handlePullCert(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, ca.RoleAdmin) {
		c.event("forbidden", clientRole(r), "pullcert")
		return
	}
	if !c.limiter.allow("pullcert:"+string(clientRole(r)), 20) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
		return
	}
	// CN 带随机后缀：一张证书只用于一次拉取，避免"临时端点"变成长期身份
	id := api.NodeID(fmt.Sprintf("ffctl-%x", time.Now().UnixNano()&0xffffff))
	certPEM, keyPEM, _, err := c.ca.Issue(string(id), true, ca.RoleNode, "127.0.0.1", "localhost")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(api.PullEndpoint{
		NodeID:     id,
		CertPEM:    string(certPEM),
		KeyPEM:     string(keyPEM),
		SignPubPEM: signPubPEM(c.signPub),
		ExpiresAt:  time.Now().Add(grantTTL).Unix(),
	})
}

// handlePull：签发"远端节点 → ffctl 端点"的授权。仅 admin。
// 数据面由源节点主动连 ffctl，不经过 controller。
func (c *controller) handlePull(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, ca.RoleAdmin) {
		c.event("forbidden", clientRole(r), "pull")
		return
	}
	var req api.PullRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.NodeID == "" || req.Src == "" || req.SrcPath == "" || req.DstPath == "" ||
		req.ListenAddr == "" || req.ListenPort <= 0 {
		http.Error(w, "node_id/src/src_path/dst_path/listen_addr/listen_port required", http.StatusBadRequest)
		return
	}
	if req.Src == req.NodeID {
		http.Error(w, "source cannot be the transfer endpoint", http.StatusBadRequest)
		return
	}
	if !c.limiter.allow("pull:"+string(req.Src), 50) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
		return
	}
	if c.graph.Addr(req.Src) == "" {
		http.Error(w, "source node offline", http.StatusUnprocessableEntity)
		return
	}
	c.mu.Lock()
	srcRevoked := c.revoked[req.Src]
	c.mu.Unlock()
	if srcRevoked {
		http.Error(w, "source revoked", http.StatusForbidden)
		return
	}

	// 目标路径写成目录时补源文件名（与 put 一致）
	dstPath := normalizeDstPath(req.DstPath, req.SrcPath)

	// 若源节点索引里能查到该文件的摘要，就把内容钉进授权，
	// 让接收端能校验"拿到的就是那个文件"而不只是"签名者合法"。
	var fileSHA string
	var fileSize int64
	c.mu.Lock()
	if req.PinHash {
		for _, e := range c.indexCache[req.Src] {
			if e.Path == req.SrcPath {
				fileSHA, fileSize = e.SHA256, e.Size
				break
			}
		}
	}
	streams := req.Streams
	if streams <= 0 {
		streams = 4
	}
	if streams > 8 {
		streams = 8
	}
	c.nextID++
	c.mu.Unlock()

	g := api.TransferGrant{
		ID:   fmt.Sprintf("pull-%d", time.Now().UnixNano()%1e12),
		Src:  req.Src,
		Dst:  req.NodeID,
		Mode: "pull",
		Hops: []api.Hop{
			{NodeID: req.Src},
			{
				NodeID:  req.NodeID,
				Addr:    req.ListenAddr,
				Proto:   "tcp", // ffctl 只监听 TCP
				TCPPort: req.ListenPort,
			},
		},
		SrcPath:    req.SrcPath,
		DstPath:    dstPath,
		ChunkSize:  grantChunkSize,
		Streams:    streams,
		FileSHA256: fileSHA,
		FileSize:   fileSize,
		ExpiresAt:  time.Now().Add(grantTTL),
	}
	g.Sign(c.signer)
	c.jobPersist(&g)
	c.jobUpdate(g.ID, "sent")

	// 交给源节点执行（它下一轮心跳就会拿到）
	c.mu.Lock()
	c.pending[req.Src] = append(c.pending[req.Src], g)
	c.mu.Unlock()
	c.notifyPending(req.Src)

	c.event("pull", req.Src, fmt.Sprintf("%s -> %s:%s", req.SrcPath, req.NodeID, dstPath))
	json.NewEncoder(w).Encode(g)
}

// recordProtoBW 用一次实测更新"边 + 协议"的吞吐（EMA 平滑）。
func (c *controller) recordProtoBW(from, to api.NodeID, proto string, mbps float64) {
	if proto == "" || mbps <= 0 {
		return
	}
	key := [2]api.NodeID{from, to}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.protoBW == nil { // 防御：写 nil map 会 panic
		c.protoBW = map[[2]api.NodeID]map[string]float64{}
	}
	m, ok := c.protoBW[key]
	if !ok {
		m = map[string]float64{}
		c.protoBW[key] = m
	}
	if prev, exists := m[proto]; exists && prev > 0 {
		mbps = prev*0.6 + mbps*0.4
	}
	m[proto] = mbps
}

// bestProto 返回该边**实测最好**的协议（没数据时返回 fallback）。
//
// 这是"从经验里学"：第一条传输仍按探测结果走；一旦某条边被证明某种
// 协议快得多（典型：丢包链路上 tcp 比 quic 快 60 倍），后续就走它。
func (c *controller) bestProto(from, to api.NodeID, fallback string) string {
	c.mu.Lock()
	m := c.protoBW[[2]api.NodeID{from, to}]
	best, bestV := fallback, 0.0
	for p, v := range m {
		if v > bestV {
			best, bestV = p, v
		}
	}
	c.mu.Unlock()
	return best
}

// pushProto 给出优先拨号协议：有探测边就用探测结果，否则默认 quic。
func (c *controller) handlePush(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, ca.RoleAdmin) {
		c.event("forbidden", clientRole(r), "push")
		return
	}
	var req api.PushRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.Dst == "" || req.DstPath == "" {
		http.Error(w, "dst/dst_path required", http.StatusBadRequest)
		return
	}
	if req.SHA256 == "" || req.Size < 0 {
		http.Error(w, "sha256/size required", http.StatusBadRequest)
		return
	}
	// 限速按**调用者**而非目标节点：脚本里批量 put（for f in *.txt）
	// 对同一目标连发几十次是正常用法，scp 也没有任何限制。之前按
	// 目标限 5/秒，实测第 6 个文件就 429，直接把批量场景打死。
	// 这里留足余量，只为挡住失控循环。
	if !c.limiter.allow("push:"+clientRole(r)+":"+string(r.TLS.PeerCertificates[0].Subject.CommonName), 50) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
		return
	}
	// 目标必须在线，否则给了授权也拨不通
	addr := c.graph.Addr(req.Dst)
	if addr == "" {
		http.Error(w, "destination node offline", http.StatusUnprocessableEntity)
		return
	}
	c.mu.Lock()
	dstRevoked := c.revoked[req.Dst]
	c.mu.Unlock()
	if dstRevoked {
		http.Error(w, "destination revoked", http.StatusForbidden)
		return
	}
	caller := api.NodeID(r.TLS.PeerCertificates[0].Subject.CommonName)
	streams := req.Streams
	if streams <= 0 {
		streams = 4
	}
	if streams > 8 {
		streams = 8
	}

	// 注意：pushProto 内部会取 c.mu，必须在**进入锁区之前**求值。
	// 否则同一 goroutine 二次加锁 → 自死锁（实测表现：controller 卡死，
	// 所有心跳超时，整个集群失联）。
	proto := pushProto(c, req.Dst)

	c.mu.Lock()
	c.nextID++
	g := api.TransferGrant{
		ID:   fmt.Sprintf("push-%d", c.nextID),
		Src:  caller,
		Dst:  req.Dst,
		Mode: "push",
		Hops: []api.Hop{
			{NodeID: caller}, // 本机不是舰队节点，仅占位（签名覆盖）
			{
				NodeID: req.Dst,
				Addr:   addr,
				// Proto 只给"优先尝试"的提示（不进签名，见 api.payloadV2），
				// 客户端失败时会自动换另一种协议。之前这里硬编码 "tcp"，
				// 等于本机直推永远用不上 QUIC。
				Proto:   proto,
				TCPPort: c.graph.TCPPort(req.Dst),
			},
		},
		SrcPath:    req.LocalPath, // 只用于目标写成目录时补文件名
		DstPath:    normalizeDstPath(req.DstPath, req.LocalPath),
		ChunkSize:  4 << 20,
		Streams:    streams,
		RateLimit:  req.RateLimit,
		FileSHA256: req.SHA256,
		FileSize:   req.Size,
		ExpiresAt:  time.Now().Add(grantTTL),
	}
	g.Sign(c.signer)
	c.mu.Unlock()
	c.jobPersist(&g) // 落库：ffctl 可用 `ffctl jobs push-...` 查历史

	c.mu.Lock()
	c.jobUpdate(g.ID, "sent")
	c.mu.Unlock()

	c.event("push", caller, fmt.Sprintf("%s -> %s:%s", caller, g.Dst, g.DstPath))
	json.NewEncoder(w).Encode(g)
}

// normalizeDstPath 把"目标写成目录"补成具体文件名。
// README 与历史用法都是 `ffctl send node-1:/data/big.iso node-2:/data/`，
// 而接收端直接 os.Rename(tmp, DstPath)，目录目标必然报
// "rename ...: file exists"（实测 16 MiB 全传完后失败并重试 3 轮）。
// controller 看不到对端文件系统，只能按末尾分隔符判断；
// 接收端另有"已存在且是目录"的兜底。
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// handleRenew：节点证书临期续期。身份由现有 mTLS 证书证明，
// 新证书沿用同一 nodeID 与 node 角色。
func (c *controller) handleRenew(w http.ResponseWriter, r *http.Request) {
	if len(r.TLS.PeerCertificates) == 0 {
		http.Error(w, "client cert required", http.StatusUnauthorized)
		return
	}
	cert := r.TLS.PeerCertificates[0]
	role := ""
	if ous := cert.Subject.OrganizationalUnit; len(ous) > 0 {
		role = ous[0]
	}
	if role != ca.RoleNode {
		http.Error(w, "node role only", http.StatusForbidden)
		return
	}
	nodeID := cert.Subject.CommonName
	c.mu.Lock()
	revoked := c.revoked[api.NodeID(nodeID)]
	c.mu.Unlock()
	if revoked {
		http.Error(w, "revoked", http.StatusForbidden)
		return
	}
	if !c.limiter.allow("renew:"+nodeID, 1) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
		return
	}
	// SAN 沿用该节点最近心跳上报的地址与主机名
	sans := []string{nodeID}
	for _, hb := range c.graph.Snapshot() {
		if hb.NodeID == api.NodeID(nodeID) {
			sans = append(sans, hb.Hostname)
			if host, _, err := net.SplitHostPort(hb.Addr); err == nil && net.ParseIP(host) != nil {
				sans = append(sans, host)
			}
			break
		}
	}
	certPEM, keyPEM, _, err := c.ca.Issue(nodeID, true, ca.RoleNode, sans...)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	c.event("renew", nodeID, "")
	json.NewEncoder(w).Encode(api.RenewResponse{NodeID: nodeID, CertPEM: string(certPEM), KeyPEM: string(keyPEM)})
}

// handleShare：仅 admin。生成临时取件码：{src, path, ttl_min}。
// 台账只存哈希；过期/用尽自动作废。
func (c *controller) handleShare(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, ca.RoleAdmin) {
		return
	}
	var req struct {
		Src    api.NodeID `json:"src"`
		Path   string     `json:"path"`
		TTLMin int        `json:"ttl_min"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil || req.Src == "" || req.Path == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.TTLMin <= 0 || req.TTLMin > 24*60 {
		req.TTLMin = 10
	}
	tok, err := ca.NewEnrollToken() // 复用随机码生成器（前缀 ff_enroll_，做分享够用）
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	code := "ff_get_" + tok[len("ff_enroll_"):]
	c.mu.Lock()
	now := time.Now()
	for k, v := range c.shares { // 过期清扫：没人访问的码之前会永久驻留
		if now.After(v.Exp) {
			delete(c.shares, k)
		}
	}
	c.shares[api.TokenHash(code)] = &shareEntry{Src: req.Src, Path: req.Path, Exp: now.Add(time.Duration(req.TTLMin) * time.Minute), Uses: 3}
	c.mu.Unlock()
	c.event("share", string(req.Src), req.Path)
	json.NewEncoder(w).Encode(map[string]any{"code": code, "expires_in_min": req.TTLMin, "max_uses": 3})
}

// handleGet：node 角色。凭码取文件：生成"存件节点 → 请求节点"的
// 定向 grant，落盘限定请求节点收件目录。
func (c *controller) handleGet(w http.ResponseWriter, r *http.Request) {
	if len(r.TLS.PeerCertificates) == 0 {
		http.Error(w, "client cert required", http.StatusUnauthorized)
		return
	}
	dst := api.NodeID(r.TLS.PeerCertificates[0].Subject.CommonName)
	var req struct {
		Code string `json:"code"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil || req.Code == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !c.limiter.allow("get:"+string(dst), 3) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
		return
	}
	c.mu.Lock()
	se, ok := c.shares[api.TokenHash(req.Code)]
	if !ok || time.Now().After(se.Exp) {
		delete(c.shares, api.TokenHash(req.Code))
		c.mu.Unlock()
		http.Error(w, "invalid or expired code", http.StatusUnauthorized)
		return
	}
	c.mu.Unlock()
	// 身份校验必须在扣次数之前：之前 se.Uses-- 在自取检查之前，
	// 源端误用自己的码会白烧一次（一共只有 3 次）。
	if dst == se.Src {
		http.Error(w, "source cannot fetch itself", http.StatusBadRequest)
		return
	}
	c.mu.Lock()
	se.Uses--
	if se.Uses <= 0 {
		delete(c.shares, api.TokenHash(req.Code))
	}
	c.mu.Unlock()
	// 组 grant：源=存件节点，目的=取件节点。
	// 路径方向必须与数据流一致（se.Src → dst）。之前写成
	// Path(dst, se.Src)，把 hop 顺序整个倒置：源端按 Hops[1] 拨号时
	// 拨的是**自己**的地址，连回自己后被中继逻辑判成"不在路径上"，
	// 于是 ff get 永远失败（一直被误认为密钥问题）。
	path := c.graph.Path(se.Src, dst)
	if path == nil || len(path) < 2 {
		http.Error(w, "no reachable path", http.StatusUnprocessableEntity)
		return
	}
	hops := make([]api.Hop, 0, len(path))
	for i, id := range path {
		hop := api.Hop{NodeID: id, TCPPort: c.graph.TCPPort(id)}
		if i > 0 {
			proto, addr, _ := c.graph.EdgeDetail(path[i-1], id)
			hop.Addr, hop.Proto = addr, proto
			if hop.Addr == "" {
				hop.Addr = c.graph.Addr(id)
			}
			if hop.Proto == "" {
				hop.Proto = "quic"
			}
		}
		hops = append(hops, hop)
	}
	name := filepath.Base(se.Path)
	c.mu.Lock()
	c.nextID++
	id := c.nextID
	c.mu.Unlock()
	grant := api.TransferGrant{
		ID:        fmt.Sprintf("get-%d", id),
		Src:       se.Src,
		Dst:       dst,
		Hops:      hops,
		SrcPath:   se.Path,
		DstPath:   filepath.Join(shareInbox(dst), name),
		ChunkSize: grantChunkSize,
		Streams:   2,
		Enc:       true,
		ExpiresAt: time.Now().Add(grantTTL),
	}
	grant.Sign(c.signer)
	c.mu.Lock()
	c.pending[grant.Src] = append(c.pending[grant.Src], grant)
	c.notifyPending(grant.Src)
	c.mu.Unlock()
	c.jobPersist(&grant)
	c.event("get", string(dst), se.Path)
	json.NewEncoder(w).Encode(grant)
}

// shareInbox 取件落盘目录标记：agent 侧映射到其 data-dir/inbox。
func (c *controller) handleKeypassPost(w http.ResponseWriter, r *http.Request) {
	if len(r.TLS.PeerCertificates) == 0 {
		http.Error(w, "client cert required", http.StatusUnauthorized)
		return
	}
	cn := api.NodeID(r.TLS.PeerCertificates[0].Subject.CommonName)
	var req struct {
		GrantID string `json:"grant_id"`
		KeyB64  string `json:"key_b64"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil || req.GrantID == "" || req.KeyB64 == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if dst := c.lookupGrantDst(req.GrantID); dst == "" || dst != cn {
		// 仅任务的目的端上报的密钥才对——此处是源端上报：应校验 CN==Src
		if gsrc := c.lookupGrantSrc(req.GrantID); gsrc == "" || gsrc != cn {
			http.Error(w, "not a participant", http.StatusForbidden)
			return
		}
	}
	if !c.limiter.allow("kp:"+string(cn), 20) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
		return
	}
	c.mu.Lock()
	now := time.Now()
	for k, v := range c.keypass { // 过期清扫：陈旧密钥材料不驻留
		if now.Sub(v.at) > 2*time.Hour {
			delete(c.keypass, k)
		}
	}
	c.keypass[req.GrantID] = keyEntry{key: req.KeyB64, at: now}
	c.mu.Unlock()
	w.WriteHeader(http.StatusOK)
}

// handleKeypassGet：目的端取密钥（校验 CN==Dst，一次性发放）。
func (c *controller) handleKeypassGet(w http.ResponseWriter, r *http.Request) {
	if len(r.TLS.PeerCertificates) == 0 {
		http.Error(w, "client cert required", http.StatusUnauthorized)
		return
	}
	cn := api.NodeID(r.TLS.PeerCertificates[0].Subject.CommonName)
	id := r.URL.Query().Get("id")
	if dst := c.lookupGrantDst(id); dst == "" || dst != cn {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	c.mu.Lock()
	e, ok := c.keypass[id]
	delete(c.keypass, id) // 一次性
	c.mu.Unlock()
	k := e.key
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"key_b64": k})
}

// handleRevoke：仅 admin。软吊销一个节点：从拓扑/队列/索引中即刻
// 剔除，拒绝其后续心跳与续期；已签发的旧 grant 在 30 分钟内自然
// 过期。节点证书作废靠"无处可用"实现（无需 CRL 分发）。
func (c *controller) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, ca.RoleAdmin) {
		return
	}
	var req struct {
		Node api.NodeID `json:"node"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Node == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	c.mu.Lock()
	c.revoked[req.Node] = true
	delete(c.pending, req.Node)
	delete(c.pendingPunch, req.Node)
	delete(c.publics, req.Node)
	delete(c.indexCache, req.Node)
	for sha, m := range c.replicas {
		delete(m, req.Node)
		if len(m) == 0 {
			delete(c.replicas, sha)
		}
	}
	c.mu.Unlock()
	c.graph.Remove(req.Node)
	c.db.Exec(`INSERT OR REPLACE INTO revoked(node,ts) VALUES(?,?)`, req.Node, time.Now().Unix())
	c.event("revoke", string(req.Node), "")
	w.WriteHeader(http.StatusOK)
}

// handleIndex：node 角色上报共享目录索引（全量替换该节点条目）。
// 副本索引是 M8 多源并行的数据源：同一 sha256 出现在多台 → 可多源。
func (c *controller) handleIndex(w http.ResponseWriter, r *http.Request) {
	if len(r.TLS.PeerCertificates) == 0 {
		http.Error(w, "client cert required", http.StatusUnauthorized)
		return
	}
	cn := r.TLS.PeerCertificates[0].Subject.CommonName
	if !c.limiter.allow("index:"+cn, 1) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
		return
	}
	var rep api.IndexReport
	if err := json.NewDecoder(r.Body).Decode(&rep); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if rep.NodeID != api.NodeID(cn) {
		http.Error(w, "node_id does not match certificate", http.StatusForbidden)
		return
	}
	c.db.Exec(`DELETE FROM replicas WHERE node=?`, rep.NodeID)
	for _, e := range rep.Entries {
		if e.SHA256 != "" {
			c.db.Exec(`INSERT OR REPLACE INTO replicas(sha,node,path,size,mtime) VALUES(?,?,?,?,?)`,
				e.SHA256, rep.NodeID, e.Path, e.Size, e.Mtime)
		}
	}
	c.mu.Lock()
	c.indexCache[rep.NodeID] = rep.Entries
	// 全量替换：先移除该节点旧条目，再插入新条目
	for sha, m := range c.replicas {
		delete(m, rep.NodeID)
		if len(m) == 0 {
			delete(c.replicas, sha)
		}
	}
	for _, e := range rep.Entries {
		if e.SHA256 == "" {
			continue
		}
		if c.replicas[e.SHA256] == nil {
			c.replicas[e.SHA256] = map[api.NodeID]string{}
		}
		c.replicas[e.SHA256][rep.NodeID] = e.Path
	}
	c.mu.Unlock()
	w.WriteHeader(http.StatusOK)
}

// lookupReplicas 返回持有该哈希的其他在线节点（node -> path）。
func (c *controller) handleJobs(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, ca.RoleAdmin) {
		return
	}
	id := r.URL.Query().Get("id")
	rows, err := c.db.Query(`SELECT id,src,dst,mode,status,updated FROM jobs WHERE (?1='' OR id=?1) ORDER BY updated DESC LIMIT 100`, id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	type jobRow struct {
		ID      string `json:"id"`
		Src     string `json:"src"`
		Dst     string `json:"dst"`
		Mode    string `json:"mode,omitempty"`
		Status  string `json:"status"`
		Updated int64  `json:"updated"`
	}
	var out []jobRow
	for rows.Next() {
		var j jobRow
		if rows.Scan(&j.ID, &j.Src, &j.Dst, &j.Mode, &j.Status, &j.Updated) == nil {
			out = append(out, j)
		}
	}
	if out == nil {
		out = []jobRow{}
	}
	json.NewEncoder(w).Encode(out)
}

func clientRole(r *http.Request) string {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return ""
	}
	ous := r.TLS.PeerCertificates[0].Subject.OrganizationalUnit
	if len(ous) == 0 {
		return ""
	}
	return ous[0]
}

func requireRole(w http.ResponseWriter, r *http.Request, role string) bool {
	if clientRole(r) != role {
		http.Error(w, fmt.Sprintf("requires %s role", role), http.StatusForbidden)
		return false
	}
	return true
}

func (c *controller) handleEnroll(w http.ResponseWriter, r *http.Request) {
	if !c.limiter.allow("enroll:"+clientIP(r), 2) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
		return
	}
	var req api.EnrollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	c.mu.Lock()
	valid := false
	// 常量时间比较：逐个比对时用 subtle，避免按字节提前返回泄漏前缀
	// 信息（时间侧信道）。
	for _, t := range c.cfg.EnrollTokens {
		if _, burned := c.ledger.Burned[api.TokenHash(t)]; !burned &&
			subtle.ConstantTimeCompare([]byte(t), []byte(req.Token)) == 1 {
			valid = true
			break
		}
	}
	if !valid {
		c.mu.Unlock()
		http.Error(w, "invalid or used token", http.StatusUnauthorized)
		return
	}
	// 编号策略：优先使用 agent 请求的稳定名字，拿不到才退回自增编号。
	// 之前只按入网顺序编号，两台机器并行启动谁先谁后不确定——实测后
	// 启动的 agent 拿到了 node-1，任何写死 node-1/node-2 的脚本在重装
	// 后全部错位。
	nodeID := ""
	if n, nerr := NormalizeNodeName(req.NodeName); nerr == nil {
		if got, ok := c.ledger.claimName(n); ok {
			nodeID = got
		}
	}
	if nodeID == "" {
		nodeID = c.ledger.nextAutoNodeID()
		c.ledger.claim(nodeID)
	}
	c.ledger.Burned[api.TokenHash(req.Token)] = nodeID
	c.ledger.save(c.cfg.DataDir)
	c.mu.Unlock()
	// 证书 SAN：enrollment 报上来的数据面 IP + 主机名
	sans := []string{req.Hostname}
	if host, _, err := net.SplitHostPort(req.Addr); err == nil && net.ParseIP(host) != nil {
		sans = append(sans, host)
	}
	certPEM, keyPEM, _, err := c.ca.Issue(nodeID, true, ca.RoleNode, sans...)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	c.event("enroll", nodeID, r.RemoteAddr)
	json.NewEncoder(w).Encode(api.EnrollResponse{
		NodeID:     nodeID,
		CertPEM:    string(certPEM),
		KeyPEM:     string(keyPEM),
		RootPEM:    string(c.ca.RootPEM()),
		SignPubPEM: signPubPEM(c.signPub),
	})
}

// handleHeartbeat：要求 node 证书；节点身份以证书 CN 为准，不可谎报。
// 响应携带该节点的待执行任务与全网在线节点表。
func (c *controller) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	if len(r.TLS.PeerCertificates) == 0 {
		http.Error(w, "client cert required", http.StatusUnauthorized)
		return
	}
	if !c.limiter.allow("hb:"+r.TLS.PeerCertificates[0].Subject.CommonName, 10) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
		return
	}
	var hb api.Heartbeat
	if err := json.NewDecoder(r.Body).Decode(&hb); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if cn := r.TLS.PeerCertificates[0].Subject.CommonName; cn != hb.NodeID {
		http.Error(w, "node_id does not match certificate", http.StatusForbidden)
		return
	}
	c.mu.Lock()
	revoked := c.revoked[hb.NodeID]
	c.mu.Unlock()
	if revoked {
		http.Error(w, "revoked", http.StatusForbidden)
		return
	}
	// 公网映射以 controller 回声口的观测为准，agent 上报值仅作参考
	c.mu.Lock()
	if pe, ok := c.publics[hb.NodeID]; ok && time.Since(pe.seen) < 90*time.Second {
		hb.Public = pe.addr
	}
	c.mu.Unlock()
	c.graph.Apply(hb)
	// 长轮询：没有待办任务时先挂住，一有任务立刻返回。
	// 没有这一步，`ffctl send` 必须等下一次心跳（5s）才被投递——
	// 实测 200MB 传输的 6s 里有 5s 纯粹在等心跳。
	if hb.WaitMS > 0 {
		d := time.Duration(hb.WaitMS) * time.Millisecond
		if d > 15*time.Second {
			d = 15 * time.Second // 上限：必须小于 topology.HeartbeatTimeout(20s)
		}
		c.awaitPending(hb.NodeID, d)
	}
	c.mu.Lock()
	jobs := c.pending[hb.NodeID]
	delete(c.pending, hb.NodeID)
	c.mu.Unlock()
	fresh := jobs[:0]
	for _, j := range jobs {
		if time.Now().Before(j.ExpiresAt) {
			fresh = append(fresh, j)
		}
	}
	jobs = fresh
	directives := c.pickPunches(&hb)
	c.mu.Lock()
	// 另一端排队中的指令（对端发牌时给本端登记的）一并下发，
	// 保证打洞双方同时行动
	if queued := c.pendingPunch[hb.NodeID]; len(queued) > 0 {
		log.Printf("下发排队指令给 %s x%d", hb.NodeID, len(queued))
		directives = append(directives, queued...)
	}
	delete(c.pendingPunch, hb.NodeID)
	c.mu.Unlock()
	// 先序列化、再写：响应写失败（客户端断线 / NAT 超时 / 中间设备 RST）
	// 时必须把任务放回队列，否则它已经从 pending 摘除、又没送到，
	// 只能等到 controller 重启由 rehydrate 捞回——任务凭空消失。
	c.mu.Lock()
	var revokedIDs []api.NodeID
	for id, v := range c.revoked {
		if v {
			revokedIDs = append(revokedIDs, id)
		}
	}
	c.mu.Unlock()
	buf, merr := json.Marshal(api.HeartbeatResponse{
		Jobs:    jobs,
		Peers:   c.graph.Peers(),
		Punches: directives,
		Revoked: revokedIDs,
	})
	if merr != nil {
		c.requeueJobs(hb.NodeID, jobs)
		http.Error(w, "encode failed", http.StatusInternalServerError)
		return
	}
	if _, werr := w.Write(buf); werr != nil {
		c.requeueJobs(hb.NodeID, jobs)
		log.Printf("心跳响应写失败（%s）：%d 条任务已放回队列", hb.NodeID, len(jobs))
		return
	}
}

// notifyPending 唤醒正在长轮询该节点的心跳请求（有待办任务了）。
func (c *controller) handleTransfer(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, ca.RoleAdmin) {
		c.event("forbidden", clientRole(r), "transfer")
		return
	}
	var req api.TransferRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	path := c.graph.Path(req.Src, req.Dst)
	if (path == nil || len(path) < 2) && c.trySwitch(w, req) {
		return // 走交换台模式（响应已写）
	}
	if path == nil || len(path) < 2 {
		http.Error(w, "no reachable path", http.StatusUnprocessableEntity)
		return
	}
	// 组装完整逐跳路径：每跳的地址与协议取自**前驱节点探测该边成功
	// 的实际值**（打洞边=公网映射，直连边=广播地址；谁探测的谁去拨）
	hops := make([]api.Hop, 0, len(path))
	for i, id := range path {
		hop := api.Hop{NodeID: id, TCPPort: c.graph.TCPPort(id)}
		if i > 0 {
			if proto, addr, ok := c.graph.EdgeDetail(path[i-1], id); ok && addr != "" {
				hop.Addr = addr
				hop.Proto = proto
			} else {
				hop.Addr = c.graph.Addr(id)
				hop.Proto = "quic"
			}
			if hop.Addr == "" {
				http.Error(w, fmt.Sprintf("%s 无可用地址", id), http.StatusUnprocessableEntity)
				return
			}
		}
		hops = append(hops, hop)
	}
	c.mu.Lock()
	c.nextID++
	id := c.nextID
	c.mu.Unlock()
	grant := api.TransferGrant{
		ID:        fmt.Sprintf("xfer-%d", id),
		Src:       req.Src,
		Dst:       req.Dst,
		Hops:      hops,
		Relays:    path[1 : len(path)-1],
		SrcPath:   req.SrcPath,
		DstPath:   normalizeDstPath(req.DstPath, req.SrcPath),
		ChunkSize: grantChunkSize,
		Streams:   4, // TODO(M4)：按路径质量与负载动态定
		RateLimit: req.RateLimit,
		ExpiresAt: time.Now().Add(grantTTL),
		Enc:       c.cfg.EncDefault, // 端到端加密（真机密钥专递链路待修，默认关；单测已验证）
	}
	// 混流：直连路径两种协议都可用时，并行流分走 TCP+UDP 叠加配额
	if len(path) == 2 && c.graph.EdgeAlt(req.Src, req.Dst) != "" {
		grant.Mix = true
	}
	// M8 多源：索引里发现其他副本 → 按路径带宽把块区间分给各源。
	// 条件：候选到目的端有直连边（多源走直连，v1 不与中继/交换台复合）。
	// 并行度按文件大小自适应（索引有 size 时）；无索引用缺省 4
	if sz := c.indexedSize(req.Src, req.SrcPath); sz > 0 {
		switch {
		case sz >= 256<<20:
			grant.Streams = 6
		case sz >= 64<<20:
			grant.Streams = 4
		case sz >= 16<<20:
			grant.Streams = 3
		default:
			grant.Streams = 1
		}
	}
	c.applyMultiSource(&grant)
	grant.Sign(c.signer)
	targets := grant.AllSources()
	c.mu.Lock()
	for _, t := range targets {
		c.pending[t] = append(c.pending[t], grant) // 每个源各收一份，各取自己的区间
		c.notifyPending(t)
	}
	npend := len(c.pending[req.Src])
	c.mu.Unlock()
	log.Printf("[trace] 签发 %s：sources=%d streams=%d 投递=%v 源队列长度=%d",
		grant.ID, len(grant.Sources), grant.Streams, targets, npend)
	c.jobPersist(&grant)
	srcs := make([]string, 0, len(targets))
	for _, t := range targets {
		srcs = append(srcs, string(t))
	}
	c.event("transfer", req.Src, strings.Join(srcs, "+")+" -> "+req.Dst)
	json.NewEncoder(w).Encode(grant)
}

// indexedSize 查源文件大小（索引）。
func (c *controller) handleJobDone(w http.ResponseWriter, r *http.Request) {
	if len(r.TLS.PeerCertificates) == 0 {
		http.Error(w, "client cert required", http.StatusUnauthorized)
		return
	}
	var req api.DoneRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if cn := r.TLS.PeerCertificates[0].Subject.CommonName; cn != req.NodeID {
		http.Error(w, "node_id does not match certificate", http.StatusForbidden)
		return
	}
	// 必须是这个 grant 的参与方：之前任何已入网节点只要猜到 grant ID
	// （xfer-<Unix秒>，可枚举）就能把别人的任务标成 done/failed、
	// 污染 pathBW 调度权重、并触发 autoRetry 重试风暴。
	if parts := c.grantParticipants(req.GrantID); len(parts) > 0 && !parts[req.NodeID] {
		c.event("forbidden", string(req.NodeID), "jobdone "+req.GrantID)
		http.Error(w, "not a participant of this grant", http.StatusForbidden)
		return
	}
	if req.OK {
		log.Printf("任务 %s 完成（%s）", req.GrantID, req.NodeID)
		c.jobUpdate(req.GrantID, "done")
		if req.Bytes > 0 && req.Duration > 0 {
			if dst := c.lookupGrantDst(req.GrantID); dst != "" {
				mbps := float64(req.Bytes) / req.Duration / 1e6
				c.mu.Lock()
				key := [2]api.NodeID{req.NodeID, dst}
				// EMA 平滑：单次传输受缓存/调度影响抖动很大，直接覆盖会让
				// 选路在两个中继之间来回跳。
				if prev, ok := c.pathBW[key]; ok && prev > 0 {
					mbps = prev*0.7 + mbps*0.3
				}
				c.pathBW[key] = mbps
				c.mu.Unlock()
				// 按协议分开记：QUIC 与 TCP 在同一条边上可能差 60 倍
				c.recordProtoBW(req.NodeID, dst, req.Proto, mbps)
				// 同步给选链算法：在此之前 Path() 只看 rtt，实测吞吐完全
				// 没参与路由（只用于交换台/多源评分），"rtt 短但很慢"的
				// 边仍然会被优先选中。
				topology.SetEdgeBW(req.NodeID, dst, mbps)
			}
		}
	} else {
		log.Printf("任务 %s 失败（%s）：%s", req.GrantID, req.NodeID, req.Err)
		c.jobUpdate(req.GrantID, "failed")
		c.event("job-fail", string(req.NodeID), req.GrantID+": "+req.Err)
		c.autoRetry(req.GrantID) // 断点续传：失败自动重签发（网络恢复后从断点继续）
	}
	// TODO(M1)：结果落 SQLite
}

// handleStatus：仅 admin，返回全图快照。
func (c *controller) handleStatus(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, ca.RoleAdmin) {
		return
	}
	json.NewEncoder(w).Encode(c.graph.Snapshot())
}

// trySwitch 交换台模式：常规路径不存在时，选举一台"源和目的都
// 能出站够到"的最闲节点当交换台（DERP 式——两端各自出站拨入，
// 交换台把两条现成连接对接，NAT 不构成障碍）。grant 同时投递给
// 源和目的两端。
