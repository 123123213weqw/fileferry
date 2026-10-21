// ff-controller：控制面单实例。职责：CA 与一次性 enrollment、
// 心跳汇聚进拓扑图、为按需传输选链并签发授权（grant）、任务下发、
// 任务记录落 SQLite。权限模型：admin 角色（操作者本人）才能发起
// 传输与查看状态；node 角色只能心跳与执行。跑在一台能同时够到
// 内外网的机器上，且只有操作者可登录。
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
	_ "modernc.org/sqlite"

	"fileferry/internal/api"
	"fileferry/internal/ca"
	"fileferry/internal/nat"
	"fileferry/internal/topology"
)

type Config struct {
	Listen       string   `yaml:"listen"`
	DataDir      string   `yaml:"data-dir"`
	EnrollTokens []string `yaml:"enroll-tokens"`
}

type controller struct {
	cfg     Config
	ca      *ca.CA
	signer  ed25519.PrivateKey
	signPub ed25519.PublicKey
	graph   *topology.Graph
	db      *sql.DB

	mu           sync.Mutex
	pending      map[api.NodeID][]api.TransferGrant // 源节点待执行任务
	nextID       int64

	publics      map[api.NodeID]pubEntry // 节点公网 NAT 映射（UDP 回声口观测）
	punchTried   map[[2]api.NodeID]time.Time
	pendingPunch map[api.NodeID][]api.PunchDirective // 待下发给另一端的打洞指令
	ledger       *enrollLedger                        // 持久化核销台账
}

type pubEntry struct {
	addr string
	seen time.Time
}

func main() {
	cfgPath := flag.String("config", "configs/controller.example.yaml", "controller 配置文件")
	flag.Parse()

	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		log.Fatal(err)
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		log.Fatal(err)
	}

	rootCA, err := ca.LoadOrCreate(cfg.DataDir + "/ca")
	if err != nil {
		log.Fatal("CA: ", err)
	}

	// 传输授权签名密钥（grant 的签发/验签，全系统唯一非证书密钥材料）
	signer, signPub, err := loadOrCreateSignKeys(cfg.DataDir)
	if err != nil {
		log.Fatal(err)
	}

	db, err := sql.Open("sqlite", cfg.DataDir+"/ff.db")
	if err != nil {
		log.Fatal(err)
	}
	// TODO(M1)：任务表 schema 与持久化

	c := &controller{
		cfg:          cfg,
		ca:           rootCA,
		signer:       signer,
		signPub:      signPub,
		graph:        topology.New(),
		db:           db,
		pending:      map[api.NodeID][]api.TransferGrant{},
		ledger:       loadEnrollLedger(cfg.DataDir),
		publics:      map[api.NodeID]pubEntry{},
		punchTried:   map[[2]api.NodeID]time.Time{},
		pendingPunch: map[api.NodeID][]api.PunchDirective{},
	}

	// M6 打洞回声口：UDP 端口 = 控制端口 + 1。agent 从数据面 socket
	// 发签名 WHOAMI，controller 记录观测到的公网映射（媒人的账本）。
	// 回环地址不登记——controller 同机的 agent 走 loopback，别家
	// 拿这个地址会打到自己身上形成假边。
	echoPort := 9444
	if _, port, err := net.SplitHostPort(cfg.Listen); err == nil {
		if p, err := strconv.Atoi(port); err == nil {
			echoPort = p + 1
		}
	}
	echo, err := nat.NewEchoServer(echoPort, rootCA.Pool(), func(nodeID, public string) {
		host, _, err := net.SplitHostPort(public)
		if err != nil || net.ParseIP(host) == nil || net.ParseIP(host).IsLoopback() {
			return
		}
		c.mu.Lock()
		c.publics[api.NodeID(nodeID)] = pubEntry{addr: public, seen: time.Now()}
		c.mu.Unlock()
		log.Printf("WHOAMI：%s -> %s", nodeID, public)
	})
	if err != nil {
		log.Fatal("UDP 回声口启动失败：", err)
	}
	defer echo.Close()
	go func() { log.Fatal(echo.Serve()) }()
	log.Printf("打洞回声口 UDP :%d", echoPort)

	// 管理员证书：仅首次启动生成到 data-dir。拷到你自己的机器保管
	// 后，建议从服务器上删除——持有它的人就是操作者。
	adminCrt, adminKey := cfg.DataDir+"/admin.crt", cfg.DataDir+"/admin.key"
	if _, err := os.Stat(adminCrt); err != nil {
		certPEM, keyPEM, _, err := rootCA.Issue("admin", false, ca.RoleAdmin)
		if err != nil {
			log.Fatal("生成管理员证书失败：", err)
		}
		os.WriteFile(adminCrt, certPEM, 0o600)
		os.WriteFile(adminKey, keyPEM, 0o600)
		log.Printf("已生成管理员证书：%s 与 %s（拷走保管，勿留在服务器）", adminCrt, adminKey)
	}

	// 证书 SAN：本机全部非回环地址（LAN + Tailscale + 主机名），
	// agent 从任何网络拨过来都能通过校验
	host, _ := os.Hostname()
	sans := []string{"127.0.0.1", "localhost", host}
	if ifaces, err := net.Interfaces(); err == nil {
		for _, ifc := range ifaces {
			addrs, _ := ifc.Addrs()
			for _, a := range addrs {
				var ip net.IP
				switch v := a.(type) {
				case *net.IPNet:
					ip = v.IP
				case *net.IPAddr:
					ip = v.IP
				}
				if ip != nil && !ip.IsLoopback() {
					sans = append(sans, ip.String())
				}
			}
		}
	}
	_, _, cert, err := rootCA.Issue("controller", true, "controller", sans...)
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/enroll", c.handleEnroll)
	mux.HandleFunc("POST /v1/heartbeat", c.handleHeartbeat)
	mux.HandleFunc("POST /v1/transfer", c.handleTransfer)
	mux.HandleFunc("POST /v1/jobdone", c.handleJobDone)
	mux.HandleFunc("GET /v1/status", c.handleStatus)

	srv := &http.Server{
		Addr:      cfg.Listen,
		Handler:   mux,
		TLSConfig: rootCA.ServerTLS(cert),
	}
	log.Printf("controller 监听 %s（数据目录 %s）", cfg.Listen, cfg.DataDir)
	log.Fatal(srv.ListenAndServeTLS("", ""))
}

func loadConfig(path string) (Config, error) {
	var cfg Config
	b, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return cfg, err
	}
	if cfg.Listen == "" {
		cfg.Listen = ":8443"
	}
	if cfg.DataDir == "" {
		cfg.DataDir = "/var/lib/ffctl"
	}
	return cfg, nil
}

// clientRole 从 mTLS 客户端证书取角色（OU 字段）。
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

func signPubPEM(pub ed25519.PublicKey) string {
	b, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return ""
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: b}))
}

// —— enrollment 台账：核销状态与节点编号持久化（防重启后 token 复活、
// 防 CN 撞号）。文件在 data-dir，随每次核销落盘。 ——
type enrollLedger struct {
	Burned   map[string]string `json:"burned"`    // tokenHash -> nodeID
	NextNode int               `json:"next_node"` // 下一节点编号
}

func loadEnrollLedger(dir string) *enrollLedger {
	l := &enrollLedger{Burned: map[string]string{}, NextNode: 1}
	if b, err := os.ReadFile(dir + "/enroll-ledger.json"); err == nil {
		json.Unmarshal(b, l)
	}
	if l.Burned == nil {
		l.Burned = map[string]string{}
	}
	if l.NextNode < 1 {
		l.NextNode = 1
	}
	return l
}

func (l *enrollLedger) save(dir string) {
	b, err := json.Marshal(l)
	if err != nil {
		return
	}
	os.WriteFile(dir+"/enroll-ledger.json", b, 0o600)
}

// handleEnroll：一次性 token 换节点证书（角色固定为 node）。
// 核销即废且**跨重启持久**；节点编号单调递增，绝不复用。
// 无证书也可访问（ServerTLS 用 VerifyClientCertIfGiven 放行）。
func (c *controller) handleEnroll(w http.ResponseWriter, r *http.Request) {
	var req api.EnrollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	c.mu.Lock()
	valid := false
	for _, t := range c.cfg.EnrollTokens {
		if _, burned := c.ledger.Burned[api.TokenHash(t)]; t == req.Token && !burned {
			valid = true
			break
		}
	}
	if !valid {
		c.mu.Unlock()
		http.Error(w, "invalid or used token", http.StatusUnauthorized)
		return
	}
	nodeID := fmt.Sprintf("node-%d", c.ledger.NextNode)
	c.ledger.NextNode++
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
	var hb api.Heartbeat
	if err := json.NewDecoder(r.Body).Decode(&hb); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if cn := r.TLS.PeerCertificates[0].Subject.CommonName; cn != hb.NodeID {
		http.Error(w, "node_id does not match certificate", http.StatusForbidden)
		return
	}
	// 公网映射以 controller 回声口的观测为准，agent 上报值仅作参考
	c.mu.Lock()
	if pe, ok := c.publics[hb.NodeID]; ok && time.Since(pe.seen) < 90*time.Second {
		hb.Public = pe.addr
	}
	c.mu.Unlock()
	c.graph.Apply(hb)
	c.mu.Lock()
	jobs := c.pending[hb.NodeID]
	delete(c.pending, hb.NodeID)
	c.mu.Unlock()
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
	json.NewEncoder(w).Encode(api.HeartbeatResponse{
		Jobs:    jobs,
		Peers:   c.graph.Peers(),
		Punches: directives,
	})
}

// pickPunches 挑选打洞配对：双方都有新鲜公网映射、互相都没有直连边、
// 且该配对距上次尝试超过冷却时间。**指令同时排队给两端**——打洞
// 必须双方同时对发，只通知一端必然失败（之前踩过的坑）。
func (c *controller) pickPunches(hb *api.Heartbeat) []api.PunchDirective {
	c.mu.Lock()
	defer c.mu.Unlock()
	myPub, ok := c.publics[hb.NodeID]
	if !ok {
		return nil // 自己还没有公网映射，等 WHOAMI 保活
	}
	// 现有边集合（双向任一存在即认为已连通）
	connected := map[api.NodeID]bool{hb.NodeID: true}
	for _, e := range hb.Edges {
		connected[e.To] = true
	}
	var out []api.PunchDirective
	for id, pe := range c.publics {
		if connected[id] || time.Since(pe.seen) >= 90*time.Second {
			continue
		}
		key := [2]api.NodeID{hb.NodeID, id}
		if key[0] > key[1] {
			key[0], key[1] = key[1], key[0]
		}
		if t, ok := c.punchTried[key]; ok && time.Since(t) < 90*time.Second {
			continue
		}
		c.punchTried[key] = time.Now()
		var private string
		if a := c.graph.Addr(id); a != "" {
			private = a
		}
		out = append(out, api.PunchDirective{Peer: id, Addr: pe.addr, Private: private})
		// 给对端排队互惠指令（含本端公网映射与广播地址）
		var myPrivate string
		if a := c.graph.Addr(hb.NodeID); a != "" {
			myPrivate = a
		}
		c.pendingPunch[id] = append(c.pendingPunch[id], api.PunchDirective{
			Peer:    hb.NodeID,
			Addr:    myPub.addr,
			Private: myPrivate,
		})
		log.Printf("发牌：%s ↔ %s（%s / %s）", hb.NodeID, id, pe.addr, myPub.addr)
	}
	return out
}

// handleTransfer：仅 admin。选链 + 签发 grant 并投递到源节点任务队列。
func (c *controller) handleTransfer(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, ca.RoleAdmin) {
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
		hop := api.Hop{NodeID: id}
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
		DstPath:   req.DstPath,
		ChunkSize: 4 << 20,
		Streams:   4, // TODO(M4)：按路径质量与负载动态定
		RateLimit: req.RateLimit,
		ExpiresAt: time.Now().Add(30 * time.Minute),
	}
	grant.Sign(c.signer)
	c.mu.Lock()
	c.pending[req.Src] = append(c.pending[req.Src], grant) // 投递到源节点队列，随下次心跳下发
	c.mu.Unlock()
	json.NewEncoder(w).Encode(grant)
}

// handleJobDone：agent 回报任务结果，node 角色。
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
	if req.OK {
		log.Printf("任务 %s 完成（%s）", req.GrantID, req.NodeID)
	} else {
		log.Printf("任务 %s 失败（%s）：%s", req.GrantID, req.NodeID, req.Err)
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
func (c *controller) trySwitch(w http.ResponseWriter, req api.TransferRequest) bool {
	snap := c.graph.Snapshot()
	best := api.NodeID("")
	bestScore := 1e9
	for _, hb := range snap {
		R := hb.NodeID
		if R == req.Src || R == req.Dst {
			continue
		}
		// 两端都要有到 R 的出站边（谁探测的谁去拨）
		if _, _, ok := c.graph.EdgeDetail(req.Src, R); !ok {
			continue
		}
		if _, _, ok := c.graph.EdgeDetail(req.Dst, R); !ok {
			continue
		}
		load := hb.LoadPct()
		if load > topology.MaxLoadPct {
			continue
		}
		score := load + float64(hb.ActiveXfers)*10 // 负载优先，在途传输数加权
		if score < bestScore {
			bestScore = score
			best = R
		}
	}
	if best == "" {
		return false
	}
	proto, addr, _ := c.graph.EdgeDetail(req.Src, best)
	if addr == "" {
		addr = c.graph.Addr(best)
	}
	if proto == "" {
		proto = "quic"
	}

	c.mu.Lock()
	c.nextID++
	id := c.nextID
	c.mu.Unlock()
	grant := api.TransferGrant{
		ID:        fmt.Sprintf("xfer-%d", id),
		Src:       req.Src,
		Dst:       req.Dst,
		Mode:      "switch",
		Hops:      []api.Hop{{NodeID: req.Src}, {NodeID: best, Addr: addr, Proto: proto}, {NodeID: req.Dst}},
		SrcPath:   req.SrcPath,
		DstPath:   req.DstPath,
		ChunkSize: 4 << 20,
		Streams:   4,
		RateLimit: req.RateLimit,
		ExpiresAt: time.Now().Add(30 * time.Minute),
	}
	grant.Sign(c.signer)
	c.mu.Lock()
	c.pending[req.Src] = append(c.pending[req.Src], grant) // 源端：发送
	c.pending[req.Dst] = append(c.pending[req.Dst], grant) // 目的端：出站接入交换台
	c.mu.Unlock()
	log.Printf("交换台模式：%s -> %s 经 %s 对接", req.Src, req.Dst, best)
	json.NewEncoder(w).Encode(grant)
	return true
}

func loadOrCreateSignKeys(dir string) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	if b, err := os.ReadFile(dir + "/sign.key"); err == nil {
		priv := ed25519.PrivateKey(b)
		return priv, priv.Public().(ed25519.PublicKey), nil
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	if err := os.WriteFile(dir+"/sign.key", priv, 0o600); err != nil {
		return nil, nil, err
	}
	return priv, priv.Public().(ed25519.PublicKey), nil
}
