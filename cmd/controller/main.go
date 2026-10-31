// ff-controller：控制面单实例。职责：CA 与一次性 enrollment、
// 心跳汇聚进拓扑图、为按需传输选链并签发授权（grant）、任务下发、
// 任务记录落 SQLite。权限模型：admin 角色（操作者本人）才能发起
// 传输与查看状态；node 角色只能心跳与执行。跑在一台能同时够到
// 内外网的机器上，且只有操作者可登录。
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
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
	"path/filepath"
	"strconv"
	"strings"
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
	EncDefault   bool     `yaml:"enc-default"` // 传输内容端到端加密（实验）
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
	runningSets  map[api.NodeID]map[string]bool     // 各节点最近心跳上报的执行中任务
	jobWaiters   map[api.NodeID][]chan struct{}     // 长轮询等待者：任务入队即唤醒（事件化投递）
	nextID       int64 // 初始化为 Unix 秒，重启后天然错开、永不重复

	publics      map[api.NodeID]pubEntry // 节点公网 NAT 映射（UDP 回声口观测）
	punchTried   map[[2]api.NodeID]time.Time
	pendingPunch map[api.NodeID][]api.PunchDirective // 待下发给另一端的打洞指令
	ledger       *enrollLedger                        // 持久化核销台账
	limiter      *rateLimiter

	replicas   map[string]map[api.NodeID]string   // sha256 -> nodeID -> path（M8 多源副本索引）
	pathBW     map[[2]api.NodeID]float64          // 实测路径吞吐 MB/s（jobdone 回填）
	indexCache map[api.NodeID][]api.IndexEntry    // 各节点最近索引（查源文件哈希/大小）
	revoked    map[api.NodeID]bool                // 吊销名单（软吊销：拒心跳/续期，旧授权 30min 自然过期）
	keypass    map[string]string                  // grantID -> 密钥材料（端到端加密专递，一次性）
	shares     map[string]*shareEntry             // 取件码 hash -> 分享（M11 临时取件）
}

// shareEntry 临时取件：短时效 + 次数限制的定向取文件授权。
type shareEntry struct {
	Src   api.NodeID
	Path  string
	Exp   time.Time
	Uses  int
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

	// WAL + busy_timeout：多 goroutine 并发回报时写锁竞争会返回
	// SQLITE_BUSY，静默丢失 done 终态更新（真机实测踩坑）
	db, err := sql.Open("sqlite", cfg.DataDir+"/ff.db?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)")
	if err != nil {
		log.Fatal(err)
	}
	db.SetMaxOpenConns(1) // 串行化写，配合 busy_timeout 根除竞态
	for _, ddl := range []string{
		`CREATE TABLE IF NOT EXISTS events(ts INTEGER, kind TEXT, node TEXT, detail TEXT)`,
		`CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY, base TEXT, src TEXT, dst TEXT, mode TEXT, status TEXT, grant_json TEXT, created INTEGER, updated INTEGER)`,
		`CREATE TABLE IF NOT EXISTS replicas(sha TEXT, node TEXT, path TEXT, size INTEGER, mtime INTEGER, PRIMARY KEY(sha,node))`,
		`CREATE TABLE IF NOT EXISTS revoked(node TEXT PRIMARY KEY, ts INTEGER)`,
	} {
		if _, err := db.Exec(ddl); err != nil {
			log.Fatal("初始化数据库失败：", err)
		}
	}

	c := &controller{
		cfg:          cfg,
		ca:           rootCA,
		signer:       signer,
		signPub:      signPub,
		graph:        topology.New(),
		db:           db,
		pending:      map[api.NodeID][]api.TransferGrant{},
		runningSets:  map[api.NodeID]map[string]bool{},
		jobWaiters:   map[api.NodeID][]chan struct{}{},
		nextID:       time.Now().Unix(),
		ledger:       loadEnrollLedger(cfg.DataDir),
		limiter:      &rateLimiter{seen: map[string][]time.Time{}},
		replicas:     map[string]map[api.NodeID]string{},
		pathBW:       map[[2]api.NodeID]float64{},
		indexCache:   map[api.NodeID][]api.IndexEntry{},
		revoked:      map[api.NodeID]bool{},
		keypass:      map[string]string{},
		shares:       map[string]*shareEntry{},
		publics:      map[api.NodeID]pubEntry{},
		punchTried:   map[[2]api.NodeID]time.Time{},
		pendingPunch: map[api.NodeID][]api.PunchDirective{},
	}

	// schema 迁移：旧库补列（ALTER 幂等，已存在则忽略）
	c.db.Exec(`ALTER TABLE jobs ADD COLUMN base TEXT`)
	// 重启恢复：未完成任务 + 副本索引 + 吊销名单（全部持久化于 SQLite）
	if n := c.rehydrate(); n > 0 {
		log.Printf("恢复未完成任务 %d 条", n)
	}
	if rows, err := c.db.Query(`SELECT sha,node,path,size,mtime FROM replicas`); err == nil {
		n := 0
		c.mu.Lock()
		for rows.Next() {
			var sha, node, path string
			var size, mtime int64
			if rows.Scan(&sha, &node, &path, &size, &mtime) != nil {
				continue
			}
			if c.replicas[sha] == nil {
				c.replicas[sha] = map[api.NodeID]string{}
			}
			c.replicas[sha][api.NodeID(node)] = path
			c.indexCache[api.NodeID(node)] = append(c.indexCache[api.NodeID(node)],
				api.IndexEntry{Path: path, Size: size, Mtime: mtime, SHA256: sha})
			n++
		}
		c.mu.Unlock()
		rows.Close()
		if n > 0 {
			log.Printf("恢复副本索引 %d 条", n)
		}
	}
	if rows, err := c.db.Query(`SELECT node FROM revoked`); err == nil {
		c.mu.Lock()
		for rows.Next() {
			var node string
			if rows.Scan(&node) == nil {
				c.revoked[api.NodeID(node)] = true
			}
		}
		c.mu.Unlock()
		rows.Close()
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
	// controller 自身证书动态自续：GetCertificate 回调在剩余 <12h 时
	// 重新签发热替换——根治"controller 证书 24h 过期导致全网失联"
	//（2026-10-24 事故：agent 续期请求因 controller 证书过期被拒，
	//  随后 agent 证书也过期，双向死锁）。
	var (
		selfMu   sync.Mutex
		selfCert tls.Certificate
		selfExp  time.Time
	)
	issueSelf := func() error {
		_, _, c, err := rootCA.Issue("controller", true, "controller", sans...)
		if err != nil {
			return err
		}
		selfMu.Lock()
		selfCert, selfExp = c, time.Now().Add(24*time.Hour)
		selfMu.Unlock()
		return nil
	}
	if err := issueSelf(); err != nil {
		log.Fatal("controller 自身证书签发失败：", err)
	}
	go func() { // 每小时巡检，剩余 <12h 即重签
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for range t.C {
			selfMu.Lock()
			left := time.Until(selfExp)
			selfMu.Unlock()
			if left < 12*time.Hour {
				if err := issueSelf(); err != nil {
					log.Println("controller 自身证书重签失败：", err)
				} else {
					log.Println("controller 自身证书已热更新")
				}
			}
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/enroll", c.handleEnroll)
	mux.HandleFunc("POST /v1/heartbeat", c.handleHeartbeat)
	mux.HandleFunc("POST /v1/transfer", c.handleTransfer)
	mux.HandleFunc("POST /v1/jobdone", c.handleJobDone)
	mux.HandleFunc("POST /v1/renew", c.handleRenew)
	mux.HandleFunc("GET /v1/status", c.handleStatus)
	mux.HandleFunc("GET /v1/jobs", c.handleJobs)
	mux.HandleFunc("POST /v1/index", c.handleIndex)
	mux.HandleFunc("POST /v1/revoke", c.handleRevoke)
	mux.HandleFunc("POST /v1/keypass", c.handleKeypassPost)
	mux.HandleFunc("GET /v1/keypass", c.handleKeypassGet)
	mux.HandleFunc("POST /v1/share", c.handleShare)
	mux.HandleFunc("POST /v1/get", c.handleGet)

	tlsCfg := rootCA.ServerTLS(tls.Certificate{})
	tlsCfg.Certificates = nil // 交由 GetCertificate 动态提供（有静态列表时 TLS 不走回调）
	tlsCfg.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		selfMu.Lock()
		defer selfMu.Unlock()
		return &selfCert, nil
	}
	srv := &http.Server{
		Addr:      cfg.Listen,
		Handler:   mux,
		TLSConfig: tlsCfg,
	}
	log.Printf("controller 监听 %s（数据目录 %s，自身证书自动续期已启用）", cfg.Listen, cfg.DataDir)
	go c.sweepStuckJobs()
	log.Fatal(srv.ListenAndServeTLS("", ""))
}

// sweepStuckJobs 卡死任务巡检：状态 'sent'（已投递）但**所有源节点
// 的最近心跳都不再报告它在执行** → 源 agent 死了且没来得及上报失败
//（kill -9 / 断电），重签发续传。宽限 60s 区分慢任务（执行中的任务
// 会持续出现在心跳 running 集里）。autoRetry 自带去重与次数上限。
func (c *controller) sweepStuckJobs() {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for range t.C {
		rows, err := c.db.Query(`SELECT id, grant_json, updated FROM jobs WHERE status='sent'`)
		if err != nil {
			continue
		}
		type stuck struct {
			id, gj string
		}
		var candidates []stuck
		now := time.Now().Unix()
		for rows.Next() {
			var it stuck
			var updated int64
			if err := rows.Scan(&it.id, &it.gj, &updated); err != nil {
				continue
			}
			if now-updated < 60 {
				continue // 宽限期：刚投递的任务不算卡死
			}
			candidates = append(candidates, it)
		}
		rows.Close()
		for _, it := range candidates {
			var g api.TransferGrant
			if json.Unmarshal([]byte(it.gj), &g) != nil {
				continue
			}
			alive := false
			for _, src := range g.AllSources() {
				if set, ok := c.runningSets[src]; ok && (set[it.id] || set["recv-"+it.id]) {
					alive = true
					break
				}
			}
			if !alive {
				log.Printf("[sweep] 任务 %s 无任何源节点在执行，判定卡死", it.id)
				c.autoRetry(it.id)
			}
		}
	}
}

// autoRetry 失败任务自动重签发（同一文件，新 grant ID）：接收端按
// 目标路径+哈希保留断点进度，新传输只补缺块。最多 3 次，防止失败
// 风暴；重试任务沿用原路径与参数。
func (c *controller) autoRetry(oldID string) {
	var gj string
	var updated int64
	if err := c.db.QueryRow(`SELECT grant_json, updated FROM jobs WHERE id=?`, oldID).Scan(&gj, &updated); err != nil {
		return
	}
	if time.Since(time.Unix(updated, 0)) > 15*time.Minute {
		return // 陈年任务（重启恢复的历史失败回报等），不重试
	}
	var g api.TransferGrant
	if json.Unmarshal([]byte(gj), &g) != nil {
		return
	}
	if g.Retries >= 3 {
		return // 重试上限，防止失败风暴
	}
	if time.Now().After(g.ExpiresAt) {
		return
	}
	base := retryBase(g.ID)
	// 去重：该根任务已有在途重试就不分叉（多源各自的失败回报
	// 都会触发 autoRetry，没有这个检查会重试风暴）
	var inflight int
	c.db.QueryRow(`SELECT COUNT(*) FROM jobs WHERE base=? AND status IN ('queued','sent') AND id != ?`, base, oldID).Scan(&inflight)
	if inflight > 0 {
		return
	}
	c.mu.Lock()
	c.nextID++
	g.Retries++
	g.ID = fmt.Sprintf("retry-%d-%s", c.nextID, base)
	g.ExpiresAt = time.Now().Add(30 * time.Minute)
	g.Sign(c.signer)
	targets := g.AllSources()
	for _, t := range targets {
		c.pending[t] = append(c.pending[t], g)
	}
	c.mu.Unlock()
	for _, t := range targets {
		c.notifyJobs(t) // 事件化投递：入队即唤醒长轮询
	}
	c.jobPersist(&g)
	log.Printf("断点续传：重签发 %s（原 %s，接收端将跳过已收块）", g.ID, oldID)
}

func retryDepth(id string) int {
	n := 0
	for strings.HasPrefix(id, "retry-") {
		i := strings.Index(id, "-")
		if i < 0 {
			break
		}
		rest := id[i+1:]
		j := strings.Index(rest, "-")
		if j < 0 {
			break
		}
		id = rest[j+1:]
		n++
	}
	return n
}

// lookupGrantSrc 从任务表反查源端（密钥上报校验用）。
func (c *controller) lookupGrantSrc(id string) api.NodeID {
	var gj string
	if err := c.db.QueryRow(`SELECT grant_json FROM jobs WHERE id=?`, id).Scan(&gj); err != nil {
		return ""
	}
	var g api.TransferGrant
	if json.Unmarshal([]byte(gj), &g) != nil {
		return ""
	}
	return g.Src
}

// lookupGrantDst 从任务表反查目的端（吞吐回填用）。
func (c *controller) lookupGrantDst(id string) api.NodeID {
	var gj string
	if err := c.db.QueryRow(`SELECT grant_json FROM jobs WHERE id=?`, id).Scan(&gj); err != nil {
		return ""
	}
	var g api.TransferGrant
	if json.Unmarshal([]byte(gj), &g) != nil {
		return ""
	}
	return g.Dst
}

// rehydrate 从 SQLite 恢复未完成任务到内存队列。
func (c *controller) rehydrate() int {
	rows, err := c.db.Query(`SELECT grant_json FROM jobs WHERE status='queued'`)
	if err != nil {
		log.Println("任务恢复查询失败：", err)
		return 0
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var gj string
		if rows.Scan(&gj) != nil {
			continue
		}
		var g api.TransferGrant
		if json.Unmarshal([]byte(gj), &g) == nil && g.Src != "" {
			c.mu.Lock()
			c.pending[g.Src] = append(c.pending[g.Src], g)
			c.mu.Unlock()
			c.notifyJobs(g.Src) // 事件化投递：入队即唤醒长轮询
			n++
		}
	}
	return n
}

// event 记录安全/审计事件（落 SQLite + 日志）。
func (c *controller) event(kind, node, detail string) {
	log.Printf("[audit] %s %s %s", kind, node, detail)
	go c.db.Exec(`INSERT INTO events(ts,kind,node,detail) VALUES(?,?,?,?)`,
		time.Now().Unix(), kind, node, detail)
}

// jobPersist 任务落库与状态更新。
func (c *controller) jobPersist(g *api.TransferGrant) {
	gj, _ := json.Marshal(g)
	// 同步写入：jobdone 的状态更新依赖此行已存在，异步会竞态丢失
	c.db.Exec(`INSERT OR REPLACE INTO jobs(id,base,src,dst,mode,status,grant_json,created,updated) VALUES(?,?,?,?,?,?,?,?,?)`,
		g.ID, retryBase(g.ID), g.Src, g.Dst, g.Mode, "queued", string(gj), time.Now().Unix(), time.Now().Unix())
}

// retryBase 剥掉 retry-N- 前缀取根任务 ID。
func retryBase(id string) string {
	for strings.HasPrefix(id, "retry-") {
		rest := strings.TrimPrefix(id, "retry-")
		if i := strings.Index(rest, "-"); i >= 0 {
			id = rest[i+1:]
		} else {
			break
		}
	}
	return id
}

func (c *controller) jobUpdate(id, status string) {
	go c.db.Exec(`UPDATE jobs SET status=?, updated=? WHERE id=?`, status, time.Now().Unix(), id)
}

// rateLimiter 每身份滑动窗口限速（防合法证书节点刷爆 controller）。
type rateLimiter struct {
	mu   sync.Mutex
	seen map[string][]time.Time
}

func (l *rateLimiter) allow(key string, perSec int) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	list := l.seen[key]
	kept := list[:0]
	for _, t := range list {
		if now.Sub(t) < time.Second {
			kept = append(kept, t)
		}
	}
	if len(kept) >= perSec {
		l.seen[key] = kept
		return false
	}
	l.seen[key] = append(kept, now)
	return true
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
	c.shares[api.TokenHash(code)] = &shareEntry{Src: req.Src, Path: req.Path, Exp: time.Now().Add(time.Duration(req.TTLMin) * time.Minute), Uses: 3}
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
	se.Uses--
	if se.Uses <= 0 {
		defer delete(c.shares, api.TokenHash(req.Code))
	}
	c.mu.Unlock()
	if dst == se.Src {
		http.Error(w, "source cannot fetch itself", http.StatusBadRequest)
		return
	}
	// 组 grant：源=存件节点，目的=取件节点
	if _, _, ok := c.graph.EdgeDetail(dst, se.Src); !ok {
		_, _, ok2 := c.graph.EdgeDetail(se.Src, dst)
		if !ok2 {
			http.Error(w, "no path to source", http.StatusUnprocessableEntity)
			return
		}
	}
	path := c.graph.Path(dst, se.Src)
	if path == nil || len(path) < 2 {
		http.Error(w, "no reachable path", http.StatusUnprocessableEntity)
		return
	}
	hops := make([]api.Hop, 0, len(path))
	for i, id := range path {
		hop := api.Hop{NodeID: id}
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
		ChunkSize: 4 << 20,
		Streams:   2,
		Enc:       true,
		ExpiresAt: time.Now().Add(30 * time.Minute),
	}
	grant.Sign(c.signer)
	c.mu.Lock()
	c.pending[grant.Src] = append(c.pending[grant.Src], grant)
	c.mu.Unlock()
	c.notifyJobs(grant.Src) // 事件化投递：入队即唤醒长轮询
	c.jobPersist(&grant)
	c.event("get", string(dst), se.Path)
	json.NewEncoder(w).Encode(grant)
}

// shareInbox 取件落盘目录标记：agent 侧映射到其 data-dir/inbox。
func shareInbox(node api.NodeID) string { return "inbox:" }

// handleKeypassPost：源端上报端到端加密密钥材料（验证其为任务源端）。
// 密钥只在 controller 内存停留至目的端取走（一次性）。
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
	c.keypass[req.GrantID] = req.KeyB64
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
	k, ok := c.keypass[id]
	delete(c.keypass, id) // 一次性
	c.mu.Unlock()
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
func (c *controller) lookupReplicas(sha string, exclude map[api.NodeID]bool) map[api.NodeID]string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := map[api.NodeID]string{}
	for node, path := range c.replicas[sha] {
		if !exclude[node] && c.graph.Addr(node) != "" {
			out[node] = path
		}
	}
	return out
}

// handleJobs：仅 admin。任务列表（含状态），支持 ?id= 精确查——
// ffctl send --wait 轮询用，也是程序化集成的任务查询接口。
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
	if !c.limiter.allow("enroll:"+r.RemoteAddr, 2) {
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
// notifyJobs 唤醒某节点的长轮询心跳（任务/打洞指令入队时调用）。
func (c *controller) notifyJobs(node api.NodeID) {
	c.mu.Lock()
	waiters := c.jobWaiters[node]
	delete(c.jobWaiters, node)
	c.mu.Unlock()
	for _, ch := range waiters {
		close(ch)
	}
}

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
	c.mu.Lock()
	set := make(map[string]bool, len(hb.Running))
	for _, id := range hb.Running {
		set[id] = true
	}
	c.runningSets[hb.NodeID] = set
	// 长轮询：无待办时压住响应，任务/打洞指令入队立即唤醒——
	// grant 投递延迟从"心跳周期的一半"降到 ~1 RTT。
	// 唤醒后在本锁内重查（入队也持本锁，双重检查防丢唤醒）。
	if len(c.pending[hb.NodeID]) == 0 && len(c.pendingPunch[hb.NodeID]) == 0 {
		ch := make(chan struct{})
		c.jobWaiters[hb.NodeID] = append(c.jobWaiters[hb.NodeID], ch)
		noWork := len(c.pending[hb.NodeID]) == 0 && len(c.pendingPunch[hb.NodeID]) == 0
		c.mu.Unlock()
		if noWork {
			select {
			case <-ch:
			case <-time.After(1500 * time.Millisecond):
			}
		}
		// 不在此处重锁：落出分支后的统一 Lock 覆盖两条路径（重入会死锁）
	} else {
		c.mu.Unlock()
	}
	c.mu.Lock()
	jobs := c.pending[hb.NodeID]
	delete(c.pending, hb.NodeID)
	for _, j := range jobs {
		c.jobUpdate(j.ID, "sent") // 已投递：卡死巡检的状态依据（带 updated 时间戳）
	}
	directivesQ := c.pendingPunch[hb.NodeID]
	delete(c.pendingPunch, hb.NodeID)
	c.mu.Unlock()
	fresh := jobs[:0]
	for _, j := range jobs {
		if time.Now().Before(j.ExpiresAt) {
			fresh = append(fresh, j)
		}
	}
	jobs = fresh
	directives, punchedPair := c.pickPunches(&hb)
	for _, n := range punchedPair {
		c.notifyJobs(n) // 打洞双方同时唤醒（指令已排队）
	}
	c.mu.Lock()
	// 另一端排队中的指令（对端发牌时给本端登记的）一并下发，
	// 保证打洞双方同时行动
	if len(directivesQ) > 0 {
		log.Printf("下发排队指令给 %s x%d", hb.NodeID, len(directivesQ))
		directives = append(directives, directivesQ...)
	}
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
func (c *controller) pickPunches(hb *api.Heartbeat) ([]api.PunchDirective, []api.NodeID) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var queuedPair []api.NodeID
	myPub, ok := c.publics[hb.NodeID]
	if !ok {
		return nil, nil // 自己还没有公网映射，等 WHOAMI 保活
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
		queuedPair = append(queuedPair, hb.NodeID, id)
	}
	return out, queuedPair
}

// handleTransfer：仅 admin。选链 + 签发 grant 并投递到源节点任务队列。
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
		Enc:       c.cfg.EncDefault, // 端到端加密（真机密钥专递链路待修，默认关；单测已验证）
		IsDir:     req.Dir,          // 目录递归：源端整树枚举，逐文件签名清单
		Delta:     req.Delta,        // 增量同步：对目的端已有近似文件只传差异（rsync 式）
	}
	if req.Streams > 0 && req.Streams <= 16 {
		grant.Streams = req.Streams // 显式指定（弱网/中继链路少流常更快：多流 TCP 互相竞争恶化拥塞）
	}
	// 实验诊断：强制首跳协议（不做正确性回退；生产留空走探测）
	if req.ForceProto == "quic" || req.ForceProto == "tcp" {
		grant.Hops[1].Proto = req.ForceProto
		grant.Mix = false
	}
	// 混流：直连路径两种协议都可用时，并行流分走 TCP+UDP 叠加配额
	// （-proto 强制时不混流——ForceProto 的 Mix=false 不能被这里覆盖）
	if req.ForceProto == "" && len(path) == 2 && c.graph.EdgeAlt(req.Src, req.Dst) != "" {
		grant.Mix = true
	}
	// 流数按路径质量自适应（M4）：高 RTT 广域链路（中继/跨境）多流 TCP
	// 互相竞争恶化拥塞——tailscale 中继实测单流 0.4 vs 4 流 0.3MB/s。
	// 直连边 RTT>50ms → 降 2 流；局域快链保留 4 流填满带宽延迟积。
	if req.Streams == 0 && len(path) == 2 {
		for _, hb := range c.graph.Snapshot() {
			if hb.NodeID != req.Src {
				continue
			}
			for _, e := range hb.Edges {
				if e.To == req.Dst && e.RTTms > 50 {
					grant.Streams = 2
					log.Printf("[trace] %s→%s RTT %.0fms，流数降为 2（广域链路）", req.Src, req.Dst, e.RTTms)
					break
				}
			}
		}
	}
	// M8 多源：索引里发现其他副本 → 按路径带宽把块区间分给各源。
	// 条件：候选到目的端有直连边（多源走直连，v1 不与中继/交换台复合）。
	// 并行度按文件大小自适应（索引有 size 时）；无索引用缺省 4
	// 目录模式不走多源（树内文件已天然并行）。
	// 多源的块区间语义与 delta 配方互斥：delta 时跳过多源
	if !req.Dir && !req.Delta && req.Streams == 0 {
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
	}
	grant.Sign(c.signer)
	targets := grant.AllSources()
	c.mu.Lock()
	for _, t := range targets {
		c.pending[t] = append(c.pending[t], grant) // 每个源各收一份，各取自己的区间
	}
	npend := len(c.pending[req.Src])
	c.mu.Unlock()
	for _, t := range targets {
		c.notifyJobs(t) // 事件化投递：入队即唤醒长轮询
	}
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
func (c *controller) indexedSize(node api.NodeID, path string) int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, e := range c.indexCache[node] {
		if e.Path == path {
			return e.Size
		}
	}
	return 0
}

// applyMultiSource 查副本索引，构造多源分片。源文件的哈希/大小取自
// 源节点的索引（索引缺失则退化为单源——安全无副作用）。
func (c *controller) applyMultiSource(g *api.TransferGrant) {
	c.mu.Lock()
	var size int64
	var sha string
	for _, e := range c.indexCache[g.Src] {
		if e.Path == g.SrcPath {
			size, sha = e.Size, e.SHA256
			break
		}
	}
	c.mu.Unlock()
	if sha == "" || size <= 0 {
		return
	}
	others := c.lookupReplicas(sha, map[api.NodeID]bool{g.Src: true, g.Dst: true})
	if len(others) == 0 {
		return
	}
	g.FileSHA256 = sha
	g.FileSize = size
	totalChunks := (size + int64(g.ChunkSize) - 1) / int64(g.ChunkSize)
	if totalChunks < 4 {
		return // 太小不值得分片
	}
	// 权重：源本身按其到目的的实测带宽（缺省 2MB/s），副本按各自
	// 实测带宽（缺省 1MB/s——副本路径通常未经实测，保守起步）
	// 候选评分 = 实测带宽 × 负载折扣 100/(100+load)：自动在
	// "路径快"与"节点闲"之间取最优（多源版的最优负载）
	type cand struct {
		id    api.NodeID
		addr  string
		proto string
		path  string
		w     float64
	}
	cands := []cand{}
	if proto, addr, ok := c.graph.EdgeDetail(g.Src, g.Dst); ok && addr != "" {
		w := c.score(g.Src, g.Dst, 2.0)
		cands = append(cands, cand{g.Src, addr, proto, g.SrcPath, w})
	}
	for id, path := range others {
		proto, addr, ok := c.graph.EdgeDetail(id, g.Dst)
		if !ok || addr == "" {
			continue // 无直连边的副本不参与（v1）
		}
		cands = append(cands, cand{id, addr, proto, path, c.score(id, g.Dst, 1.0)})
	}
	if len(cands) < 2 {
		return
	}
	var wsum float64
	for _, cd := range cands {
		wsum += cd.w
	}
	g.Sources = nil
	var cursor int64
	for _, cd := range cands {
		share := int64(float64(totalChunks) * cd.w / wsum)
		if share < 1 {
			share = 1
		}
		end := cursor + share
		if end > totalChunks {
			end = totalChunks
		}
		g.Sources = append(g.Sources, api.SourceSpec{
			NodeID: cd.id, Addr: cd.addr, Proto: cd.proto, Path: cd.path, Start: cursor, End: end,
		})
		cursor = end
		if cursor >= totalChunks {
			break
		}
	}
	// 兜底：最后一个源吃掉剩余全部
	if cursor < totalChunks && len(g.Sources) > 0 {
		g.Sources[len(g.Sources)-1].End = totalChunks
	}
	log.Printf("多源并行：%d 副本，%d 块分区", len(g.Sources), totalChunks)
}

// score 候选评分：实测带宽 × 负载折扣 100/(100+load)。
func (c *controller) score(from, to api.NodeID, defBW float64) float64 {
	c.mu.Lock()
	bw := defBW
	if v, ok := c.pathBW[[2]api.NodeID{from, to}]; ok && v > 0 {
		bw = v
	}
	c.mu.Unlock()
	load := c.graph.LoadPct(to)
	return bw * 100.0 / (100.0 + load)
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
		c.jobUpdate(req.GrantID, "done")
		if req.Bytes > 0 && req.Duration > 0 {
			if dst := c.lookupGrantDst(req.GrantID); dst != "" {
				c.mu.Lock()
				c.pathBW[[2]api.NodeID{req.NodeID, dst}] = float64(req.Bytes) / req.Duration / 1e6
				c.mu.Unlock()
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
	c.notifyJobs(req.Src) // 事件化投递：入队即唤醒长轮询
	c.notifyJobs(req.Dst) // 事件化投递：入队即唤醒长轮询
	log.Printf("交换台模式：%s -> %s 经 %s 对接", req.Src, req.Dst, best)
	c.jobPersist(&grant)
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
