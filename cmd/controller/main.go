package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"fileferry/internal/api"
	"fileferry/internal/ca"
	"fileferry/internal/nat"
	"fileferry/internal/topology"
	"flag"
	"fmt"
	"gopkg.in/yaml.v3"

	// 空导入：注册 sqlite 驱动（重构把这类"无引用的导入"弄丢过，
	// 编译器不会报错，但运行时报 unknown driver）
	"log"
	_ "modernc.org/sqlite"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
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

	mu      sync.Mutex
	pending map[api.NodeID][]api.TransferGrant // 源节点待执行任务
	nextID  int64                              // 初始化为 Unix 秒，重启后天然错开、永不重复

	publics      map[api.NodeID]pubEntry // 节点公网 NAT 映射（UDP 回声口观测）
	punchTried   map[[2]api.NodeID]time.Time
	pendingPunch map[api.NodeID][]api.PunchDirective // 待下发给另一端的打洞指令
	ledger       *enrollLedger                       // 持久化核销台账
	limiter      *rateLimiter
	wakeMu       sync.Mutex
	wake         map[api.NodeID]chan struct{} // 长轮询：有待办任务时唤醒挂住的心跳

	replicas   map[string]map[api.NodeID]string     // sha256 -> nodeID -> path（M8 多源副本索引）
	pathBW     map[[2]api.NodeID]float64            // 实测路径吞吐 MB/s（jobdone 回填）
	protoBW    map[[2]api.NodeID]map[string]float64 // 每条边每种协议的实测吞吐
	indexCache map[api.NodeID][]api.IndexEntry      // 各节点最近索引（查源文件哈希/大小）
	revoked    map[api.NodeID]bool                  // 吊销名单（软吊销：拒心跳/续期，旧授权 30min 自然过期）
	keypass    map[string]keyEntry                  // grantID -> 密钥材料（端到端加密专递，一次性）
	shares     map[string]*shareEntry               // 取件码 hash -> 分享（M11 临时取件）
}

// keyEntry 是待到取密钥材料及其落库时间（用于过期清扫：源端上报了
// 但目的端始终没来取的任务，之前会永久驻留 map）。
type keyEntry struct {
	key string
	at  time.Time
}

// shareEntry 临时取件：短时效 + 次数限制的定向取文件授权。
type shareEntry struct {
	Src  api.NodeID
	Path string
	Exp  time.Time
	Uses int
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
		nextID:       time.Now().Unix(),
		ledger:       loadEnrollLedger(cfg.DataDir),
		limiter:      &rateLimiter{seen: map[string][]time.Time{}},
		wake:         map[api.NodeID]chan struct{}{},
		replicas:     map[string]map[api.NodeID]string{},
		pathBW:       map[[2]api.NodeID]float64{},
		protoBW:      map[[2]api.NodeID]map[string]float64{},
		indexCache:   map[api.NodeID][]api.IndexEntry{},
		revoked:      map[api.NodeID]bool{},
		keypass:      map[string]keyEntry{},
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
	mux.HandleFunc("POST /v1/push", c.handlePush)
	mux.HandleFunc("POST /v1/pullcert", c.handlePullCert)
	mux.HandleFunc("POST /v1/pull", c.handlePull)
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
	// 请求体上限：最大的合法请求是节点索引上报（每文件一条），
	// 16 MiB 足够；超过直接 413，避免未认证连接把内存吃穿。
	srv := &http.Server{
		Addr:      cfg.Listen,
		Handler:   http.MaxBytesHandler(mux, 16<<20),
		TLSConfig: tlsCfg,
		// 控制面不能被慢连接拖死：之前没设任何超时，未认证的慢速
		// 请求头 + 大 JSON 就能占满连接与内存。
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
	log.Printf("controller 监听 %s（数据目录 %s，自身证书自动续期已启用）", cfg.Listen, cfg.DataDir)
	log.Fatal(srv.ListenAndServeTLS("", ""))
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
	for _, t := range g.AllSources() {
		c.pending[t] = append(c.pending[t], g)
		c.notifyPending(t)
	}
	c.mu.Unlock()
	c.jobPersist(&g)
	log.Printf("断点续传：重签发 %s（原 %s，接收端将跳过已收块）", g.ID, oldID)
}

// grantParticipants 返回该 grant 的全部合法参与方（源、目的、各分片源）。
// 任务表里查不到时返回 nil——表示"无从校验"，由调用方决定放行（兼容
// 重启恢复期间的窗口）还是拒绝。
func (c *controller) grantParticipants(id string) map[api.NodeID]bool {
	var gj string
	if err := c.db.QueryRow(`SELECT grant_json FROM jobs WHERE id=?`, id).Scan(&gj); err != nil {
		return nil
	}
	var g api.TransferGrant
	if json.Unmarshal([]byte(gj), &g) != nil {
		return nil
	}
	m := map[api.NodeID]bool{g.Src: true, g.Dst: true}
	for _, sp := range g.Sources {
		m[sp.NodeID] = true
	}
	for _, h := range g.Hops { // 中继也要能回报（失败时用于换链）
		m[h.NodeID] = true
	}
	return m
}

// NormalizeNodeName 校验节点名，规则与 api.ValidateNodeName 一致
// （任意 UTF-8，禁止 ':' '/' 控制字符，长度 ≤64 字节）。
//
// 为什么单独拆一层：'：' 与 `node:/path` 语法冲突，而
// splitNodePath 取第一个冒号，名字带冒号时 "a:b:/data/x" 会被静默
// 解析成 node="a"、path="b:/data/x"——不报错、传到错的地方。所以
// 这里明确拒绝而不是静默替换。X.509 CN 与 V2 签名串都能容纳 UTF-8，
// 不构成限制（实测 "数据库-主" 可原样进 CN）。
func NormalizeNodeName(raw string) (string, error) {
	if err := api.ValidateNodeName(raw); err != nil {
		return "", err
	}
	return raw, nil
}

// claimName 占用一个节点名（大小写不敏感去重，避免 Node-1 / node-1
// 在舰队长里看起来像两台不同的机器却难以区分）。返回实际使用的名字。
func (l *enrollLedger) claimName(name string) (string, bool) {
	if l.Used == nil {
		l.Used = map[string]bool{}
	}
	key := strings.ToLower(name)
	if l.Used[key] {
		return "", false
	}
	l.Used[key] = true
	return name, true
}

const (
	// grantChunkSize 与 transfer.ChunkSize 对齐（4 MiB）。集中定义，
	// 避免三处授权构造各写一遍魔法数、日后改块大小漏掉其中一处。
	grantChunkSize = 4 << 20
	// grantTTL 是签发后的有效期；超时视为失效（防重放）。
	grantTTL = 30 * time.Minute
)

// handlePullCert：给 ffctl 签发一张**可作 TLS 服务器**的短时效传输证书。
// 仅 admin。管理员证书只带 ClientAuth，无法在 pull 场景里充当服务端。
// pushProto 给出优先拨号协议：先看该边有没有"实测更快"的协议记录，
// 再看探测结果，都没有则默认 quic。
//
// 之前只用探测结果，而探测只测握手 RTT，看不出 QUIC 在高丢包下的稳态
// 吞吐塌陷（实测 2% 丢包慢 60 倍），于是每次都挑慢的那条。
func pushProto(c *controller, id api.NodeID) string {
	hint := ""
	for _, hb := range c.graph.Snapshot() {
		for _, e := range hb.Edges {
			if e.To == id && e.Proto != "" {
				hint = e.Proto
				break
			}
		}
		if hint != "" {
			break
		}
	}
	if hint == "" {
		hint = "quic"
	}
	// 按"对端 → 本机"这条边学到的实测结果修正；caller 是本机管理员，
	// 不算节点，所以 from 用空串（等价"没有源端记录"）。
	return c.bestProto("", id, hint)
}

// handlePush：本机(管理员) → 远端节点 直推。仅 admin。
//
// 设计要点：controller 只签授权 + 给出目标拨号地址，**数据不经过
// controller**，也没有"先上传到某源节点再转"的中转开销。授权里的
// Src 就是调用者的证书 CN，接收端靠它校验 manifest 签名者，所以
// 完整性保证与节点间传输完全一致（mTLS + 逐块 SHA256 + 全文件摘要）。
func normalizeDstPath(dst, srcPath string) string {
	if dst == "" {
		return dst
	}
	if strings.HasSuffix(dst, "/") || strings.HasSuffix(dst, "\\") ||
		strings.HasSuffix(dst, string(filepath.Separator)) {
		base := filepath.Base(srcPath)
		if base == "" || base == "." || base == string(filepath.Separator) {
			return dst
		}
		return filepath.Join(dst, base)
	}
	return dst
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
	mu    sync.Mutex
	seen  map[string][]time.Time
	calls uint64
}

func (l *rateLimiter) allow(key string, perSec int) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	// 每 1k 次调用做一次全局清扫：之前空列表的 key 永不回收，
	// 公网扫端口每个 SourceIP:port 留一条，map 无界增长。
	if l.calls++; l.calls%1024 == 0 {
		for k, v := range l.seen {
			if len(v) == 0 || now.Sub(v[len(v)-1]) > 2*time.Second {
				delete(l.seen, k)
			}
		}
	}
	if len(l.seen) > 100000 { // 兜底上限，防清扫跟不上时的内存膨胀
		for k := range l.seen {
			delete(l.seen, k)
			if len(l.seen) <= 50000 {
				break
			}
		}
	}
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

// clientIP 取限速用的客户端标识。enroll 之前没有证书，只能用 IP——
// 之前用 r.RemoteAddr（含临时端口），换条连接就换一个桶，限速形同
// 虚设（实测坏 token 连发：401 401 429 429 429 429 401 401 429 429）。
func shareInbox(node api.NodeID) string { return "inbox:" }

// handleKeypassPost：源端上报端到端加密密钥材料（验证其为任务源端）。
// 密钥只在 controller 内存停留至目的端取走（一次性）。
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
	Used     map[string]bool   `json:"used"`      // 已占用的 nodeID（防撞号）
}

// claim 占用一个 nodeID：返回 false 表示已被别人占用。
func (l *enrollLedger) claim(id string) bool {
	if l.Used == nil {
		l.Used = map[string]bool{}
	}
	key := strings.ToLower(id)
	if l.Used[key] {
		return false
	}
	l.Used[key] = true
	return true
}

// nextAutoNodeID 取下一个未被占用的 node-N。
func (l *enrollLedger) nextAutoNodeID() string {
	for {
		id := fmt.Sprintf("node-%d", l.NextNode)
		l.NextNode++
		if l.Used == nil || !l.Used[strings.ToLower(id)] {
			return id
		}
	}
}

func loadEnrollLedger(dir string) *enrollLedger {
	l := &enrollLedger{Burned: map[string]string{}, NextNode: 1}
	if b, err := os.ReadFile(dir + "/enroll-ledger.json"); err == nil {
		json.Unmarshal(b, l)
	}
	if l.Burned == nil {
		l.Burned = map[string]string{}
	}
	if l.Used == nil {
		l.Used = map[string]bool{}
	}
	// 从核销台账回填已占用 ID（老版本 ledger 没有 used 字段）
	for _, id := range l.Burned {
		l.Used[strings.ToLower(id)] = true
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
func (c *controller) notifyPending(id api.NodeID) {
	c.wakeMu.Lock()
	if ch, ok := c.wake[id]; ok {
		close(ch)
		delete(c.wake, id)
	}
	c.wakeMu.Unlock()
}

// awaitPending 在最多 d 内等待该节点出现待办任务。
// 返回 true 表示已有任务（或被唤醒）。
//
// 顺序很重要：**先注册唤醒通道，再复查一次队列**。反过来的话存在
// 丢唤醒竞态——任务恰好落在"查完队列、还没注册"之间时 notifyPending
// 找不到通道，心跳会白等到超时（实测表现为延迟随机变成 5~8 秒）。
func (c *controller) awaitPending(id api.NodeID, d time.Duration) bool {
	c.wakeMu.Lock()
	ch, ok := c.wake[id]
	if !ok {
		ch = make(chan struct{})
		c.wake[id] = ch
	}
	c.wakeMu.Unlock()

	// 注册之后再查一次：若这期间已入队，直接返回，不进入等待
	c.mu.Lock()
	n := len(c.pending[id])
	c.mu.Unlock()
	if n > 0 {
		return true
	}

	tm := time.NewTimer(d)
	defer tm.Stop()
	select {
	case <-ch:
		return true
	case <-tm.C:
		c.wakeMu.Lock()
		if cur, exists := c.wake[id]; exists && cur == ch {
			delete(c.wake, id) // 超时回收，避免 map 泄漏
		}
		c.wakeMu.Unlock()
		return false
	}
}

// requeueJobs 把没送达的任务放回该节点的待投递队列（保持原顺序在前）。
func (c *controller) requeueJobs(id api.NodeID, jobs []api.TransferGrant) {
	if len(jobs) == 0 {
		return
	}
	c.mu.Lock()
	c.pending[id] = append(append([]api.TransferGrant{}, jobs...), c.pending[id]...)
	c.mu.Unlock()
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
			TCPPort: c.graph.TCPPort(cd.id),
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
		DstPath:   normalizeDstPath(req.DstPath, req.SrcPath),
		ChunkSize: grantChunkSize,
		Streams:   4,
		RateLimit: req.RateLimit,
		ExpiresAt: time.Now().Add(grantTTL),
	}
	grant.Sign(c.signer)
	c.mu.Lock()
	c.pending[req.Src] = append(c.pending[req.Src], grant) // 源端：发送
	c.pending[req.Dst] = append(c.pending[req.Dst], grant) // 目的端：出站接入交换台
	c.notifyPending(req.Src)
	c.notifyPending(req.Dst)
	c.mu.Unlock()
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
