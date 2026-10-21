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
	"sync"
	"time"

	"gopkg.in/yaml.v3"
	_ "modernc.org/sqlite"

	"fileferry/internal/api"
	"fileferry/internal/ca"
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

	mu      sync.Mutex
	tokens  map[string]bool                // 已核销的一次性令牌
	pending map[api.NodeID][]api.TransferGrant // 源节点待执行任务
	nextID  int64
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
		cfg:     cfg,
		ca:      rootCA,
		signer:  signer,
		signPub: signPub,
		graph:   topology.New(),
		db:      db,
		tokens:  map[string]bool{},
		pending: map[api.NodeID][]api.TransferGrant{},
	}

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

// handleEnroll：一次性 token 换节点证书（角色固定为 node）。
// 核销即废，无证书也可访问（ServerTLS 用 VerifyClientCertIfGiven 放行）。
func (c *controller) handleEnroll(w http.ResponseWriter, r *http.Request) {
	var req api.EnrollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	c.mu.Lock()
	valid := false
	for _, t := range c.cfg.EnrollTokens {
		if t == req.Token && !c.tokens[t] {
			c.tokens[t] = true // 核销
			valid = true
			break
		}
	}
	nodeID := fmt.Sprintf("node-%d", len(c.tokens)) // tokens 已含本次，从 node-1 起
	c.mu.Unlock()
	if !valid {
		http.Error(w, "invalid or used token", http.StatusUnauthorized)
		return
	}
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
	c.graph.Apply(hb)
	c.mu.Lock()
	jobs := c.pending[hb.NodeID]
	delete(c.pending, hb.NodeID)
	c.mu.Unlock()
	json.NewEncoder(w).Encode(api.HeartbeatResponse{Jobs: jobs, Peers: c.graph.Peers()})
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
	if path == nil || len(path) < 2 {
		http.Error(w, "no reachable path", http.StatusUnprocessableEntity)
		return
	}
	// 组装完整逐跳路径：每跳带数据面地址与拨号协议（协议来自
	// 前驱节点探测该边的结果，QUIC 优先，不通则 TCP）
	hops := make([]api.Hop, 0, len(path))
	for i, id := range path {
		hop := api.Hop{NodeID: id}
		if i > 0 {
			hop.Addr = c.graph.Addr(id)
			if hop.Addr == "" {
				http.Error(w, fmt.Sprintf("%s offline", id), http.StatusUnprocessableEntity)
				return
			}
			hop.Proto = c.graph.EdgeInfo(path[i-1], id)
			if hop.Proto == "" {
				hop.Proto = "quic"
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
