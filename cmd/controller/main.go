// ff-controller：控制面单实例。职责：CA 与一次性 enrollment、
// 心跳汇聚进拓扑图、为按需传输选链并签发授权（grant）、任务记录
// 落 SQLite。跑在一台能同时够到内外网的机器上即可。
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"log"
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
	cfg    Config
	ca     *ca.CA
	signer ed25519.PrivateKey
	verify ed25519.PublicKey
	graph  *topology.Graph
	db     *sql.DB

	mu     sync.Mutex
	tokens map[string]bool // 已核销的一次性令牌
	nextID int64
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
	signer, verify, err := loadOrCreateSignKeys(cfg.DataDir)
	if err != nil {
		log.Fatal(err)
	}

	db, err := sql.Open("sqlite", cfg.DataDir+"/ff.db")
	if err != nil {
		log.Fatal(err)
	}
	// TODO(M1)：任务表 schema 与持久化

	c := &controller{
		cfg:    cfg,
		ca:     rootCA,
		signer: signer,
		verify: verify,
		graph:  topology.New(),
		db:     db,
		tokens: map[string]bool{},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/enroll", c.handleEnroll)
	mux.HandleFunc("POST /v1/heartbeat", c.handleHeartbeat)
	mux.HandleFunc("POST /v1/transfer", c.handleTransfer)
	mux.HandleFunc("GET /v1/status", c.handleStatus)

	host, _ := os.Hostname()
	_, _, cert, err := rootCA.Issue("controller", true, "127.0.0.1", "localhost", host)
	if err != nil {
		log.Fatal(err)
	}
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

// handleEnroll：一次性 token 换节点证书。核销即废，无证书也可访问
// （ServerTLS 用 VerifyClientCertIfGiven 放行本路径）。
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
	certPEM, keyPEM, _, err := c.ca.Issue(nodeID, true, req.Hostname) // agent 同时做数据面服务端；生产环境 SAN 在 M2 按心跳上报地址补签
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(api.EnrollResponse{
		NodeID:  nodeID,
		CertPEM: string(certPEM),
		KeyPEM:  string(keyPEM),
		RootPEM: string(c.ca.RootPEM()),
	})
}

// handleHeartbeat：要求 mTLS；节点身份以证书 CN 为准，不可谎报。
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
	w.WriteHeader(http.StatusOK)
}

// handleTransfer：选链 + 签发 grant。TODO(M2)：通知源/目的/中继节点。
func (c *controller) handleTransfer(w http.ResponseWriter, r *http.Request) {
	if len(r.TLS.PeerCertificates) == 0 {
		http.Error(w, "client cert required", http.StatusUnauthorized)
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
	c.mu.Lock()
	c.nextID++
	id := c.nextID
	c.mu.Unlock()
	grant := &api.TransferGrant{
		ID:         fmt.Sprintf("xfer-%d", id),
		Src:        req.Src,
		Dst:        req.Dst,
		Relays:     path[1 : len(path)-1],
		SrcPath:    req.SrcPath,
		DstPath:    req.DstPath,
		ChunkSize:  4 << 20,
		RateLimit:  req.RateLimit,
		ExpiresAt:  time.Now().Add(30 * time.Minute),
	}
	grant.Sign(c.signer)
	json.NewEncoder(w).Encode(grant)
}

// handleStatus：全图快照，ffctl status 用。
func (c *controller) handleStatus(w http.ResponseWriter, r *http.Request) {
	if len(r.TLS.PeerCertificates) == 0 {
		http.Error(w, "client cert required", http.StatusUnauthorized)
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
