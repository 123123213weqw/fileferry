// ff-agent：每台服务器一个。职责：enrollment（首次）、心跳上报
// （负载 + 可达性边）、对端探测、数据面监听与传输执行。
// agent 只保持对 controller 的出站连接，任务与节点列表都由心跳
// 响应捎带——天然穿越 NAT，无需任何入站端口（数据面监听除外）。
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/quic-go/quic-go"
	"gopkg.in/yaml.v3"

	"fileferry/internal/api"
	"fileferry/internal/transfer"
)

type Config struct {
	Controller  string `yaml:"controller"`
	EnrollToken string `yaml:"enroll-token"`
	DataPort    int    `yaml:"data-port"`
	DataDir     string `yaml:"data-dir"`
	// Advertise 显式声明对外的数据面地址（host:port）。controller 与
	// agent 同机时自动探测会得到 127.0.0.1，公网机必须手工指定。
	Advertise string `yaml:"advertise"`
}

var (
	cfg       Config
	nodeID    string
	hostname  string
	tlsConf   *tls.Config
	hbClient  *api.Client
	signPub   ed25519.PublicKey // grant 验签公钥

	mu      sync.Mutex
	peers   []api.PeerInfo   // 最近一次心跳响应下发的在线节点
	edges   []api.EdgeReport // 最近一轮探测的可达边
	running map[string]bool  // 去重：正在执行的 grant ID

	probeNow = make(chan struct{}, 1) // 节点表变化时立即触发一轮探测
)

func main() {
	cfgPath := flag.String("config", "configs/agent.example.yaml", "agent 配置文件")
	flag.Parse()

	if err := run(*cfgPath); err != nil {
		log.Fatal(err)
	}
}

func run(cfgPath string) error {
	if err := loadConfig(cfgPath); err != nil {
		return err
	}
	var err error
	hostname, err = os.Hostname()
	if err != nil {
		return err
	}

	// 1. 证书：本地没有就先 enrollment，同时取得 grant 验签公钥
	cert, rootPool, err := loadOrCreateCert()
	if err != nil {
		return err
	}
	tlsConf = &tls.Config{
		Certificates: []tls.Certificate{*cert},
		RootCAs:      rootPool,
		MinVersion:   tls.VersionTLS13,
	}
	if err := loadSignPub(); err != nil {
		return err
	}
	hbClient = &api.Client{Base: cfg.Controller, HC: &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConf}}}
	running = map[string]bool{}
	log.Printf("agent %s 就绪（controller=%s）", nodeID, cfg.Controller)

	// 2. 心跳 + 探测循环
	go heartbeatLoop()
	go probeLoop()

	// 3. 数据面：QUIC 监听（UDP）+ TCP 回退监听（端口约定 +1）。
	// 服务端强制校验客户端证书（此前仅靠 grant 验签兜底）。
	serverTLS := &tls.Config{
		Certificates: []tls.Certificate{*cert},
		ClientCAs:    rootPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", cfg.DataPort))
	if err != nil {
		return err
	}
	udp, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	ln, err := quic.Listen(udp, serverTLS, &quic.Config{MaxIdleTimeout: 30 * time.Second})
	if err != nil {
		return err
	}
	defer ln.Close()
	tcpLn, err := tls.Listen("tcp", fmt.Sprintf(":%d", cfg.DataPort+1), serverTLS)
	if err != nil {
		log.Printf("TCP 回退监听失败（仅 QUIC 可用）：%v", err)
	} else {
		defer tcpLn.Close()
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	errCh := make(chan error, 2)
	go func() { errCh <- transfer.ServeQUIC(ln, nodeID, verifyGrant, tlsConf) }()
	if tcpLn != nil {
		go func() { errCh <- transfer.ServeTCP(tcpLn, nodeID, verifyGrant, tlsConf) }()
	}
	select {
	case err := <-errCh:
		return err
	case s := <-sig:
		log.Println("收到信号退出：", s)
		return nil
	}
}

func loadConfig(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return err
	}
	if cfg.Controller == "" || cfg.DataDir == "" {
		return fmt.Errorf("controller / data-dir 未配置")
	}
	if cfg.DataPort == 0 {
		cfg.DataPort = 7800
	}
	return nil
}

// loadOrCreateCert 优先读 data-dir 下的既有证书；缺失则用一次性
// token 向 controller enrollment 并落盘。
// TODO(M1)：证书临期自动续期。
func loadOrCreateCert() (*tls.Certificate, *x509.CertPool, error) {
	certPath := filepath.Join(cfg.DataDir, "node.crt")
	keyPath := filepath.Join(cfg.DataDir, "node.key")
	if cert, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
		if len(cert.Certificate) > 0 {
			if c, err := x509.ParseCertificate(cert.Certificate[0]); err == nil {
				nodeID = c.Subject.CommonName
			}
		}
		pool, err := loadRootPool()
		return &cert, pool, err
	}
	if cfg.EnrollToken == "" {
		return nil, nil, fmt.Errorf("无证书且未配置 enroll-token")
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return nil, nil, err
	}
	// enroll 阶段还没有根证书，无法校验 controller 身份，先跳过校验；
	// 该连接只被一次性 token 保护。TODO(M1)：config 里支持证书指纹
	// 固定（trust-on-first-use），消除这一窗口。
	cl := &api.Client{Base: cfg.Controller, HC: &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}},
	}}
	resp, err := cl.Enroll(api.EnrollRequest{
		Token:    cfg.EnrollToken,
		Hostname: hostname,
		Addr:     advertisedAddr(),
	})
	if err != nil {
		return nil, nil, fmt.Errorf("enroll: %w", err)
	}
	nodeID = resp.NodeID
	if err := os.WriteFile(certPath, []byte(resp.CertPEM), 0o600); err != nil {
		return nil, nil, err
	}
	if err := os.WriteFile(keyPath, []byte(resp.KeyPEM), 0o600); err != nil {
		return nil, nil, err
	}
	if err := os.WriteFile(filepath.Join(cfg.DataDir, "ca.crt"), []byte(resp.RootPEM), 0o644); err != nil {
		return nil, nil, err
	}
	if err := os.WriteFile(filepath.Join(cfg.DataDir, "sign.pub"), []byte(resp.SignPubPEM), 0o644); err != nil {
		return nil, nil, err
	}
	cert, err := tls.X509KeyPair([]byte(resp.CertPEM), []byte(resp.KeyPEM))
	if err != nil {
		return nil, nil, err
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM([]byte(resp.RootPEM))
	return &cert, pool, nil
}

func loadRootPool() (*x509.CertPool, error) {
	b, err := os.ReadFile(filepath.Join(cfg.DataDir, "ca.crt"))
	if err != nil {
		return nil, err
	}
	if block, _ := pem.Decode(b); block == nil {
		return nil, fmt.Errorf("ca.crt 不是合法 PEM")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b) {
		return nil, fmt.Errorf("ca.crt 解析失败")
	}
	return pool, nil
}

// loadSignPub 载入 controller 的 grant 签名公钥（enrollment 时取得）。
func loadSignPub() error {
	b, err := os.ReadFile(filepath.Join(cfg.DataDir, "sign.pub"))
	if err != nil {
		return fmt.Errorf("读取 sign.pub：%w（删掉 data-dir 重新入网可修复）", err)
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return fmt.Errorf("sign.pub 不是合法 PEM")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}
	p, ok := pub.(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("sign.pub 不是 ed25519 公钥")
	}
	signPub = p
	return nil
}

// verifyGrant 在数据面本地验签：签名有效、发给我、未过期。
func verifyGrant(g *api.TransferGrant) bool {
	return g.Verify(signPub) && g.Dst == nodeID && time.Now().Before(g.ExpiresAt)
}

// advertisedAddr 返回对外广播的数据面地址：优先显式配置，
// 否则取"通往 controller 方向"的本机源 IP。
func advertisedAddr() string {
	if cfg.Advertise != "" {
		return cfg.Advertise
	}
	return fmt.Sprintf("%s:%d", localIPTowardsController(), cfg.DataPort)
}

func heartbeatLoop() {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for range t.C {
		mu.Lock()
		hb := api.Heartbeat{
			NodeID:   nodeID,
			Hostname: hostname,
			Addr:     advertisedAddr(),
			Edges:    edges,
			TS:       time.Now(),
			// TODO(M1)：/proc 采集 CPU/内存/磁盘/网卡
		}
		mu.Unlock()
		resp, err := hbClient.Heartbeat(hb)
		if err != nil {
			log.Println("心跳失败：", err)
			continue
		}
		mu.Lock()
		changed := !samePeerSet(peers, resp.Peers)
		peers = resp.Peers
		mu.Unlock()
		if changed {
			select { // 非阻塞触发：节点表变了，马上探测
			case probeNow <- struct{}{}:
			default:
			}
		}
		for i := range resp.Jobs {
			go runJob(resp.Jobs[i])
		}
	}
}

// samePeerSet 判断两份节点表是否含相同 ID 集合。
func samePeerSet(a, b []api.PeerInfo) bool {
	if len(a) != len(b) {
		return false
	}
	set := make(map[api.NodeID]bool, len(a))
	for _, p := range a {
		set[p.ID] = true
	}
	for _, p := range b {
		if !set[p.ID] {
			return false
		}
	}
	return true
}

// runJob 执行一次传输：源端验签 -> QUIC 发送 -> 回报结果。
func runJob(g api.TransferGrant) {
	mu.Lock()
	if running[g.ID] {
		mu.Unlock()
		return
	}
	running[g.ID] = true
	mu.Unlock()
	defer func() {
		mu.Lock()
		delete(running, g.ID)
		mu.Unlock()
	}()

	done := func(ok bool, errStr string) {
		if err := hbClient.JobDone(api.DoneRequest{GrantID: g.ID, NodeID: nodeID, OK: ok, Err: errStr}); err != nil {
			log.Println("回报失败：", err)
		}
	}

	if !g.Verify(signPub) || g.Src != nodeID {
		done(false, "grant 验签失败")
		return
	}
	if time.Now().After(g.ExpiresAt) {
		done(false, "grant 已过期")
		return
	}
	timeout := time.Until(g.ExpiresAt)
	if timeout > 30*time.Minute {
		timeout = 30 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if len(g.Hops) < 2 {
		done(false, "grant 路径不完整")
		return
	}
	firstHop := g.Hops[1]
	start := time.Now()
	if err := transfer.SendFile(ctx, g.SrcPath, firstHop, tlsConf, &g); err != nil {
		done(false, err.Error())
		log.Printf("任务 %s 失败：%v", g.ID, err)
		return
	}
	via := ""
	if len(g.Hops) > 2 {
		ids := make([]string, 0, len(g.Hops)-2)
		for _, h := range g.Hops[1 : len(g.Hops)-1] {
			ids = append(ids, h.NodeID)
		}
		via = "（经 " + strings.Join(ids, " -> ") + " 中继）"
	}
	done(true, "")
	log.Printf("任务 %s 完成：%s -> %s%s（耗时 %s）", g.ID, g.SrcPath, g.Dst, via, time.Since(start).Round(time.Millisecond))
}

// probeLoop 探测所有在线对端，成功边回填到心跳。触发时机：节点表
// 变化（立即）或每 30 秒兜底一轮。探测并行执行，单轮预算约 2 秒。
// TODO(M3)：UDP 失败时 TCP 回退探测；失败对端指数退避。
func probeLoop() {
	runRound := func() {
		mu.Lock()
		targets := make([]api.PeerInfo, 0, len(peers))
		for _, p := range peers {
			if p.ID != nodeID {
				targets = append(targets, p)
			}
		}
		mu.Unlock()
		var (
			wg      sync.WaitGroup
			muEdges sync.Mutex
			found   []api.EdgeReport
		)
		for _, p := range targets {
			wg.Add(1)
			go func(p api.PeerInfo) {
				defer wg.Done()
				ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
				defer cancel()
				rtt, proto, err := transfer.Probe(ctx, p.Addr, tlsConf)
				if err != nil {
					log.Printf("探测 %s(%s) 失败：%v", p.ID, p.Addr, err)
					return
				}
				muEdges.Lock()
				found = append(found, api.EdgeReport{To: p.ID, RTTms: float64(rtt.Microseconds()) / 1000.0, Proto: proto})
				muEdges.Unlock()
			}(p)
		}
		wg.Wait()
		mu.Lock()
		edges = found
		mu.Unlock()
	}
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-t.C:
		case <-probeNow:
		}
		runRound()
	}
}

// localIPTowardsController 返回"通往 controller 方向"的本机源 IP：
// controller 在哪个网络里，这个地址就在哪个网络里可达（tailnet 场景
// 下即 Tailscale IP，其他节点都能直连）。取不到时退化为公网出口 IP。
func localIPTowardsController() string {
	if u, err := url.Parse(cfg.Controller); err == nil {
		if host := u.Hostname(); host != "" {
			if c, err := net.DialTimeout("tcp", net.JoinHostPort(host, u.Port()), 2*time.Second); err == nil {
				defer c.Close()
				if addr, ok := c.LocalAddr().(*net.TCPAddr); ok {
					return addr.IP.String()
				}
			}
		}
	}
	return localIP()
}

func localIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:53")
	if err == nil {
		defer conn.Close()
		if addr, ok := conn.LocalAddr().(*net.UDPAddr); ok {
			return addr.IP.String()
		}
	}
	return "127.0.0.1"
}
