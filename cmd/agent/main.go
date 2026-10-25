// ff-agent：每台服务器一个。职责：enrollment（首次）、心跳上报
// （负载 + 可达性边）、对端探测、WHOAMI 公网映射保活（M6）、
// 打洞执行（M6）、数据面监听与传输执行。
// 监听、探测、拨号共用同一个 UDP socket（quic.Transport），NAT
// 映射才一致——这是打洞成立的前提。agent 只保持对 controller 的
// 出站连接，任务/节点表/打洞指令都由心跳响应捎带，天然穿越 NAT。
package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/quic-go/quic-go"
	"gopkg.in/yaml.v3"

	"fileferry/internal/api"
	"fileferry/internal/nat"
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
	// AllowedDirs 落盘路径白名单：源路径与目的路径都必须位于其中，
	// 恶意授权也写不了白名单外（如 /etc）。空 = 不限制。
	AllowedDirs []string `yaml:"allowed-dirs"`
	// ShareDir 共享目录：M8 多源副本发现的数据源，agent 定期扫描
	// 并上报文件索引（后台算哈希，mtime 不变不重算）。空 = 用第一
	// 个 allowed-dir；再为空则不参与多源。
	ShareDir string `yaml:"share-dir"`
	// NodeName 请求的稳定节点名（缺省取主机名）。同名的第一次入网
	// 占用该名字，之后的入网/重装沿用同一身份。
	NodeName string `yaml:"node-name"`
}

var (
	cfg      Config
	nodeID   string
	hostname string
	tlsConf  *tls.Config
	nodeCert tls.Certificate // WHOAMI 签名用
	hbClient *api.Client
	signPub  ed25519.PublicKey // grant 验签公钥
	udpConn  *sniffConn        // 数据面共享 socket（监听+拨号+打洞+WHOAMI）

	mu       sync.Mutex
	peers    []api.PeerInfo    // 最近一次心跳响应下发的在线节点
	edges    []api.EdgeReport  // 最近一轮探测的可达边
	punched  map[string]string // 打洞成功的对端 -> 公网映射地址
	myPublic string            // controller 回声口告知的本机公网映射
	running  map[string]bool   // 去重：正在执行的 grant ID
	dueRep   []dueReport       // 待补发的任务回报（带时效，陈年丢弃）

	probeNow = make(chan struct{}, 1) // 节点表变化时立即触发一轮探测

	cpuSamplerGlobal cpuSampler // CPU 占用率需要两次采样求差

	revokedMu  sync.Mutex
	revokedIDs = map[api.NodeID]bool{} // controller 下发的撤销名单（数据面自保）
)

// sniffConn 在数据面 UDP socket 外截流 WHOAMI 回复，其余包交给 QUIC。
type sniffConn struct {
	*net.UDPConn
	whoamiCh chan []byte
}

// sniff 判断一个数据包是不是 controller 的 WHOAMI 回声，是则投进
// whoamiCh 并返回 true（该包不应再交给 QUIC）。
func (c *sniffConn) sniff(p []byte) bool {
	if len(p) < 6 || string(p[:6]) != "FFWHO1" {
		return false
	}
	b := make([]byte, len(p))
	copy(b, p)
	select {
	case c.whoamiCh <- b:
	default:
	}
	return true
}

func (c *sniffConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		n, addr, err := c.UDPConn.ReadFromUDP(p)
		if err != nil {
			return n, addr, err
		}
		if c.sniff(p[:n]) {
			continue // 不交给 QUIC
		}
		return n, addr, err
	}
}

// ReadMsgUDP 必须显式实现：sniffConn 内嵌 *net.UDPConn，ReadMsgUDP 会被
// 提升，于是它满足 quic-go 的 OOBCapablePacketConn，quic-go 会**直接
// 调用 ReadMsgUDP** 而完全绕过上面的 ReadFrom——WHOAMI 回声因此被当成
// QUIC 垃圾包丢弃，myPublic 永远为空（每个 agent 每 25s 刷一行超时）。
// 这里显式覆盖，既保留 ECN/批量读优化，又让嗅探真正生效。
func (c *sniffConn) ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error) {
	for {
		n, oobn, flags, addr, err = c.UDPConn.ReadMsgUDP(b, oob)
		if err != nil {
			return
		}
		if c.sniff(b[:n]) {
			continue
		}
		return
	}
}

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
	nodeCert = *cert
	tlsConf = &tls.Config{
		Certificates: []tls.Certificate{*cert},
		RootCAs:      rootPool,
		MinVersion:   tls.VersionTLS13,
	}
	if err := loadSignPub(); err != nil {
		return err
	}
	transfer.SetKeyDeliverer(func(grantID string, material []byte) error {
		return hbClient.PostKeypass(grantID, material)
	})
	transfer.SetKeyFetcher(func(grantID string) ([]byte, error) {
		return hbClient.GetKeypass(grantID)
	})
	transfer.SetInboxRoot(cfg.DataDir)
	if len(cfg.AllowedDirs) > 0 {
		guard, gerr := transfer.NewPathGuard(cfg.AllowedDirs)
		if gerr != nil {
			return gerr
		}
		transfer.SetPathGuard(guard)
		log.Printf("路径白名单：%v", cfg.AllowedDirs)
	}
	// 给控制面请求设总超时：之前没有 Timeout，TCP 半开时心跳 goroutine
	// 会永久阻塞——节点被判离线且永远不会自愈（连重连都不做）。
	hbClient = &api.Client{Base: cfg.Controller, HC: &http.Client{
		Timeout:   20 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsConf, IdleConnTimeout: 60 * time.Second},
	}}
	running = map[string]bool{}
	punched = map[string]string{}
	log.Printf("agent %s 就绪（controller=%s）", nodeID, cfg.Controller)

	if shareDir() != "" {
		go indexLoop()
	}

	// 2. 数据面：共享 Transport（同一 UDP socket 上监听与拨号）。
	//    必须**先**把 udpConn 建好再起后台循环——whoamiLoop/tryPunch
	//    都直接用 udpConn；之前先起 goroutine 后赋值，启动瞬间是 nil，
	//    实测 30 次启动有 19 次 nil 解引用 panic（约 63%）。
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
	rawUDP, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	if err := rawUDP.SetReadBuffer(4 << 20); err == nil {
		_ = rawUDP.SetWriteBuffer(4 << 20)
	}
	// 嗅探外壳 + Transport：外壳截流 WHOAMI 回复，Transport 在同一
	// socket 上多路分解全部 QUIC 连接（监听 + 拨号）——监听/拨号/
	// WHOAMI 真正共用一个 socket，NAT 映射才对得上号
	udpConn = &sniffConn{UDPConn: rawUDP, whoamiCh: make(chan []byte, 4)}
	tr := &quic.Transport{Conn: udpConn}
	transfer.SetTransport(tr)
	ln, err := tr.Listen(serverTLS, &quic.Config{
		MaxIdleTimeout:                 30 * time.Second,
		InitialStreamReceiveWindow:     8 << 20,
		MaxStreamReceiveWindow:         16 << 20,
		InitialConnectionReceiveWindow: 16 << 20,
		MaxConnectionReceiveWindow:     32 << 20,
	})
	if err != nil {
		return err
	}
	defer ln.Close()
	defer rawUDP.Close()
	tcpLn, err := tls.Listen("tcp", fmt.Sprintf(":%d", cfg.DataPort+1), serverTLS)
	if err != nil {
		log.Printf("TCP 回退监听失败（仅 QUIC 可用）：%v", err)
	} else {
		defer tcpLn.Close()
	}

	// 3. 后台循环：心跳 / 探测 / WHOAMI 保活 / 证书续期。
	//    放在数据面就绪之后，保证它们用到的 udpConn 一定非 nil。
	go heartbeatLoop()
	go probeLoop()
	go whoamiLoop()
	go certRenewLoop()

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
		Timeout:   15 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}},
	}}
	// 请求一个稳定节点名：优先 node-name 配置，否则用主机名。
	// 显式配置时严格校验、非法直接失败——静默改名会让运维以为节点叫
	// A 而实际叫 B。主机名不受我们控制，交给 controller 侧宽松处理。
	wantName := cfg.NodeName
	if wantName != "" {
		if err := api.ValidateNodeName(wantName); err != nil {
			return nil, nil, fmt.Errorf("agent.yaml 的 node-name 非法: %w", err)
		}
	} else {
		wantName = hostname
	}
	resp, err := cl.Enroll(api.EnrollRequest{
		Token:    cfg.EnrollToken,
		Hostname: hostname,
		Addr:     advertisedAddr(),
		NodeName: wantName,
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

// verifyGrant 在数据面本地验签：签名有效、未过期。身份匹配由各
// 路径自查：接收端查 Dst==selfID，中继查在路径上，交换台查参与方。
// isRevoked 报告节点是否已被 controller 撤销。
func isRevoked(id api.NodeID) bool {
	revokedMu.Lock()
	defer revokedMu.Unlock()
	return revokedIDs[id]
}

func verifyGrant(g *api.TransferGrant) bool {
	if isRevoked(g.Src) || isRevoked(g.Dst) {
		log.Printf("[verify] 拒绝 %s：参与方已撤销（src=%q dst=%q）", g.ID, g.Src, g.Dst)
		return false
	}
	for _, sp := range g.Sources {
		if isRevoked(sp.NodeID) {
			log.Printf("[verify] 拒绝 %s：源 %q 已撤销", g.ID, sp.NodeID)
			return false
		}
	}
	for _, h := range g.Hops {
		if isRevoked(h.NodeID) {
			log.Printf("[verify] 拒绝 %s：路径节点 %q 已撤销", g.ID, h.NodeID)
			return false
		}
	}
	ok := g.Verify(signPub)
	exp := time.Now().Before(g.ExpiresAt)
	if !ok || !exp {
		log.Printf("[verify] 拒绝 %s：签名%v 过期%v（stream=%d retries=%d hops=%d src=%q dst=%q exp=%s）",
			g.ID, ok, exp, g.Streams, g.Retries, len(g.Hops), g.Src, g.Dst, g.ExpiresAt.Format(time.RFC3339))
	}
	return ok && exp
}

// advertisedAddr 返回对外广播的数据面地址：优先显式配置，
// 否则取"通往 controller 方向"的本机源 IP。
func advertisedAddr() string {
	if cfg.Advertise != "" {
		return cfg.Advertise
	}
	return fmt.Sprintf("%s:%d", localIPTowardsController(), cfg.DataPort)
}

// dueReport 带时效的积压回报：陈年失败回报被补发会触发 controller
// 的 autoRetry 风暴（压测实锤）——超期直接丢弃。
type dueReport struct {
	req api.DoneRequest
	at  time.Time
}

// reportDone 发任务回报；失败（如断网）入队由心跳循环补发——
// controller 依赖失败回报触发断点续传的重签发。积压超过 10 分钟
// 视为陈旧丢弃（那时 controller 早已按超时处理或任务已无意义）。
func reportDone(req api.DoneRequest) {
	if err := hbClient.JobDone(req); err != nil {
		mu.Lock()
		dueRep = append(dueRep, dueReport{req: req, at: time.Now()})
		mu.Unlock()
	}
}

// certRenewLoop 证书临期自动续期：余量 <8h 时用现有证书身份向
// controller 换新证书（同 nodeID），落盘后自我重启（exec）生效。
func certRenewLoop() {
	check := func() (time.Duration, error) {
		b, err := os.ReadFile(filepath.Join(cfg.DataDir, "node.crt"))
		if err != nil {
			return 0, err
		}
		block, _ := pem.Decode(b)
		if block == nil {
			return 0, fmt.Errorf("node.crt 非法")
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return 0, err
		}
		return time.Until(c.NotAfter), nil
	}
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		left, err := check()
		if err != nil {
			log.Println("证书检查失败：", err)
		} else if left < 8*time.Hour {
			resp, err := hbClient.Renew()
			if err != nil {
				log.Println("证书续期失败（稍后重试）：", err)
			} else {
				if err := os.WriteFile(filepath.Join(cfg.DataDir, "node.crt"), []byte(resp.CertPEM), 0o600); err != nil {
					log.Fatal("续期证书写盘失败：", err)
				}
				if err := os.WriteFile(filepath.Join(cfg.DataDir, "node.key"), []byte(resp.KeyPEM), 0o600); err != nil {
					log.Fatal("续期私钥写盘失败：", err)
				}
				log.Printf("证书已续期（nodeID=%s），自我重启生效", resp.NodeID)
				// exec 要求绝对路径：启动时的相对路径换目录后会失败
				exe, err := os.Executable()
				if err != nil {
					exe = os.Args[0]
				}
				syscall.Exec(exe, append([]string{exe}, os.Args[1:]...), os.Environ()) // 原地重启
			}
		}
		<-t.C
	}
}

// shareDir 返回多源共享目录：显式配置 > 第一个 allowed-dir > 空。
func shareDir() string {
	if cfg.ShareDir != "" {
		return cfg.ShareDir
	}
	transfer.SetKeyDeliverer(func(grantID string, material []byte) error {
		return hbClient.PostKeypass(grantID, material)
	})
	transfer.SetKeyFetcher(func(grantID string) ([]byte, error) {
		return hbClient.GetKeypass(grantID)
	})
	if len(cfg.AllowedDirs) > 0 {
		return cfg.AllowedDirs[0]
	}
	return ""
}

// indexLoop 定期扫描共享目录并向 controller 上报文件索引。哈希缓存
// 在 data-dir（size+mtime 命中不重算），大文件的哈希只算一次。
func indexLoop() {
	dir := shareDir()
	type cached struct {
		Size  int64  `json:"size"`
		Mtime int64  `json:"mtime"`
		SHA   string `json:"sha256"`
	}
	cachePath := filepath.Join(cfg.DataDir, "index-cache.json")
	cache := map[string]cached{}
	if b, err := os.ReadFile(cachePath); err == nil {
		json.Unmarshal(b, &cache)
	}
	save := func() {
		if b, err := json.Marshal(cache); err == nil {
			os.WriteFile(cachePath, b, 0o600)
		}
	}
	scan := func() {
		entries := []api.IndexEntry{}
		filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || strings.HasPrefix(d.Name(), ".ff-") {
				return nil // 跳过临时文件
			}
			info, err := d.Info()
			if err != nil {
				return nil
			}
			key := p
			c, hit := cache[key]
			if !hit || c.Size != info.Size() || c.Mtime != info.ModTime().Unix() {
				f, err := os.Open(p)
				if err != nil {
					return nil
				}
				h := sha256.New()
				io.Copy(h, f)
				f.Close()
				c = cached{info.Size(), info.ModTime().Unix(), hex.EncodeToString(h.Sum(nil))}
				cache[key] = c
			}
			entries = append(entries, api.IndexEntry{
				Path: p, Size: c.Size, Mtime: c.Mtime, SHA256: c.SHA,
			})
			return nil
		})
		save()
		if err := hbClient.Index(api.IndexReport{NodeID: nodeID, Entries: entries}); err != nil {
			log.Println("索引上报失败：", err)
		} else {
			log.Printf("索引已上报：%d 个文件", len(entries))
		}
	}
	scan()
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for range t.C {
		scan()
	}
}

func heartbeatLoop() {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for range t.C {
		cpu := cpuSamplerGlobal.pct()
		mem := memPct()
		free := diskFree(cfg.DataDir)
		mu.Lock()
		active := len(running)
		hb := api.Heartbeat{
			NodeID:        nodeID,
			Hostname:      hostname,
			Addr:          advertisedAddr(),
			Public:        myPublic,
			Edges:         edges,
			TS:            time.Now(),
			CPUPct:        cpu,
			MemPct:        mem,
			DiskFreeBytes: free,
			ActiveXfers:   active,
		}
		mu.Unlock()
		resp, err := hbClient.Heartbeat(hb)
		if err != nil {
			log.Println("心跳失败：", err)
			continue
		}
		mu.Lock()
		backlog := dueRep
		dueRep = nil
		mu.Unlock()
		for i, r := range backlog { // 网络恢复：补发新鲜积压，丢弃陈年
			if time.Since(r.at) > 10*time.Minute {
				continue
			}
			if err := hbClient.JobDone(r.req); err != nil {
				// 只把当前一条放回会让后面未发的整段凭空消失
				// （之前 break 之前没有把 backlog[i+1:] 收回来）。
				mu.Lock()
				dueRep = append(append([]dueReport{}, backlog[i:]...), dueRep...)
				mu.Unlock()
				break
			}
		}
		mu.Lock()
		changed := !samePeerSet(peers, resp.Peers)
		peers = resp.Peers
		mu.Unlock()
		if resp.Revoked != nil { // 全量替换
			revokedMu.Lock()
			fresh := make(map[api.NodeID]bool, len(resp.Revoked))
			for _, id := range resp.Revoked {
				fresh[id] = true
			}
			revokedIDs = fresh
			revokedMu.Unlock()
		}
		if changed {
			select {
			case probeNow <- struct{}{}:
			default:
			}
		}
		for i := range resp.Jobs {
			go runJob(resp.Jobs[i])
		}
		for _, d := range resp.Punches {
			log.Printf("收到打洞指令：对端 %s（%s）", d.Peer, d.Addr)
			go tryPunch(d)
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

// whoamiLoop 从**数据面 socket**（经嗅探外壳）向 controller 回声口
// 周期发签名 WHOAMI——必须从这个 socket 发，NAT 映射才是数据面的
// 映射；回复由嗅探外壳截流回来。保持映射鲜活并得知自己的公网地址。
func whoamiLoop() {
	echoAddr, err := controllerEchoAddr()
	if err != nil {
		log.Println("WHOAMI 不启动：", err)
		return
	}
	t := time.NewTicker(25 * time.Second)
	defer t.Stop()
	send := func() {
		if udpConn == nil { // 防御：数据面尚未就绪
			return
		}
		pkt, err := nat.Build(nodeID, nodeCert, time.Now())
		if err != nil {
			return
		}
		raddr, err := net.ResolveUDPAddr("udp", echoAddr)
		if err != nil {
			return
		}
		// 丢弃上一轮遗留的回声，避免读到陈旧的公网映射
	drain:
		for {
			select {
			case <-udpConn.whoamiCh:
			default:
				break drain
			}
		}
		if _, err := udpConn.WriteTo(pkt, raddr); err != nil {
			log.Println("WHOAMI 发送失败：", err)
			return
		}
		select {
		case reply := <-udpConn.whoamiCh:
			if pub, ok := nat.ParseEchoReply(reply); ok {
				mu.Lock()
				myPublic = pub // 观测到的 ip:port 原样使用——端口就是
				// 数据面 socket 的 NAT 映射端口
				mu.Unlock()
			}
		case <-time.After(3 * time.Second):
			log.Println("WHOAMI 超时未收到回声（", echoAddr, "）")
		}
	}
	send()
	for range t.C {
		send()
	}
}

// controllerEchoAddr 回声口地址 = controller 主机 + (控制端口+1)。
func controllerEchoAddr() (string, error) {
	u, err := url.Parse(cfg.Controller)
	if err != nil || u.Hostname() == "" {
		return "", fmt.Errorf("controller 地址解析失败")
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	p, err := strconvAtoi(port)
	if err != nil {
		return "", err
	}
	return net.JoinHostPort(u.Hostname(), fmt.Sprintf("%d", p+1)), nil
}

func strconvAtoi(s string) (int, error) {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("bad port %q", s)
		}
		n = n*10 + int(c-'0')
	}
	return n, nil
}

func hostOf(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return hostport
}

// tryPunch 执行一次打洞：向对方公网映射持续发开洞包（本 socket 的
// NAT 放行记录），同时从同一 socket 反复 QUIC 探测——握手包本身
// 就是打洞包。成功则把该地址登记为探测目标，由常规探测维持这条边。
func tryPunch(d api.PunchDirective) {
	mu.Lock()
	if _, ok := punched[d.Peer]; ok {
		mu.Unlock()
		return // 已有直连，无需再打
	}
	mu.Unlock()

	if udpConn == nil { // 防御：数据面尚未就绪
		return
	}
	go transfer.SendOpeners(udpConn, d.Addr, 8*time.Second)
	targets := []string{d.Addr}
	if d.Private != "" && d.Private != d.Addr {
		targets = append(targets, d.Private)
	}
	for i := 0; i < 10; i++ {
		for _, tgt := range targets {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			rtt, _, err := transfer.Probe(ctx, tgt, tlsConf)
			cancel()
			if err == nil {
				mu.Lock()
				punched[d.Peer] = tgt
				mu.Unlock()
				log.Printf("打洞成功：%s（%s，rtt %s）", d.Peer, tgt, rtt.Round(time.Millisecond))
				select { // 立即探测一轮，让新边尽快上图
				case probeNow <- struct{}{}:
				default:
				}
				return
			}
		}
		time.Sleep(600 * time.Millisecond)
	}
	log.Printf("打洞失败：%s（NAT 类型不支持或防火墙拦截，走中继兜底）", d.Peer)
}

// runJob 执行一次任务。角色由 grant 与自身身份的关系决定：
// 交换台模式下目的端也要出站接入（derp 式，NAT 不构成障碍）。
func runJob(g api.TransferGrant) {
	if g.Dst == nodeID && g.Mode == "switch" {
		runSwitchRecv(g)
		return
	}
	// 身份检查：主源（Src）或多源分片源（Sources 含本机）都接受——
	// 副源也是任务的主人，不能在多源分片检查之前丢弃（M8 集成顺序 bug）
	mineIdx := -1
	for i, sp := range g.Sources {
		if sp.NodeID == nodeID {
			mineIdx = i
			break
		}
	}
	if g.Src != nodeID && mineIdx < 0 {
		log.Printf("[trace] 忽略任务 %s：既非 Src(%s) 也非分片源", g.ID, g.Src)
		return
	}
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

	startTime := time.Now()
	sentBytes := int64(0)
	done := func(ok bool, errStr string) {
		d := time.Since(startTime).Seconds()
		reportDone(api.DoneRequest{
			GrantID: g.ID, NodeID: nodeID, OK: ok, Err: errStr,
			Bytes: sentBytes, Duration: d,
		})
	}

	sigOK := g.Verify(signPub)
	expOK := time.Now().Before(g.ExpiresAt)
	if !sigOK || !expOK {
		log.Printf("[trace] 任务 %s 被拒：签名无效=%v 过期=%v（本机 %s vs 授权至 %s）",
			g.ID, !sigOK, !expOK, time.Now().Format(time.RFC3339), g.ExpiresAt.Format(time.RFC3339))
		done(false, "grant 验签失败或已过期")
		return
	}
	// 取件落盘映射：inbox: 前缀 → 本机 data-dir/inbox/（安全：不能让
	// 远端指定任意本机路径）
	// 注意：inbox: 映射只在接收端做（transfer.groupFor）。源端绝不能
	// 改写 DstPath——grant 是要原样转发给目的端验签的。
	if strings.HasPrefix(g.DstPath, "inbox:") {
		if _, err := transfer.SafeInboxPath(cfg.DataDir, g.DstPath); err != nil {
			log.Printf("[trace] 任务 %s 被拒：%v", g.ID, err)
			done(false, err.Error())
			return
		}
	}
	log.Printf("[trace] 任务 %s 开始执行：sources=%d mode=%q", g.ID, len(g.Sources), g.Mode)
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
	// 多源模式：本节点只发自己分到的块区间 [Start, End)；单源模式
	// 发全文件。找不到自己的分片则忽略（这份 grant 是发给别的源的）。
	var startCh, endCh int64 = 0, -1
	var hopAddr, hopProto, sendPath string
	sendPath = g.SrcPath
	via := ""
	switch {
	case len(g.Sources) > 0:
		if mineIdx < 0 {
			log.Printf("[trace] 忽略任务 %s：本机不在分片列表", g.ID)
			return // 不是我的分片
		}
		startCh, endCh = g.Sources[mineIdx].Start, g.Sources[mineIdx].End
		hopAddr, hopProto = g.Sources[mineIdx].Addr, g.Sources[mineIdx].Proto
		sendPath = g.Sources[mineIdx].Path // 各副本本地路径不同
		via = fmt.Sprintf("（多源分片 [%d,%d)）", startCh, endCh)
	case g.Mode == "switch":
		hopAddr, hopProto = g.Hops[1].Addr, g.Hops[1].Proto
		via = fmt.Sprintf("（经 %s 交换台对接）", g.Hops[1].NodeID)
	default:
		hopAddr, hopProto = g.Hops[1].Addr, g.Hops[1].Proto
		if len(g.Hops) > 2 {
			ids := make([]string, 0, len(g.Hops)-2)
			for _, h := range g.Hops[1 : len(g.Hops)-1] {
				ids = append(ids, h.NodeID)
			}
			via = "（经 " + strings.Join(ids, " -> ") + " 中继）"
		}
	}
	if !transfer.PathAllowed(sendPath) {
		log.Printf("[trace] 任务 %s 被拒：源路径不在白名单 %s", g.ID, sendPath)
		done(false, "源路径不在白名单内")
		return
	}
	// switch 模式建流走配对；直连/多源直接拨
	var open transfer.StreamOpener
	if g.Mode == "switch" {
		open = transfer.OpenerSwitch(ctx, g.Hops[1], tlsConf, &g)
	} else {
		hop := api.Hop{NodeID: g.Dst, Addr: hopAddr, Proto: hopProto}
		open = transfer.OpenerDirect(ctx, hop, tlsConf)
	}
	sentBytes, err := transfer.SendFileRange(ctx, sendPath, open, tlsConf, &g, startCh, endCh)
	if err != nil {
		done(false, err.Error())
		log.Printf("任务 %s 失败：%v", g.ID, err)
		return
	}
	done(true, "")
	log.Printf("任务 %s 完成：%s -> %s%s（耗时 %s）", g.ID, g.SrcPath, g.Dst, via, time.Since(startTime).Round(time.Millisecond))
}

// runSwitchRecv 交换台模式的目的端：按 grant.Streams 出站拨向交换台
// 配对，每条连接独立接收一个份额（与发送端的并行连接一一配对）。
func runSwitchRecv(g api.TransferGrant) {
	mu.Lock()
	if running["recv-"+g.ID] {
		mu.Unlock()
		return
	}
	running["recv-"+g.ID] = true
	mu.Unlock()
	defer func() {
		mu.Lock()
		delete(running, "recv-"+g.ID)
		mu.Unlock()
	}()

	if !g.Verify(signPub) || g.Dst != nodeID || len(g.Hops) < 2 {
		log.Printf("接收任务 %s 验签失败", g.ID)
		return
	}
	timeout := time.Until(g.ExpiresAt)
	if timeout > 30*time.Minute {
		timeout = 30 * time.Minute
	}
	n := g.Streams
	if n < 1 {
		n = 1
	}
	start := time.Now()
	var wg sync.WaitGroup
	var fail int32
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			if err := switchRecvShare(ctx, g); err != nil {
				atomic.AddInt32(&fail, 1)
				log.Printf("接收任务 %s 份额失败：%v", g.ID, err)
			}
		}()
	}
	wg.Wait()
	if fail > 0 {
		log.Printf("接收任务 %s 失败（%d/%d 份额失败）", g.ID, fail, n)
		return
	}
	log.Printf("接收完成：%s（src=%s，交换台 %s，耗时 %s）", g.ID, g.Src, g.Hops[1].NodeID, time.Since(start).Round(time.Millisecond))
}

// switchRecvShare 接入交换台并按标准 FFJ1 逻辑接收一个连接份额。
func switchRecvShare(ctx context.Context, g api.TransferGrant) error {
	stream, closeConn, err := transfer.DialSwitch(ctx, g.Hops[1].Addr, g.Hops[1].Proto, tlsConf, &g)
	if err != nil {
		return err
	}
	defer closeConn()

	head := make([]byte, 4)
	if _, err := io.ReadFull(stream, head); err != nil {
		return err
	}
	if string(head) != "FFJ1" {
		return fmt.Errorf("非传输流 %q", head)
	}
	br := bufio.NewReader(stream)
	line, err := br.ReadString('\n')
	if err != nil {
		return err
	}
	var gg api.TransferGrant
	if err := json.Unmarshal([]byte(line), &gg); err != nil || gg.ID != g.ID {
		return fmt.Errorf("grant 不符")
	}
	transfer.RecvStream(br, stream, &gg, tlsConf.RootCAs)
	// ACK 已写入流：只半关写侧，等对端读走、对端关闭后再退出，
	// 避免 QUIC 立即关连接丢弃未送达的 ACK
	transfer.CloseWrite(stream)
	if s, ok := stream.(interface{ SetReadDeadline(time.Time) error }); ok {
		s.SetReadDeadline(time.Now().Add(60 * time.Second))
	}
	io.ReadFull(stream, make([]byte, 1))
	return nil
}

// probeLoop 探测所有目标：广播地址（节点表）+ 打洞公网映射。
// 对打洞地址的探测本身就是 NAT 保活。触发：目标变化或 30 秒兜底。
func probeLoop() {
	runRound := func() {
		type target struct {
			id   api.NodeID
			addr string
		}
		mu.Lock()
		byID := make(map[api.NodeID]string, len(peers)+len(punched))
		for id, addr := range punched {
			byID[id] = addr // 打洞地址优先（已知可通）
		}
		for _, p := range peers {
			if p.ID != nodeID {
				if _, ok := byID[p.ID]; !ok {
					byID[p.ID] = p.Addr
				}
			}
		}
		targets := make([]target, 0, len(byID))
		for id, addr := range byID {
			targets = append(targets, target{id, addr})
		}
		mu.Unlock()
		var (
			wg      sync.WaitGroup
			muEdges sync.Mutex
			found   []api.EdgeReport
		)
		for _, tg := range targets {
			wg.Add(1)
			go func(tg target) {
				defer wg.Done()
				ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
				defer cancel()
				rtt, proto, alt, err := transfer.ProbeWithAlt(ctx, tg.addr, tlsConf)
				if err != nil {
					log.Printf("探测 %s(%s) 失败：%v", tg.id, tg.addr, err)
					return
				}
				muEdges.Lock()
				found = append(found, api.EdgeReport{To: tg.id, RTTms: float64(rtt.Microseconds()) / 1000.0, Proto: proto, Addr: tg.addr, AltProto: alt})
				muEdges.Unlock()
			}(tg)
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
// 下即 Tailscale IP，其他节点都能直连）。用 UDP 拨号探测——不实际
// 发包、只查路由决策，对端零噪音（TCP 拨 TLS 口再挂断会在 controller
// 日志里留一串假扫描记录）。取不到时退化为公网出口 IP。
func localIPTowardsController() string {
	if u, err := url.Parse(cfg.Controller); err == nil {
		if host := u.Hostname(); host != "" {
			port := u.Port()
			if port == "" {
				port = "443"
			}
			if c, err := net.Dial("udp", net.JoinHostPort(host, port)); err == nil {
				defer c.Close()
				if addr, ok := c.LocalAddr().(*net.UDPAddr); ok {
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
