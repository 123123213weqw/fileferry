// ff-agent：每台服务器一个。职责：enrollment（首次）、心跳上报
// （负载 + 可达性）、数据面监听与传输执行。
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
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
}

var (
	cfg   Config
	nodeID    string
	tlsConf   *tls.Config
	hbClient  *api.Client
	hostname  string
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

	// 1. 证书：本地没有就先 enrollment
	cert, rootPool, err := loadOrCreateCert()
	if err != nil {
		return err
	}
	tlsConf = &tls.Config{
		Certificates: []tls.Certificate{*cert},
		RootCAs:      rootPool,
		MinVersion:   tls.VersionTLS13,
	}
	hbClient = &api.Client{Base: cfg.Controller, HC: &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConf}}}
	log.Printf("agent %s 就绪（controller=%s）", nodeID, cfg.Controller)

	// 2. 心跳循环（负载指标 M1 补 /proc 采集；可达性边 M3 探测产出）
	go heartbeatLoop()

	// 3. 数据面：QUIC 监听（TCP 回退 M3）
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", cfg.DataPort))
	if err != nil {
		return err
	}
	udp, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	ln, err := quic.Listen(udp, tlsConf, &quic.Config{MaxIdleTimeout: 30 * time.Second})
	if err != nil {
		return err
	}
	defer ln.Close()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	errCh := make(chan error, 1)
	go func() { errCh <- transfer.Serve(ln, cfg.DataDir) }()
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
	cl := &api.Client{Base: cfg.Controller, HC: &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13},
	}}}
	resp, err := cl.Enroll(api.EnrollRequest{Token: cfg.EnrollToken, Hostname: hostname})
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

func heartbeatLoop() {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for range t.C {
		ip := localIP()
		hb := api.Heartbeat{
			NodeID:   nodeID,
			Hostname: hostname,
			Addr:     fmt.Sprintf("%s:%d", ip, cfg.DataPort),
			TS:       time.Now(),
			// TODO(M1)：/proc 采集 CPU/内存/磁盘/网卡
			// TODO(M3)：探测结果填充 Edges
		}
		if err := hbClient.Heartbeat(hb); err != nil {
			log.Println("心跳失败：", err)
		}
	}
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
