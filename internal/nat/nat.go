// Package nat 实现 M6 打洞的"回声口"：agent 从数据面 socket 发来
// 签名的 WHOAMI 包，controller 回以观测到的公网 ip:port（迷你 STUN）。
// 包带节点证书与 ed25519 签名，验签过 CA 证书链才受理——防止任何
// 扫端口者把节点变成 UDP 喷射器。
package nat

import (
	"bytes"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"time"
)

const (
	magic  = "FFWHO1"
	maxAge = 90 * time.Second // 打洞包时间窗，防重放
)

// Whoami 是回声请求体。签名覆盖 "nodeID|ts"。
type Whoami struct {
	NodeID  string `json:"node_id"`
	TS      int64  `json:"ts"`
	CertB64 string `json:"cert"`
	SigB64  string `json:"sig"`
}

// Build 用本节点证书构造签名请求（agent 侧）。
func Build(nodeID string, cert tls.Certificate, now time.Time) ([]byte, error) {
	priv, ok := cert.PrivateKey.(ed25519.PrivateKey)
	if !ok || len(cert.Certificate) == 0 {
		return nil, fmt.Errorf("nat: 证书缺少 ed25519 私钥")
	}
	ts := now.Unix()
	sig := ed25519.Sign(priv, signPayload(nodeID, ts))
	body, err := json.Marshal(Whoami{
		NodeID:  nodeID,
		TS:      ts,
		CertB64: base64.StdEncoding.EncodeToString(cert.Certificate[0]),
		SigB64:  base64.StdEncoding.EncodeToString(sig),
	})
	if err != nil {
		return nil, err
	}
	return append([]byte(magic+"\n"), append(body, '\n')...), nil
}

func signPayload(nodeID string, ts int64) []byte {
	b := make([]byte, 0, len(nodeID)+8)
	b = append(b, nodeID...)
	var t [8]byte
	binary.BigEndian.PutUint64(t[:], uint64(ts))
	return append(b, t[:]...)
}

// ParseAndVerify 解析并验证请求（controller 侧）：证书链有效、CN 与
// 声明一致、签名正确、时间在窗内。返回节点 ID。
func ParseAndVerify(data []byte, pool *x509.CertPool, now time.Time) (nodeID string, err error) {
	parts := bytes.SplitN(bytes.TrimSpace(data), []byte("\n"), 2)
	if len(parts) != 2 || string(parts[0]) != magic {
		return "", fmt.Errorf("nat: 非 WHOAMI 包")
	}
	var w Whoami
	if err := json.Unmarshal(parts[1], &w); err != nil {
		return "", err
	}
	certDER, err := base64.StdEncoding.DecodeString(w.CertB64)
	if err != nil {
		return "", err
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return "", err
	}
	if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, CurrentTime: now}); err != nil {
		return "", fmt.Errorf("nat: 证书链无效: %w", err)
	}
	if cert.Subject.CommonName != w.NodeID {
		return "", fmt.Errorf("nat: CN 与 nodeID 不符")
	}
	if d := now.Sub(time.Unix(w.TS, 0)); d > maxAge || d < -maxAge {
		return "", fmt.Errorf("nat: 时间戳超出窗口")
	}
	pub, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return "", fmt.Errorf("nat: 证书非 ed25519")
	}
	sig, err := base64.StdEncoding.DecodeString(w.SigB64)
	if err != nil {
		return "", err
	}
	if !ed25519.Verify(pub, signPayload(w.NodeID, w.TS), sig) {
		return "", fmt.Errorf("nat: 签名无效")
	}
	return w.NodeID, nil
}

// EchoServer 在 UDP 端口上应答 WHOAMI，把观测到的公网地址回调给
// controller（公网映射表由 controller 维护，agent 不自行声称）。
type EchoServer struct {
	conn *net.UDPConn
	pool *x509.CertPool
	cb   func(nodeID, publicAddr string)
}

func NewEchoServer(port int, pool *x509.CertPool, cb func(nodeID, public string)) (*EchoServer, error) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: port})
	if err != nil {
		return nil, err
	}
	return &EchoServer{conn: conn, pool: pool, cb: cb}, nil
}

func (s *EchoServer) Serve() error {
	buf := make([]byte, 4096)
	lastDrop := time.Now()
	for {
		n, from, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			return err
		}
		nodeID, err := ParseAndVerify(buf[:n], s.pool, time.Now())
		if err != nil {
			if time.Since(lastDrop) > 10*time.Second { // 公网端口常被扫，限流记日志
				lastDrop = time.Now()
				log.Printf("WHOAMI 丢弃（来自 %s）：%v", from, err)
			}
			continue
		}
		pub := from.String()
		s.cb(nodeID, pub)
		s.conn.WriteToUDP(append([]byte(magic+"\n"), []byte(pub)...), from)
	}
}

func (s *EchoServer) Close() error { return s.conn.Close() }

// ParseEchoReply 解析回声应答（agent 侧）：返回自己的公网映射。
func ParseEchoReply(data []byte) (public string, ok bool) {
	parts := bytes.SplitN(bytes.TrimSpace(data), []byte("\n"), 2)
	if len(parts) != 2 || string(parts[0]) != magic {
		return "", false
	}
	return string(parts[1]), true
}
