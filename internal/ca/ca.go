// Package ca 实现内嵌 CA：controller 首次启动生成根证书，为每台
// agent 签发短时效证书，所有连接走 mTLS。根私钥只存在于 controller
// 所在机器，服务器之间不存在任何两两共享的静态密钥——每台机器
// 只持有自己的证书。
package ca

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// CertTTL 是节点证书的有效期；到期前由持有方向 controller 续期（M1 TODO）。
// 管理员证书用 AdminCertTTL：操作者不便每天换证书，靠妥善保管弥补。
const (
	CertTTL     = 24 * time.Hour
	AdminCertTTL = 10 * 365 * 24 * time.Hour
)

type CA struct {
	mu        sync.Mutex
	priv      ed25519.PrivateKey
	rootCert  *x509.Certificate
	rootPEM   []byte
	pool      *x509.CertPool
	serial    int64
}

// LoadOrCreate 读取 dir 下的 ca.key/ca.crt，不存在则生成新的根。
func LoadOrCreate(dir string) (*CA, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("ca dir: %w", err)
	}
	keyPath, crtPath := filepath.Join(dir, "ca.key"), filepath.Join(dir, "ca.crt")
	if kb, err := os.ReadFile(keyPath); err == nil {
		cb, err := os.ReadFile(crtPath)
		if err != nil {
			return nil, err
		}
		return loadFromPEM(kb, cb)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "fileferry-root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(20, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(crtPath, pemEncode("CERTIFICATE", der), 0o644); err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyPath, pemEncode("PRIVATE KEY", keyDER), 0o600); err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return newCA(priv, cert), nil
}

func loadFromPEM(keyPEM, crtPEM []byte) (*CA, error) {
	kb, _ := pem.Decode(keyPEM)
	cb, _ := pem.Decode(crtPEM)
	if kb == nil || cb == nil {
		return nil, fmt.Errorf("ca pem decode failed")
	}
	key, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		return nil, err
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("ca key is not ed25519")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, err
	}
	return newCA(priv, cert), nil
}

func newCA(priv ed25519.PrivateKey, root *x509.Certificate) *CA {
	pool := x509.NewCertPool()
	pool.AddCert(root)
	return &CA{
		priv:     priv,
		rootCert: root,
		rootPEM:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw}),
		pool:     pool,
	}
}

func pemEncode(typ string, b []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: b})
}

// 证书角色：写在 OU 字段里，controller 据此做权限判定。
// admin = 操作者本人（发起传输、看状态）；node = 普通节点（心跳 + 干活）。
const (
	RoleAdmin = "admin"
	RoleNode  = "node"
)

// Issue 为 nodeID 签发一张新证书。server=true 时附带 ServerAuth
// 用途（controller 和数据面监听需要）；role 填 RoleAdmin 或 RoleNode；
// sans 填入对端拨号时使用的地址/主机名（IP 进 IPAddresses，其余进
// DNSNames），否则 TLS 校验会因缺 SAN 失败。返回 PEM 供 enrollment
// 响应下发，tls.Certificate 供本进程直接使用。
func (c *CA) Issue(nodeID string, server bool, role string, sans ...string) (certPEM, keyPEM []byte, cert tls.Certificate, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.serial++
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, cert, err
	}
	eku := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	if server {
		eku = append(eku, x509.ExtKeyUsageServerAuth)
	}
	ttl := CertTTL
	if role == RoleAdmin {
		ttl = AdminCertTTL
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(c.serial + 1),
		Subject:               pkix.Name{CommonName: nodeID, Organization: []string{"fileferry"}, OrganizationalUnit: []string{role}},
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().Add(ttl),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           eku,
	}
	for _, s := range sans {
		if ip := net.ParseIP(s); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, s)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.rootCert, pub, c.priv)
	if err != nil {
		return nil, nil, cert, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, cert, err
	}
	return pemEncode("CERTIFICATE", der), pemEncode("PRIVATE KEY", keyDER),
		tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}, nil
}

// ServerTLS 是数据面/controller 的服务端配置。/v1/enroll 允许
// 无证书访问（由一次性 token 把关），其余请求要求客户端证书。
func (c *CA) ServerTLS(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    c.pool,
		MinVersion:   tls.VersionTLS13,
	}
}

// ClientTLS 是 agent 侧配置：校验对端必须由同一 CA 签发。
func (c *CA) ClientTLS(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      c.pool,
		MinVersion:   tls.VersionTLS13,
	}
}

// NewEnrollToken 生成一次性入网令牌；controller 只保存其 SHA-256，
// 单个令牌泄漏不影响其他节点。
func NewEnrollToken() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "ff_enroll_" + hex.EncodeToString(b), nil
}

func (c *CA) RootPEM() []byte       { return c.rootPEM }
func (c *CA) Pool() *x509.CertPool  { return c.pool }
func (c *CA) RootCert() *x509.Certificate { return c.rootCert }
