// Package api 定义 controller 的 REST 协议类型与客户端，
// agent 和 ffctl 共用。
package api

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type NodeID = string

// EdgeReport 是一次探测的结果：本节点到 To 方向主动可达。
// RTT 单位毫秒，Proto 为 "quic" 或 "tcp"（M3 探测循环产出，
// TCP 是 UDP 被防火墙拦截时的回退通道）。
type EdgeReport struct {
	To    NodeID  `json:"to"`
	RTTms float64 `json:"rtt_ms"`
	Proto string  `json:"proto"`
}

// Heartbeat 是 agent 每 5 秒上报的实时负载与可达性快照，
// 是拓扑图和负载调度的唯一数据源。
type Heartbeat struct {
	NodeID        NodeID       `json:"node_id"`
	Hostname      string       `json:"hostname"`
	Addr          string       `json:"addr"` // 数据面地址 host:port（QUIC）
	CPUPct        float64      `json:"cpu_pct"`
	MemPct        float64      `json:"mem_pct"`
	DiskFreeBytes uint64       `json:"disk_free_bytes"`
	NICBps        float64      `json:"nic_bps"`
	ActiveXfers   int          `json:"active_xfers"`
	Edges         []EdgeReport `json:"edges"`
	TS            time.Time    `json:"ts"`
}

// LoadPct 汇总负载水位，供拓扑调度作边权。
func (h Heartbeat) LoadPct() float64 { return (h.CPUPct + h.MemPct) / 2 }

// PeerInfo 是心跳响应里下发的在线节点信息，供 agent 互相探测。
type PeerInfo struct {
	ID   NodeID `json:"id"`
	Addr string `json:"addr"` // 数据面地址 host:port（QUIC）
}

// HeartbeatResponse 是心跳的响应：下发给该节点的待执行任务与
// 全网在线节点列表（agent 只需出站连接 controller，天然过 NAT）。
type HeartbeatResponse struct {
	Jobs   []TransferGrant `json:"jobs"`
	Peers  []PeerInfo      `json:"peers"`
}

// EnrollRequest / EnrollResponse：一次性 token 换取本节点证书与根证书。
// Addr 是本机数据面地址（host:port），其 IP 会被写进证书 SAN——
// 对端按 IP 拨号时 TLS 校验依赖它。
type EnrollRequest struct {
	Token    string `json:"token"`
	Hostname string `json:"hostname"`
	Addr     string `json:"addr"`
}

type EnrollResponse struct {
	NodeID     string `json:"node_id"`
	CertPEM    string `json:"cert_pem"`
	KeyPEM     string `json:"key_pem"`
	RootPEM    string `json:"root_pem"`
	SignPubPEM string `json:"sign_pub_pem"` // grant 验签公钥
}

// DoneRequest 是 agent 回报任务执行结果。
type DoneRequest struct {
	GrantID string `json:"grant_id"`
	NodeID  NodeID `json:"node_id"`
	OK      bool   `json:"ok"`
	Err     string `json:"err,omitempty"`
}

// TransferRequest 是 ffctl 发起的按需传输请求。
type TransferRequest struct {
	Src       NodeID `json:"src"`
	SrcPath   string `json:"src_path"`
	Dst       NodeID `json:"dst"`
	DstPath   string `json:"dst_path"`
	RateLimit int64  `json:"rate_limit_bps"` // 0 = 不限速
}

// TransferGrant 是 controller 签名的单次传输授权：写明源、目的、
// 中继链、文件摘要、限速与过期时间。节点用 controller 公钥本地
// 验签，全程不共享任何密钥。
type TransferGrant struct {
	ID         string    `json:"id"`
	Src        NodeID    `json:"src"`
	Dst        NodeID    `json:"dst"`
	DstAddr    string    `json:"dst_addr"` // 目的端数据面地址（直连场景；中继链地址 M3 补）
	Relays     []NodeID  `json:"relays"`
	SrcPath    string    `json:"src_path"`
	DstPath    string    `json:"dst_path"`
	FileSHA256 string    `json:"file_sha256"`
	ChunkSize  int       `json:"chunk_size"`
	RateLimit  int64     `json:"rate_limit_bps"`
	ExpiresAt  time.Time `json:"expires_at"`
	Sig        string    `json:"sig"` // ed25519，覆盖以上所有字段
}

// payload 返回待签名字节（不含 Sig 本身）。
func (g *TransferGrant) payload() []byte {
	g2 := *g
	g2.Sig = ""
	b, _ := json.Marshal(g2)
	return b
}

func (g *TransferGrant) Sign(priv ed25519.PrivateKey) {
	g.Sig = hex.EncodeToString(ed25519.Sign(priv, g.payload()))
}

func (g *TransferGrant) Verify(pub ed25519.PublicKey) bool {
	sig, err := hex.DecodeString(g.Sig)
	if err != nil {
		return false
	}
	return ed25519.Verify(pub, g.payload(), sig)
}

// Client 是 controller 的 HTTP 客户端；enroll 阶段可不带证书调用。
type Client struct {
	Base string
	HC   *http.Client
}

func (c *Client) post(path string, req, resp any) error {
	b, err := json.Marshal(req)
	if err != nil {
		return err
	}
	r, err := c.HC.Post(c.Base+path, "application/json", bytes.NewReader(b))
	if err != nil {
		return err
	}
	defer r.Body.Close()
	body, _ := io.ReadAll(r.Body)
	if r.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %s", r.Status, string(body))
	}
	if len(body) == 0 {
		return nil // 允许空响应体（如 heartbeat ACK）
	}
	return json.Unmarshal(body, resp)
}

func (c *Client) Enroll(req EnrollRequest) (*EnrollResponse, error) {
	var resp EnrollResponse
	if err := c.post("/v1/enroll", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) Heartbeat(h Heartbeat) (*HeartbeatResponse, error) {
	var resp HeartbeatResponse
	if err := c.post("/v1/heartbeat", h, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) JobDone(req DoneRequest) error {
	var ignored struct{}
	return c.post("/v1/jobdone", req, &ignored)
}

func (c *Client) Get(path string, resp any) error {
	r, err := c.HC.Get(c.Base + path)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	body, _ := io.ReadAll(r.Body)
	if r.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %s", r.Status, string(body))
	}
	if len(body) == 0 {
		return nil
	}
	return json.Unmarshal(body, resp)
}

// Status 拉取全图快照（admin）。
func (c *Client) Status() ([]Heartbeat, error) {
	var out []Heartbeat
	if err := c.Get("/v1/status", &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Client) Send(req TransferRequest) (*TransferGrant, error) {
	var resp TransferGrant
	if err := c.post("/v1/transfer", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// TokenHash 供 controller 存储一次性令牌的摘要。
func TokenHash(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}
