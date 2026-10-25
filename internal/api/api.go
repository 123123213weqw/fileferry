// Package api 定义 controller 的 REST 协议类型与客户端，
// agent 和 ffctl 共用。
package api

import (
	"encoding/base64"
	"strings"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"net/http"
	"time"
)

type NodeID = string

// EdgeReport 是一次探测的结果：本节点到 To 方向主动可达。
// RTT 单位毫秒，Proto 为 "quic" 或 "tcp"（TCP 是 UDP 被防火墙
// 拦截时的回退通道）。Addr 是实际拨通的地址——打洞成功的边是
// 对端的公网 NAT 映射，直连边是对端广播的地址，controller 构建
// 传输路径时以此为准（谁探测的谁去拨）。
type EdgeReport struct {
	To    NodeID  `json:"to"`
	RTTms float64 `json:"rtt_ms"`
	Proto string  `json:"proto"`
	Addr  string  `json:"addr"`
	// AltProto：两种协议都通时的副协议（混流用：并行流各占一条
	// 协议通道，叠加两种限速配额）。空 = 只有一种可用。
	AltProto string `json:"alt_proto,omitempty"`
}

// Heartbeat 是 agent 每 5 秒上报的实时负载与可达性快照，
// 是拓扑图和负载调度的唯一数据源。Public 是本节点经 controller
// UDP 回声口得知的自身公网 NAT 映射（agent 不自行声称，controller
// 回填校验），供打洞配对用。
type Heartbeat struct {
	NodeID        NodeID       `json:"node_id"`
	Hostname      string       `json:"hostname"`
	Addr          string       `json:"addr"` // 数据面地址 host:port（QUIC）
	Public        string       `json:"public,omitempty"`
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

// PunchDirective 是 controller 随心跳下发的打洞指令：对端 Peer 的
// 公网 NAT 映射（Addr，来自 controller 的 UDP 回声口）与私网地址
// （Private，同网段时直接可通）。双方同时向对方发包即可在两个
// NAT 上留下放行记录。指令经 mTLS 心跳信道到达，无需额外签名。
type PunchDirective struct {
	Peer     NodeID `json:"peer"`
	Addr     string `json:"addr"`     // 对端公网映射 host:port
	Private  string `json:"private"`  // 对端广播地址 host:port
}

// HeartbeatResponse 是心跳的响应：下发给该节点的待执行任务、
// 全网在线节点表（agent 只需出站连接 controller，天然过 NAT）、
// 以及打洞指令。
type HeartbeatResponse struct {
	Jobs    []TransferGrant   `json:"jobs"`
	Peers   []PeerInfo        `json:"peers"`
	Punches []PunchDirective  `json:"punches"`
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

// DoneRequest 是 agent 回报任务执行结果。Bytes/Duration 用于
// controller 回填路径实测吞吐（多源调度按带宽分配块区间）。
type DoneRequest struct {
	GrantID  string `json:"grant_id"`
	NodeID   NodeID `json:"node_id"`
	OK       bool   `json:"ok"`
	Err      string `json:"err,omitempty"`
	Bytes    int64  `json:"bytes,omitempty"`
	Duration float64 `json:"duration_s,omitempty"`
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
// Hop 是传输路径上的一跳。Proto 记录拨到这一跳用的协议
// （"quic" 或 "tcp"，由前驱节点的探测结果决定）；Hops[0] 是源端，
// 自身的 Addr/Proto 不使用。
type Hop struct {
	NodeID NodeID `json:"node_id"`
	Addr   string `json:"addr"`
	Proto  string `json:"proto"`
}

type TransferGrant struct {
	ID         string    `json:"id"`
	Src        NodeID    `json:"src"`
	Dst        NodeID    `json:"dst"`
	// Mode 为空 = 常规模式（直连或逐跳中继，前驱拨下一跳）；
	// "switch" = 交换台模式：两端各自**出站**拨向 Hops[1] 指定的
	// 交换台节点（DERP 式），交换台把两条现成连接对接。适用于
	// 任何一方都拨不进对方 NAT 的场景。
	Mode       string    `json:"mode,omitempty"`
	Hops       []Hop     `json:"hops"` // 完整路径：源端、各中继/交换台、目的端
	Relays     []NodeID  `json:"relays"`
	// Sources 是 M8 多源并行：文件存在多份副本时，controller 把块
	// 区间按路径带宽分配给各源，目的端同时从多台拉不同块——叠加
	// 各"源-目的对"独立的限速配额。为空时单源（Hops[1]）。每个源
	// 节点收到同一份 grant，各取自己的区间发送。
	Sources    []SourceSpec `json:"sources,omitempty"`
	SrcPath    string    `json:"src_path"`
	DstPath    string    `json:"dst_path"`
	FileSHA256 string    `json:"file_sha256"`
	FileSize   int64     `json:"file_size"`
	ChunkSize  int       `json:"chunk_size"`
	Streams    int       `json:"streams"` // 每源的并行连接数：绕 per-flow 限速、填满带宽延迟积
	RateLimit  int64     `json:"rate_limit_bps"`
	ExpiresAt  time.Time `json:"expires_at"`
	Retries    int       `json:"retries,omitempty"` // 断点续传自动重试代数（上限 3）
	Enc        bool      `json:"enc,omitempty"`    // 端到端加密（密钥经 controller 专递，不进 grant）
	Mix        bool      `json:"mix,omitempty"`    // 混流：偶数流走主协议、奇数流走副协议（TCP+UDP 叠加配额）
	Sig        string    `json:"sig"` // ed25519，覆盖以上所有字段
}

// SourceSpec 是多源 grant 中一个源的分片：负责块区间 [Start, End)。
type SourceSpec struct {
	NodeID NodeID `json:"node_id"`
	Addr   string `json:"addr"`
	Proto  string `json:"proto"`
	Path   string `json:"path"`  // 该源本地的文件路径（各副本路径可不同）
	Start  int64  `json:"start"` // 起始块号（含）
	End    int64  `json:"end"`   // 结束块号（不含）
}

// AllSources 返回参与发送的全部节点 ID（含主源）。
func (g *TransferGrant) AllSources() []NodeID {
	out := []NodeID{g.Src}
	for _, s := range g.Sources {
		if s.NodeID != g.Src {
			out = append(out, s.NodeID)
		}
	}
	return out
}

// payload 返回待签名的规范串（不含 Sig）。手工拼接而非 json.Marshal
// 整个 struct——未来新增字段不进签名，新旧版本互验不破（曾因新增
// Retries 字段导致新旧混编时全网验签失败）。
func (g *TransferGrant) payload() []byte {
	var sb strings.Builder
	sb.WriteString("ff1|")
	sb.WriteString(g.ID)
	sb.WriteByte('|')
	sb.WriteString(string(g.Src))
	sb.WriteByte('|')
	sb.WriteString(string(g.Dst))
	sb.WriteByte('|')
	sb.WriteString(g.Mode)
	sb.WriteByte('|')
	fmt.Fprintf(&sb, "%d|%s|%d|", g.FileSize, g.FileSHA256, g.ChunkSize)
	for _, h := range g.Hops {
		// Proto 不进签名：混流按流改写拨号协议属路由提示，非授权语义
		fmt.Fprintf(&sb, "h:%s,%s;", h.NodeID, h.Addr)
	}
	for _, sp := range g.Sources {
		fmt.Fprintf(&sb, "s:%s,%s,%s,%d,%d;", sp.NodeID, sp.Addr, sp.Path, sp.Start, sp.End)
	}
	sb.WriteString(g.SrcPath)
	sb.WriteByte('|')
	sb.WriteString(g.DstPath)
	fmt.Fprintf(&sb, "|%d|%d|%d|%v|%v", g.Streams, g.Retries, g.ExpiresAt.Unix(), g.Enc, g.Mix)
	return []byte(sb.String())
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

// Post 供 ffctl 等外部调用方使用的通用 POST。
func (c *Client) Post(path string, req, resp any) error { return c.post(path, req, resp) }

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

// JobInfo 是任务查询结果（/v1/jobs）。
type JobInfo struct {
	ID      string `json:"id"`
	Src     string `json:"src"`
	Dst     string `json:"dst"`
	Mode    string `json:"mode,omitempty"`
	Status  string `json:"status"`
	Updated int64  `json:"updated"`
}

// Jobs 查询任务列表；id 为空返回全部（近期），否则精确匹配。
func (c *Client) Jobs(id string) ([]JobInfo, error) {
	var out []JobInfo
	path := "/v1/jobs"
	if id != "" {
		path += "?id=" + url.QueryEscape(id)
	}
	if err := c.Get(path, &out); err != nil {
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
// RenewRequest / RenewResponse：节点证书临期续期，身份由现有
// mTLS 证书证明，新证书沿用同一 nodeID 与角色。
type RenewRequest struct{}

type RenewResponse struct {
	NodeID  string `json:"node_id"`
	CertPEM string `json:"cert_pem"`
	KeyPEM  string `json:"key_pem"`
}

func (c *Client) Renew() (*RenewResponse, error) {
	var resp RenewResponse
	if err := c.post("/v1/renew", RenewRequest{}, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}


// IndexEntry 是 agent 上报的共享目录文件索引（M8 多源副本发现）。
// SHA256 由 agent 后台计算并缓存（size+mtime 不变不重算）。
type IndexEntry struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	Mtime  int64  `json:"mtime"`
	SHA256 string `json:"sha256"`
}

// IndexReport 是全量索引上报（替换该节点的全部旧条目）。
type IndexReport struct {
	NodeID  NodeID       `json:"node_id"`
	Entries []IndexEntry `json:"entries"`
}

func (c *Client) Index(rep IndexReport) error {
	var ignored struct{}
	return c.post("/v1/index", rep, &ignored)
}

func TokenHash(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// Keypass 上报/获取端到端加密密钥材料（key+nonce 前缀）。
func (c *Client) PostKeypass(grantID string, material []byte) error {
	var ignored struct{}
	return c.post("/v1/keypass", map[string]any{
		"grant_id": grantID, "key_b64": base64.StdEncoding.EncodeToString(material),
	}, &ignored)
}

func (c *Client) GetKeypass(grantID string) ([]byte, error) {
	var resp struct {
		KeyB64 string `json:"key_b64"`
	}
	if err := c.Get("/v1/keypass?id="+url.QueryEscape(grantID), &resp); err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(resp.KeyB64)
}
