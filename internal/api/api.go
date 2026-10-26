// Package api 定义 controller 的 REST 协议类型与客户端，
// agent 和 ffctl 共用。
package api

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type NodeID = string

// EdgeReport 是一次探测的结果：本节点到 To 方向主动可达。
// RTT 单位毫秒，Proto 为 "quic" 或 "tcp"（TCP 是 UDP 被防火墙
// 拦截时的回退通道）。Addr 是实际拨通的地址——打洞成功的边是
// 对端的公网 NAT 映射，直连边是对端广播的地址，controller 构建
// 传输路径时以此为准（谁探测的谁去拨）。
type EdgeReport struct {
	To      NodeID  `json:"to"`
	RTTms   float64 `json:"rtt_ms"`
	Proto   string  `json:"proto"`
	Addr    string  `json:"addr"`
	TCPPort int     `json:"tcp_port,omitempty"`
	// AltProto：两种协议都通时的副协议（混流用：并行流各占一条
	// 协议通道，叠加两种限速配额）。空 = 只有一种可用。
	AltProto string `json:"alt_proto,omitempty"`
}

// Heartbeat 是 agent 每 5 秒上报的实时负载与可达性快照，
// 是拓扑图和负载调度的唯一数据源。Public 是本节点经 controller
// UDP 回声口得知的自身公网 NAT 映射（agent 不自行声称，controller
// 回填校验），供打洞配对用。
type Heartbeat struct {
	NodeID   NodeID `json:"node_id"`
	Hostname string `json:"hostname"`
	Addr     string `json:"addr"` // 数据面地址 host:port（QUIC）
	// TCPPort 是本节点 TCP 数据面的实际端口（0 = 未上报，按 addr 端口+1
	// 推断）。被墙网络里 TCP 常被挪到 443，各节点端口未必相同，所以必须
	// 由节点自己上报，不能靠全局约定。
	TCPPort int `json:"tcp_port,omitempty"`
	// WaitMS 让控制面做长轮询：没有待办任务时不要立刻返回，而是挂住
	// 最多这么多毫秒，一有任务就马上回。没有长轮询时，`ffctl send`
	// 必须等下一次心跳（5s）才会被投递——实测 200MB 传输总耗时 6s，
	// 其中 5s 纯粹是在等心跳。scp 是立即开始的，这里必须对齐。
	WaitMS        int          `json:"wait_ms,omitempty"`
	Public        string       `json:"public,omitempty"`
	CPUPct        float64      `json:"cpu_pct"`
	MemPct        float64      `json:"mem_pct"`
	DiskFreeBytes uint64       `json:"disk_free_bytes"`
	ActiveXfers   int          `json:"active_xfers"`
	Edges         []EdgeReport `json:"edges"`
	TS            time.Time    `json:"ts"`
}

// LoadPct 汇总负载水位，供拓扑调度作边权。
// LoadPct 返回节点负载水位（0-100+）。
//
// 之前只算 CPU 与内存的均值，磁盘水位完全不参与调度——一个磁盘快满的
// 节点照样会被选成中继与目的端，写满后传输失败。现在把"磁盘余量"当
// 一维水位纳入：
//
//	diskPct = 100 - free/2GiB*100   （低于 2GiB 余量开始告警）
//
// 2GiB 是经验阈值：小于它时再大的文件也可能写不进去。
func (h Heartbeat) LoadPct() float64 {
	base := (h.CPUPct + h.MemPct) / 2
	if h.DiskFreeBytes > 0 {
		const reserve = 2 << 30 // 2 GiB
		diskPct := 100.0
		if h.DiskFreeBytes < uint64(reserve) {
			// 余量越少越接近 100；完全没有余量时封顶 100
			diskPct = 100 - float64(h.DiskFreeBytes)/float64(reserve)*100
		} else {
			diskPct = 0
		}
		// 取三者最大：任一维吃紧都应当降低该节点的吸引力
		if diskPct > base {
			return diskPct
		}
	}
	return base
}

// PeerInfo 是心跳响应里下发的在线节点信息，供 agent 互相探测。
type PeerInfo struct {
	ID   NodeID `json:"id"`
	Addr string `json:"addr"` // 数据面地址 host:port（QUIC）
	// TCPPort 是该节点 TCP 数据面的实际端口（0 = 用 Addr 端口+1）。
	TCPPort int `json:"tcp_port,omitempty"`
}

// PunchDirective 是 controller 随心跳下发的打洞指令：对端 Peer 的
// 公网 NAT 映射（Addr，来自 controller 的 UDP 回声口）与私网地址
// （Private，同网段时直接可通）。双方同时向对方发包即可在两个
// NAT 上留下放行记录。指令经 mTLS 心跳信道到达，无需额外签名。
type PunchDirective struct {
	Peer    NodeID `json:"peer"`
	Addr    string `json:"addr"`    // 对端公网映射 host:port
	Private string `json:"private"` // 对端广播地址 host:port
}

// HeartbeatResponse 是心跳的响应：下发给该节点的待执行任务、
// 全网在线节点表（agent 只需出站连接 controller，天然过 NAT）、
// 以及打洞指令。
type HeartbeatResponse struct {
	Jobs    []TransferGrant  `json:"jobs"`
	Peers   []PeerInfo       `json:"peers"`
	Punches []PunchDirective `json:"punches"`
	// Revoked 是已撤销节点名单（全量下发，几十个 ID 的量级）。
	// 数据面据此拒收/拒发：之前撤销只体现在控制面（心跳/续期被拒），
	// 被撤销节点的证书在 24h 内仍能直接把流推向任何目的端。
	Revoked []NodeID `json:"revoked,omitempty"`
}

// EnrollRequest / EnrollResponse：一次性 token 换取本节点证书与根证书。
// Addr 是本机数据面地址（host:port），其 IP 会被写进证书 SAN——
// 对端按 IP 拨号时 TLS 校验依赖它。
type EnrollRequest struct {
	Token    string `json:"token"`
	Hostname string `json:"hostname"`
	Addr     string `json:"addr"`
	// NodeName 是 agent 请求的稳定节点名（来自 node-name 配置，缺省
	// 取主机名）。controller 可用则用之，不可用（重名/非法）才自增编号，
	// 保证重装后身份不漂移。
	NodeName string `json:"node_name,omitempty"`
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
	GrantID  string  `json:"grant_id"`
	NodeID   NodeID  `json:"node_id"`
	OK       bool    `json:"ok"`
	Err      string  `json:"err,omitempty"`
	Bytes    int64   `json:"bytes,omitempty"`
	Duration float64 `json:"duration_s,omitempty"`
	// Proto 是这条数据实际走的协议（"quic"/"tcp"）。controller 据此
	// 记录"每条边每种协议的实测吞吐"，用于后续选路——QUIC 在高丢包
	// 链路上会被基于丢包的拥塞控制压塌（实测 2% 丢包时慢 60 倍），
	// 只有按协议分开记才能学出"这条边该用 tcp"。
	Proto string `json:"proto,omitempty"`
}

// PullEndpoint 是 ffctl 作为**数据面接收端**所需的凭据。
//
// 与 put 相反，pull 时 ffctl 要监听 TLS 并充当服务器，因此需要一张带
// ServerAuth 的证书——管理员证书只带 ClientAuth，直接用会在 TLS 握手
// 阶段被发送方拒绝。controller 为此按需签发一张短时效的传输端点证书。
type PullEndpoint struct {
	NodeID     NodeID `json:"node_id"` // ffctl 的身份（证书 CN）
	CertPEM    string `json:"cert_pem"`
	KeyPEM     string `json:"key_pem"`
	SignPubPEM string `json:"sign_pub_pem"` // 校验授权签名用
	ExpiresAt  int64  `json:"expires_at"`
}

// PullRequest 申请"从远端节点拉取到本机"的授权。
type PullRequest struct {
	NodeID     NodeID `json:"node_id"` // 上面拿到的 ffctl 身份
	Src        NodeID `json:"src"`
	SrcPath    string `json:"src_path"`
	DstPath    string `json:"dst_path"`    // 本机保存路径（目录会自动补源文件名）
	ListenAddr string `json:"listen_addr"` // ffctl 数据面监听地址 host:port
	ListenPort int    `json:"listen_port"` // 实际 TCP 端口
	Streams    int    `json:"streams,omitempty"`
	// PinHash 要求把源节点索引里的摘要钉进授权（强校验）。
	// 默认关闭：索引是定期上报的，文件在两次上报之间被改动就会让
	// 合法传输被拒（实测踩到——agent 启动时索引了同名旧文件）。
	PinHash bool `json:"pin_hash,omitempty"`
}

// PushRequest 是"本机 → 远端节点"直推的申请（等价 scp local host:/path）。
// ffctl 在本地算好摘要与大小一起提交，controller 只负责签授权、给出
// 目标的拨号地址——数据面由 ffctl 直接连目标节点，不经过 controller，
// 也没有"先上传到某个源节点"的中转开销。
type PushRequest struct {
	Dst       NodeID `json:"dst"`
	DstPath   string `json:"dst_path"`
	LocalPath string `json:"local_path"` // 仅用于目标写成目录时补文件名
	SHA256    string `json:"sha256"`
	Size      int64  `json:"size"`
	Streams   int    `json:"streams,omitempty"` // 0 = 默认
	RateLimit int64  `json:"rate_limit_bps"`
}

// TransferRequest 是 ffctl 发起的按需传输请求。
type TransferRequest struct {
	Src       NodeID `json:"src"`
	SrcPath   string `json:"src_path"`
	Dst       NodeID `json:"dst"`
	DstPath   string `json:"dst_path"`
	RateLimit int64  `json:"rate_limit_bps"` // 0 = 不限速
	// Proto 强制数据面协议（"tcp"/"quic"，空=按探测/学习结果）。
	//
	// 存在的理由：被墙网络里 UDP 常被丢包或拦截，QUIC 会静默变慢或不通。
	// 没有这个字段时，`ffctl -proto tcp send ...` 会被**静默忽略**——用户
	// 以为强制了 TCP，实际仍按默认走，排查时会误判成"TCP 也慢"。
	Proto string `json:"proto,omitempty"`
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
	// TCPPort 是该跳 TCP 数据面的实际端口（0 = 用 Addr 端口+1）。
	TCPPort int `json:"tcp_port,omitempty"`
}

type TransferGrant struct {
	ID  string `json:"id"`
	Src NodeID `json:"src"`
	Dst NodeID `json:"dst"`
	// Mode 为空 = 常规模式（直连或逐跳中继，前驱拨下一跳）；
	// "switch" = 交换台模式：两端各自**出站**拨向 Hops[1] 指定的
	// 交换台节点（DERP 式），交换台把两条现成连接对接。适用于
	// 任何一方都拨不进对方 NAT 的场景。
	Mode   string   `json:"mode,omitempty"`
	Hops   []Hop    `json:"hops"` // 完整路径：源端、各中继/交换台、目的端
	Relays []NodeID `json:"relays"`
	// Sources 是 M8 多源并行：文件存在多份副本时，controller 把块
	// 区间按路径带宽分配给各源，目的端同时从多台拉不同块——叠加
	// 各"源-目的对"独立的限速配额。为空时单源（Hops[1]）。每个源
	// 节点收到同一份 grant，各取自己的区间发送。
	Sources    []SourceSpec `json:"sources,omitempty"`
	SrcPath    string       `json:"src_path"`
	DstPath    string       `json:"dst_path"`
	FileSHA256 string       `json:"file_sha256"`
	FileSize   int64        `json:"file_size"`
	ChunkSize  int          `json:"chunk_size"`
	Streams    int          `json:"streams"` // 每源的并行连接数：绕 per-flow 限速、填满带宽延迟积
	RateLimit  int64        `json:"rate_limit_bps"`
	ExpiresAt  time.Time    `json:"expires_at"`
	Retries    int          `json:"retries,omitempty"` // 断点续传自动重试代数（上限 3）
	Enc        bool         `json:"enc,omitempty"`     // 端到端加密（密钥经 controller 专递，不进 grant）
	Mix        bool         `json:"mix,omitempty"`     // 混流：偶数流走主协议、奇数流走副协议（TCP+UDP 叠加配额）
	Sig        string       `json:"sig"`               // ed25519，覆盖以上所有字段
}

// SourceSpec 是多源 grant 中一个源的分片：负责块区间 [Start, End)。
type SourceSpec struct {
	NodeID NodeID `json:"node_id"`
	Addr   string `json:"addr"`
	Proto  string `json:"proto"`
	Path   string `json:"path"`  // 该源本地的文件路径（各副本路径可不同）
	Start  int64  `json:"start"` // 起始块号（含）
	End    int64  `json:"end"`   // 结束块号（不含）
	// TCPPort 是该副本节点 TCP 数据面的实际端口（0 = Addr 端口+1）。
	TCPPort int `json:"tcp_port,omitempty"`
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
// payloadV2 是长度前缀版本：手拼分隔符的旧格式里，NodeID / 路径若含
// ',' ';' '|' 就能构造出"不同 JSON 却同一签名串"的歧义。V2 对每个
// 变长字段前置长度，签名串与结构一一对应。
func (g *TransferGrant) payloadV2() []byte {
	var sb strings.Builder
	sb.WriteString("ff2|")
	wStr := func(v string) {
		fmt.Fprintf(&sb, "%d:", len(v))
		sb.WriteString(v)
	}
	wInt := func(v int64) { fmt.Fprintf(&sb, "%d;", v) }
	wStr(g.ID)
	wStr(string(g.Src))
	wStr(string(g.Dst))
	wStr(g.Mode)
	wInt(g.FileSize)
	wStr(g.FileSHA256)
	wInt(int64(g.ChunkSize))
	wInt(int64(len(g.Hops)))
	for _, h := range g.Hops {
		wStr(string(h.NodeID))
		wStr(h.Addr) // Proto 不进签名（同 V1：拨号协议是路由提示）
	}
	wInt(int64(len(g.Sources)))
	for _, sp := range g.Sources {
		wStr(string(sp.NodeID))
		wStr(sp.Addr)
		wStr(sp.Path)
		wInt(sp.Start)
		wInt(sp.End)
	}
	wStr(g.SrcPath)
	wStr(g.DstPath)
	wInt(int64(g.Streams))
	wInt(int64(g.Retries))
	wInt(g.ExpiresAt.Unix())
	if g.Enc {
		wStr("enc")
	}
	if g.Mix {
		wStr("mix")
	}
	return []byte(sb.String())
}

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

// ValidateNodeName 校验显式配置的节点名。与 controller 的
// NormalizeNodeName 同一套规则：任意 UTF-8，但禁止 ':'（与
// `node:/path` 语法冲突）、'/'、控制字符、前后空白与超长。
func ValidateNodeName(name string) error {
	if strings.TrimSpace(name) != name {
		return fmt.Errorf("节点名首尾不能有空白")
	}
	if name == "" {
		return fmt.Errorf("节点名为空")
	}
	if len(name) > 64 {
		return fmt.Errorf("节点名过长（%d 字节，上限 64）", len(name))
	}
	for _, r := range name {
		switch {
		case r < 0x20 || r == 0x7f:
			return fmt.Errorf("节点名不能含控制字符")
		case r == ':' || r == '/' || r == '\\':
			return fmt.Errorf("节点名不能含 %q（与 node:/path 语法冲突）", r)
		}
	}
	return nil
}

func (g *TransferGrant) Sign(priv ed25519.PrivateKey) {
	g.Sig = hex.EncodeToString(ed25519.Sign(priv, g.payloadV2()))
}

func (g *TransferGrant) Verify(pub ed25519.PublicKey) bool {
	sig, err := hex.DecodeString(g.Sig)
	if err != nil {
		return false
	}
	// 先按 V2 验；不通过再按 V1 验，保证 controller 先升级、agent
	// 后升级的滚动过程中已签发的旧 grant 仍然有效。
	return ed25519.Verify(pub, g.payloadV2(), sig) ||
		ed25519.Verify(pub, g.payload(), sig)
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
