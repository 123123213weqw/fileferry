package transfer

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fileferry/internal/api"
	"fmt"
	"github.com/quic-go/quic-go"
	"io"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	ChunkSize = 4 << 20 // 4 MiB
	Magic     = "FFCH"
	headerLen = 4 + 4 + 8
)

// Stream 是数据面的一条逻辑流：QUIC 的 stream 或 TLS 后的 TCP 连接。
type Stream interface {
	io.ReadWriteCloser
}

// quicConf 是数据面统一的 QUIC 参数：放宽流控窗口与空闲超时。
// 默认窗口在小缓冲/高延迟链路上会把吞吐压到 1MB/s 量级。
func quicConf() *quic.Config {
	const mb = 1 << 20
	return &quic.Config{
		MaxIdleTimeout:                 30 * time.Second,
		InitialStreamReceiveWindow:     8 * mb,
		MaxStreamReceiveWindow:         16 * mb,
		InitialConnectionReceiveWindow: 16 * mb,
		MaxConnectionReceiveWindow:     32 * mb,
	}
}

// sharedTransport：M6 打洞要求"监听、探测、拨号、WHOAMI"共用同一
// 个 UDP socket，NAT 映射才一致。Transport 按连接 ID 在一个 socket
// 上多路分解全部 QUIC 连接（监听 + 各次拨号），agent 启动时注入
// （Conn 是带嗅探的外壳，截流 WHOAMI 回复）；nil 时退回独立 socket。
var sharedTransport *quic.Transport

// SetTransport 注入共享 Transport（监听与拨号同 socket）。
func SetTransport(t *quic.Transport) { sharedTransport = t }

// SendOpeners 从指定 UDP socket 向 target 周期发送开洞包。
// 包内容无意义（对端 QUIC 视为垃圾丢弃），意义仅在"本 socket 向
// target 发过包"这条 NAT 放行记录。dur 结束后停止。
// 同时向映射端口 ±32 扇形喷洒（对称 NAT 的端口预测：对端出口
// 映射端口通常在已观测映射附近递增），提高对穿成功率。
// progressSink 是发送进度回调，只给 CLI 设（守护进程不设）。
//
// 存在的理由：被墙链路上一次大文件传输可能跑几十秒到几分钟，没有进度
// 输出时用户无法区分"在慢慢传"和"已经卡死"——这正是我自己实测时遇到
// 91 秒静默卡顿、只能靠猜的情况。
var (
	progressMu   sync.RWMutex
	progressSink func(sent int64)
)

// SetProgressSink 注册发送进度回调（nil 取消）。回调在发送路径上同步
// 调用，必须快速返回。
func SetProgressSink(fn func(sent int64)) {
	progressMu.Lock()
	progressSink = fn
	progressMu.Unlock()
}

func emitProgress(sent int64) {
	progressMu.RLock()
	fn := progressSink
	progressMu.RUnlock()
	if fn != nil {
		fn(sent)
	}
}

// taskRate 是**整任务**（跨全部并行流）共享的限速器。
//
// 注意：不能每流各算各的——4 条流各限 2MB/s 合计就是 8MB/s，
// 与"每任务限速"的语义不符（实测 20MB@2MB/s 本该 10 秒，实际 2.5 秒）。
func (t *taskRate) sentBytes() int64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.sent
}

// take 记录本次发送字节数，并按整任务平均速率补睡（limit<=0 不睡）。
func (t *taskRate) take(n int64) {
	if t == nil || n <= 0 {
		return
	}
	t.mu.Lock()
	t.sent += n
	sent := t.sent
	limit := t.limit
	t.mu.Unlock()
	emitProgress(sent)
	if limit <= 0 {
		return
	}
	want := time.Duration(float64(sent) / float64(limit) * float64(time.Second))
	if ahead := want - time.Since(t.start); ahead > 0 {
		time.Sleep(ahead)
	}
}

// spreadPorts 是"端口未知"时允许探测的候选偏移。之前固定扫 13 个
// 连续附近的端口（±1,2,4,8,16,32）——形态上就是一次端口扫描，实测
// 8 秒内打 13 个端口，在 FortiGate/云厂商的扫描检测里很容易被整 IP
// 隔离（连带把 SSH 一起封掉）。现在只有在对端端口未知时才退化为
// 这 3 个最可能的偏移。
var spreadPorts = []int{-1, 1, -2}

// SendOpeners 向 target 持续发开洞包。
// exact=true 表示 target 是该 socket 的**已知公网映射**（WHOAMI 观测
// 值），此时只打这一个端口，不做任何扩散。
func SendOpeners(udp net.PacketConn, target string, dur time.Duration, exact bool) {
	addr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		return
	}
	spray := []*net.UDPAddr{addr}
	if port := addr.Port; !exact && port > 33 && port < 65500 {
		for _, d := range spreadPorts {
			if p := port + d; p > 0 && p < 65536 {
				a2 := *addr
				a2.Port = p
				spray = append(spray, &a2)
			}
		}
	}
	deadline := time.Now().Add(dur)
	for time.Now().Before(deadline) {
		for _, a := range spray {
			udp.WriteTo([]byte("FFOPEN\n"), a)
		}
		time.Sleep(300 * time.Millisecond)
	}
}

// DialStream 按协议拨到 addr 并打开一条流。返回的 closer 关闭底层
// 连接（QUIC conn / TCP conn），流本身的写侧由调用者按需半关闭。
// DialStream 建立一条数据面流。tcpPort 是该**目标节点** TCP 数据面的
// 实际端口（来自对端心跳上报）；0 时退回全局覆盖或 Addr 端口+1。
func DialStream(ctx context.Context, addr, proto string, tcpPort int, tlsConf *tls.Config) (Stream, func(), error) {
	switch proto {
	case "tcp":
		host, portStr, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, nil, err
		}
		// TCP 端口：默认取数据面 UDP 端口 + 1；设置了 tcpPortOverride
		// 时一律用它。被墙网络里通常只放行 443，而 UDP(QUIC) 往往被
		// 干扰，此时把 TCP 数据面挪到 443 是唯一能通的办法。
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, nil, err
		}
		if tcpPort <= 0 {
			// 没有对端上报的端口时退回默认约定：数据面 UDP 端口 + 1。
			// 绝不回退到"本机自己的端口"——那会把对端地址拨到自己身上
			// （实测会报"拒绝中继：不在路径上"）。
			tcpPort = port + 1
		}
		d := net.Dialer{Timeout: 5 * time.Second}
		conn, err := tls.DialWithDialer(&d, "tcp", net.JoinHostPort(host, strconv.Itoa(tcpPort)), tlsConf)
		if err != nil {
			return nil, nil, err
		}
		return conn, func() { conn.Close() }, nil
	default: // "quic"
		udpAddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			return nil, nil, err
		}
		if sharedTransport != nil {
			conn, err := sharedTransport.Dial(ctx, udpAddr, tlsConf, quicConf())
			if err != nil {
				return nil, nil, err
			}
			stream, err := conn.OpenStreamSync(ctx)
			if err != nil {
				conn.CloseWithError(0, "")
				return nil, nil, err
			}
			return stream, func() { conn.CloseWithError(0, "") }, nil
		}
		udp, err := net.ListenUDP("udp", nil)
		if err != nil {
			return nil, nil, err
		}
		if err := udp.SetReadBuffer(4 << 20); err == nil {
			_ = udp.SetWriteBuffer(4 << 20)
		}
		conn, err := quic.Dial(ctx, udp, udpAddr, tlsConf, quicConf())
		if err != nil {
			udp.Close()
			return nil, nil, err
		}
		stream, err := conn.OpenStreamSync(ctx)
		if err != nil {
			conn.CloseWithError(0, "")
			udp.Close()
			return nil, nil, err
		}
		return stream, func() { conn.CloseWithError(0, ""); udp.Close() }, nil
	}
}

// CloseWrite 半关闭写侧（向对端发 FIN 但保持可读），QUIC 的 Close
// 与 TCP/TLS 的 CloseWrite 语义一致。
func (m *Manifest) Verify(grant *api.TransferGrant, roots *x509.CertPool) error {
	certDER, err := base64.StdEncoding.DecodeString(m.CertB64)
	if err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(m.SigB64)
	if err != nil {
		return err
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return err
	}
	// KeyUsages 必须是 Any：这里校验的是"集群成员对清单的签名"，不是
	// TLS 服务器身份。x509 默认按 ServerAuth 校验，而管理员证书只带
	// ClientAuth → 本机直推会被误判为"证书链无效"（实测
	// "certificate specifies an incompatible key usage"）。
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:       roots,
		CurrentTime: time.Now(),
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return fmt.Errorf("manifest: 证书链无效: %w", err)
	}
	srcOK := cert.Subject.CommonName == grant.Src
	for _, sp := range grant.Sources { // M8 多源：任一源签的清单均可
		if cert.Subject.CommonName == sp.NodeID {
			srcOK = true
			break
		}
	}
	if !srcOK {
		return fmt.Errorf("manifest: 签名者 %s 不在源集合", cert.Subject.CommonName)
	}
	pub, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("manifest: 非 ed25519 证书")
	}
	if !ed25519.Verify(pub, manifestPayload(m.GrantID, m.SHA256, m.Size), sig) {
		return fmt.Errorf("manifest: 签名无效")
	}
	if m.GrantID != grant.ID {
		return fmt.Errorf("manifest: grantID 不符")
	}
	// 把"文件内容"钉到 controller 签名的 grant 上：grant 里带摘要时，
	// 清单必须与之一致，否则任何一个参与源都能替换自己那段内容并按
	// 替换后的整文件重算哈希，接收端照样验收通过（多源模式的完整性
	// 前提）。之前这里只验"签名者 ∈ 源集合"，不看 grant 的摘要。
	if grant.FileSHA256 != "" && !strings.EqualFold(m.SHA256, grant.FileSHA256) {
		return fmt.Errorf("manifest: 全文件哈希与授权不符")
	}
	if grant.FileSize > 0 && m.Size != grant.FileSize {
		return fmt.Errorf("manifest: 文件大小与授权不符（%d vs %d）", m.Size, grant.FileSize)
	}
	return nil
}

// StreamOpener 建立一条数据面流（常规拨号或交换台配对）。
type GrantVerifier func(*api.TransferGrant) bool

// ServeQUIC 在 QUIC 监听上分发流。tlsConf 用于中继时拨下一跳；
// peerCN 为本连接对端证书 CN（交换台校验参与方用）。
func ServeQUIC(ln *quic.Listener, selfID string, verify GrantVerifier, tlsConf *tls.Config) error {
	for {
		conn, err := ln.Accept(context.Background())
		if err != nil {
			return err
		}
		go func() {
			defer conn.CloseWithError(0, "")
			cn := ""
			if pcs := conn.ConnectionState().TLS.PeerCertificates; len(pcs) > 0 {
				cn = pcs[0].Subject.CommonName
			}
			for {
				stream, err := conn.AcceptStream(context.Background())
				if err != nil {
					return
				}
				go HandleStream(stream, selfID, verify, tlsConf, cn)
			}
		}()
	}
}

// ServeTCP 在 TLS 后的 TCP 监听上分发连接（QUIC 被禁网络的回退通道）。
func ServeTCP(ln net.Listener, selfID string, verify GrantVerifier, tlsConf *tls.Config) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go HandleStream(conn, selfID, verify, tlsConf, "")
	}
}

// HandleStream 处理一条数据面流：探测 / 接收 / 中继 / 交换台接入。
func HandleStream(stream Stream, selfID string, verify GrantVerifier, tlsConf *tls.Config, peerCNStr string) {
	defer stream.Close()
	head := make([]byte, 4)
	if _, err := io.ReadFull(stream, head); err != nil {
		return
	}
	switch string(head) {
	case "PING":
		stream.Write([]byte("PONG\n"))
	case "FFJ1":
		br := bufio.NewReader(stream)
		line, err := readHeaderLine(br) // grant JSON 行
		if err != nil {
			fmt.Println("传输头读取失败：", err)
			return
		}
		var grant api.TransferGrant
		if err := json.Unmarshal([]byte(line), &grant); err != nil {
			fmt.Println("grant 解析失败：", err)
			return
		}
		if verify == nil || !verify(&grant) {
			fmt.Printf("拒绝未授权传输 %s（src=%s）\n", grant.ID, grant.Src)
			return
		}
		switch {
		case grant.Dst == selfID:
			recvOne(br, stream, &grant, tlsConf)
		default:
			relayStream(br, stream, &grant, selfID, tlsConf)
		}
	case "FFSW":
		handleSwitchJoin(bufio.NewReader(stream), stream, verify, peerCNStr)
	default:
		fmt.Printf("未知流类型 %q\n", head)
	}
}

// resolveCN 解析对端证书 CN：优先服务层传入（QUIC 场景），否则
// 从 TCP TLS 连接自取。
func (s *switchboard) remove(grantID string, w *swWaiter) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, pool := range []map[string][]*swWaiter{s.src, s.dst} {
		list := pool[grantID]
		for i, x := range list {
			if x == w {
				pool[grantID] = append(list[:i], list[i+1:]...)
				break
			}
		}
		if len(pool[grantID]) == 0 {
			delete(pool, grantID)
		}
	}
}

// pipeWaiters 双向管道（与中继转发同一套语义：反向半关闭保证
// ACK 之后的 FIN 不丢数据）。
var pathGuard func(string) bool

// SetPathGuard 注入落盘路径白名单检查。
func SetPathGuard(g func(string) bool) { pathGuard = g }

// PathAllowed 报告路径是否被允许（发送端源路径与接收端目的路径通用）。
func PathAllowed(p string) bool { return pathGuard == nil || pathGuard(p) }

// within 判断 p 是否在 dir 之内（按路径分量比较，不是字符串前缀）。
// 之前的实现用 strings.HasPrefix：白名单 /home/me/ff 时
// /home/me/ff-evil/x 也能通过，等于白名单无效。
func within(p, dir string) bool {
	rel, err := filepath.Rel(dir, p)
	if err != nil {
		return false
	}
	if rel == "." {
		return true
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return false
	}
	return !filepath.IsAbs(rel)
}

// resolveBest 尽量把路径解析成真实路径：逐级对已存在的部分做
// EvalSymlinks，末尾尚不存在的部分按字面拼接。这样白名单位于符号
// 链接之下（/home/me/ff -> /srv/data）时不会被误拒，而
// /home/me/ff/link -> /etc 这类逃逸会被解析出来并被拦下。
func resolveBest(p string) string {
	if abs, err := filepath.Abs(p); err == nil {
		p = abs
	}
	if real, err := filepath.EvalSymlinks(p); err == nil {
		return real
	}
	dir, base := filepath.Split(p)
	dir = filepath.Clean(dir)
	if dir == string(filepath.Separator) || dir == "." || dir == p {
		return filepath.Clean(p)
	}
	return filepath.Join(resolveBest(dir), base)
}

// NewPathGuard 构造白名单检查函数。白名单项本身同样先解析成真实路径，
// 比较时两侧都解析，避免"白名单是软链、目标是真实路径"的假拒绝。
func NewPathGuard(dirs []string) (func(string) bool, error) {
	roots := make([]string, 0, len(dirs))
	for _, d := range dirs {
		if strings.TrimSpace(d) == "" {
			continue
		}
		abs, err := filepath.Abs(d)
		if err != nil {
			return nil, fmt.Errorf("白名单路径非法 %q: %w", d, err)
		}
		roots = append(roots, resolveBest(abs))
	}
	if len(roots) == 0 {
		return nil, fmt.Errorf("allowed-dirs 为空")
	}
	return func(p string) bool {
		if p == "" {
			return false
		}
		target := resolveBest(p)
		for _, r := range roots {
			if within(target, r) {
				return true
			}
		}
		return false
	}, nil
}

// inboxRoot 是"取件码"落盘目录（agent 启动时注入 data-dir）。
// 映射只在**接收端**做：之前写在源端的 runJob 里，源端把 grant 的
// DstPath 改成自己的绝对路径后再转发，目的端按被改过的 DstPath 验签
// 必然失败——所以 ff share / ff get 从来就没通过（一直被误判成
// "密钥专递链路待修"）。
var inboxRoot string

// SetInboxRoot 注入取件落盘目录。
func SetInboxRoot(dir string) { inboxRoot = dir }

// SafeInboxPath 把 grant 里的 inbox: 标记映射到本机 dataDir/inbox 之内。
// 只接受单层文件名：任何目录分隔、..、绝对路径都拒绝——之前直接
// filepath.Join(dataDir, "inbox", TrimPrefix(dst,"inbox:"))，
// "inbox:../../etc/cron.d/x" 会逃到 dataDir 之外。
func SafeInboxPath(dataDir, dstPath string) (string, error) {
	rest := strings.TrimPrefix(dstPath, "inbox:")
	rest = strings.TrimPrefix(rest, "/")
	if rest == "" {
		return "", fmt.Errorf("取件路径为空")
	}
	// 只允许单个文件名，禁止任何路径分量
	if rest != filepath.Base(rest) || rest == "." || rest == ".." ||
		strings.ContainsRune(rest, filepath.Separator) {
		return "", fmt.Errorf("取件路径非法：%q", dstPath)
	}
	inbox := filepath.Join(dataDir, "inbox")
	out := filepath.Join(inbox, rest)
	if !within(out, inbox) {
		return "", fmt.Errorf("取件路径越界：%q", dstPath)
	}
	return out, nil
}

// RecvStream 按认证清单接收：读 manifest 行并验签，然后进组收块。
// 这是接收端（直连与交换台路径共用的入口）。
var (
	recvMu     sync.Mutex
	recvGroups = map[string]*recvGroup{}
	completed  = map[string]time.Time{} // 已完成的 grant，2h 内拒绝重放
)

func Probe(ctx context.Context, addr string, tcpPort int, tlsConf *tls.Config) (time.Duration, string, error) {
	rtt, proto, _, err := ProbeWithAlt(ctx, addr, tcpPort, tlsConf)
	return rtt, proto, err
}

// ProbeWithAlt 返回（胜者协议, 副协议或空, rtt, err）。两者皆通时
// 副协议非空——混流将各流分散到两条协议通道。
// ProbeWithAlt 探测一条边。tcpPort 是**对端**上报的 TCP 数据面端口
// （0 = 用 addr 端口+1），被墙网络里各节点端口可能不同。
func ProbeWithAlt(ctx context.Context, addr string, tcpPort int, tlsConf *tls.Config) (time.Duration, string, string, error) {
	qRTT, qErr := probeOne(ctx, addr, "quic", tcpPort, tlsConf)
	tRTT, tErr := probeOne(ctx, addr, "tcp", tcpPort, tlsConf)
	switch {
	case qErr != nil && tErr != nil:
		return 0, "", "", tErr
	case qErr != nil:
		return tRTT, "tcp", "", nil
	case tErr != nil:
		return qRTT, "quic", "", nil
	case tRTT < qRTT*3/2:
		return tRTT, "tcp", "quic", nil // RTT 接近 → TCP 主（吞吐优先），QUIC 副
	default:
		return qRTT, "quic", "tcp", nil
	}
}

func probeOne(ctx context.Context, addr, proto string, tcpPort int, tlsConf *tls.Config) (time.Duration, error) {
	start := time.Now()
	s, closeConn, err := DialStream(ctx, addr, proto, tcpPort, tlsConf)
	if err != nil {
		return 0, err
	}
	defer closeConn()
	if _, err := pingPong(s); err != nil {
		return 0, err
	}
	return time.Since(start), nil
}

func pingPong(s Stream) (int, error) {
	if _, err := s.Write([]byte("PING\n")); err != nil {
		return 0, err
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(s, buf); err != nil {
		return 0, err
	}
	if string(buf) != "PONG\n" {
		return 0, fmt.Errorf("bad pong")
	}
	return 5, nil
}

// readLine 从流读一行（到 \n，最长 8KB），不引入缓冲。
// maxHeaderLine 是流首部单行的上限：grant / manifest 都是小 JSON
// （源集合最多十几项），1 MiB 已经远超正常需要。之前用
// bufio.Reader.ReadString，任何已入网节点只要不发换行就能把对端
// 内存吃穿。
const maxHeaderLine = 1 << 20

// readHeaderLine 读一行并以 maxHeaderLine 封顶，超长直接报错断流。
func readHeaderLine(br *bufio.Reader) (string, error) {
	var sb []byte
	for {
		chunk, err := br.ReadSlice('\n')
		if len(sb)+len(chunk) > maxHeaderLine {
			return "", fmt.Errorf("首部行超长（>%d 字节）", maxHeaderLine)
		}
		sb = append(sb, chunk...)
		if err == nil {
			return string(sb), nil
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		return "", err
	}
}

func readLine(r io.Reader) (string, error) {
	var sb []byte
	one := make([]byte, 1)
	for len(sb) < 8192 {
		if _, err := io.ReadFull(r, one); err != nil {
			return "", err
		}
		if one[0] == '\n' {
			return string(sb), nil
		}
		sb = append(sb, one[0])
	}
	return "", fmt.Errorf("line too long")
}
