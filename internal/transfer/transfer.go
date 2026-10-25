// Package transfer 实现数据面：分块传输、逐块校验、中继转发，
// 底层按探测结果走 QUIC（UDP）或 TCP+TLS，同一套流协议。
//
// 一个流（QUIC stream 或 TCP 连接）按首 4 字节分发：
//
//	"PING" —— 探测流，回 "PONG\n"，供拓扑回填可达边（rtt）
//	"FFJ1" —— 传输流，首行为 grant JSON：
//	          目的端 → 验签 + 收文件 + 原子落盘 + 回 ACK
//	          中继节点 → 验签 + 确认自己在路径上 → 拨下一跳、双向转发
//
// 帧格式：[4B magic "FFCH"][4B chunk idx][8B length][data][32B sha256(data)]
// 每个 chunk 独立校验；接收端先写临时文件再原子改名，落盘路径只
// 来自 controller 签名的 grant——陌生节点无法向任意路径投递文件。
package transfer

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"

	"fileferry/internal/api"
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
// taskRate 是**整任务**（跨全部并行流）共享的限速器。
//
// 注意：不能每流各算各的——4 条流各限 2MB/s 合计就是 8MB/s，
// 与"每任务限速"的语义不符（实测 20MB@2MB/s 本该 10 秒，实际 2.5 秒）。
type taskRate struct {
	mu    sync.Mutex
	limit int64
	sent  int64
	start time.Time
}

// newTaskRate 总是返回非 nil：limit<=0 表示不限速，但仍累计已发字节
// （返回给调用方报告真实吞吐；续传时"文件大小/耗时"会严重虚高）。
func newTaskRate(limit int64) *taskRate {
	return &taskRate{limit: limit, start: time.Now()}
}

// sent 返回累计已发字节。
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
func CloseWrite(s Stream) { closeWrite(s) }

// closeWrite 半关闭写侧（向对端发 FIN 但保持可读），QUIC 的 Close
// 与 TCP/TLS 的 CloseWrite 语义一致。
func closeWrite(s Stream) {
	type cw interface{ CloseWrite() error }
	if x, ok := s.(cw); ok {
		x.CloseWrite()
		return
	}
	s.Close()
}

// WriteFrame 把第 idx 块按帧格式写进 w。
func WriteFrame(w io.Writer, idx int64, data []byte) error {
	hdr := make([]byte, headerLen)
	copy(hdr, Magic)
	binary.BigEndian.PutUint32(hdr[4:8], uint32(idx))
	binary.BigEndian.PutUint64(hdr[8:16], uint64(len(data)))
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	if _, err := w.Write(data); err != nil {
		return err
	}
	sum := sha256.Sum256(data)
	_, err := w.Write(sum[:])
	return err
}

// ReadFrame 从 r 读出一帧并校验哈希，返回块号与数据。
// 零长度帧是完成哨兵。
func ReadFrame(r io.Reader) (idx int64, data []byte, err error) {
	hdr := make([]byte, headerLen)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return 0, nil, err
	}
	if string(hdr[:4]) != Magic {
		return 0, nil, fmt.Errorf("bad magic %q", hdr[:4])
	}
	idx = int64(binary.BigEndian.Uint32(hdr[4:8]))
	n := binary.BigEndian.Uint64(hdr[8:16])
	if n > ChunkSize+64 { // 端到端加密的密文比明文多 AEAD 标签（16B）
		return 0, nil, fmt.Errorf("chunk too large: %d", n)
	}
	data = make([]byte, n)
	if _, err := io.ReadFull(r, data); err != nil {
		return 0, nil, err
	}
	var sum [32]byte
	if _, err := io.ReadFull(r, sum[:]); err != nil {
		return 0, nil, err
	}
	if sha256.Sum256(data) != sum {
		return 0, nil, fmt.Errorf("chunk %d: hash mismatch", idx)
	}
	return idx, data, nil
}

// Manifest 是源端对传输内容的认证清单：{grantID, 文件 SHA-256,
// 字节数} 用源端节点证书私钥签名。它把"文件内容"与"授权"绑定：
// 恶意中继即使整体替换数据和清单也无法通过验签；接收端按清单的
// 总块数判定完成（而非哨兵计数），重放旧流只会重复写相同块，无害。
type Manifest struct {
	GrantID string `json:"grant_id"`
	SHA256  string `json:"sha256"`
	Size    int64  `json:"size"`
	CertB64 string `json:"cert"` // 源端证书 DER
	SigB64  string `json:"sig"`  // ed25519 签名 over grantID|sha256|size
}

func manifestPayload(grantID, sha string, size int64) []byte {
	return []byte(grantID + "|" + sha + "|" + strconv.FormatInt(size, 10))
}

// BuildManifest 计算文件指纹并用 tlsConf 中的节点证书签名（发送端）。
func BuildManifest(grantID, path string, tlsConf *tls.Config) (*Manifest, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	h := sha256.New()
	size, err := io.Copy(h, f)
	if err != nil {
		return nil, err
	}
	if len(tlsConf.Certificates) == 0 {
		return nil, fmt.Errorf("manifest: 无节点证书")
	}
	cert := tlsConf.Certificates[0]
	priv, ok := cert.PrivateKey.(ed25519.PrivateKey)
	if !ok || len(cert.Certificate) == 0 {
		return nil, fmt.Errorf("manifest: 证书缺少 ed25519 私钥")
	}
	m := &Manifest{
		GrantID: grantID,
		SHA256:  hex.EncodeToString(h.Sum(nil)),
		Size:    size,
		CertB64: base64.StdEncoding.EncodeToString(cert.Certificate[0]),
	}
	m.SigB64 = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, manifestPayload(m.GrantID, m.SHA256, m.Size)))
	return m, nil
}

// Verify 校验清单签名、证书链与 grant 参与方身份（接收端）。
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
type StreamOpener func() (Stream, func(), error)

// SendFile 发送整个文件（单源模式）。
func SendFile(ctx context.Context, path string, open StreamOpener, tlsConf *tls.Config, grant *api.TransferGrant) (int64, error) {
	return SendFileRange(ctx, path, open, tlsConf, grant, 0, -1)
}

// SendFileRange 计算并签名传输清单（manifest），经 open 建立的流发出
// 块区间 [startCh, endCh)（endCh<0 = 到文件尾）。多源模式各源只发
// 自己的区间；接收端按块号稀疏写，天然汇聚。返回发送字节数。
// grant.Streams 是本源的并行连接数，区间内交错分块。
func SendFileRange(ctx context.Context, path string, open StreamOpener, tlsConf *tls.Config, grant *api.TransferGrant, startCh, endCh int64) (int64, error) {
	mf, err := BuildManifest(grant.ID, path, tlsConf)
	if err != nil {
		return 0, fmt.Errorf("构建清单失败: %w", err)
	}
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	n := grant.Streams
	if n < 1 {
		n = 1
	}
	// 流的数量不能超过块的个数：小文件开 4 条流只是多付 4 次 TLS
	// 握手，一点并行收益都没有（1MB 文件只有 1 块）。实测这是小文件
	// 延迟的主要来源之一。
	if chunks := int((mf.Size + ChunkSize - 1) / ChunkSize); chunks > 0 && n > chunks {
		n = chunks
	}
	// 端到端加密：每 grant 一把密钥（所有流共用），发送前上报一次。
	// 每流一把会让 controller 的单槽一次性发放互相覆盖（真机踩坑）。
	var enc *streamCipher
	if grant.Enc {
		var key []byte
		var err error
		if enc, key, err = newStreamCipher(); err != nil {
			return 0, err
		}
		if keyDeliverer == nil {
			return 0, fmt.Errorf("grant 要求加密但未配置密钥上报")
		}
		if err := keyDeliverer(grant.ID, append(key, enc.noncePrefix...)); err != nil {
			return 0, fmt.Errorf("密钥上报失败: %w", err)
		}
	}
	rate := newTaskRate(grant.RateLimit) // 整任务共享配额（跨全部流）
	errCh := make(chan error, n)
	var wg sync.WaitGroup
	for r := 0; r < n; r++ {
		// 混流：奇数流换副协议（tcp<->quic 对称推导，端口约定由
		// DialStream 处理），叠加两种限速配额；副协议失败自然回退主协议
		thisOpen := open
		if grant.Mix && r%2 == 1 && len(grant.Hops) >= 2 {
			h := grant.Hops[1]
			if h.Proto == "tcp" {
				h.Proto = "quic"
			} else {
				h.Proto = "tcp"
			}
			// 只换建流协议：流头（含签名）必须始终是原始 grant——
			// 改写 Proto 后未重签的 grant 会被对端验签拒绝（并发风暴根因）
			thisOpen = OpenerDirect(ctx, h, tlsConf)
		}
		wg.Add(1)
		go func(r int, o StreamOpener) {
			defer wg.Done()
			errCh <- sendShare(ctx, f, o, grant, mf, enc, startCh, endCh, r, n, rate)
		}(r, thisOpen)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			return 0, err
		}
	}
	return rate.sentBytes(), nil
}

// OpenerDirect 返回常规模式的建流函数（拨 firstHop）。QUIC 建流
// 失败时自动降级 TCP 重试——签发时刻的边协议可能与当前网络状态
// 有 30 秒竞态窗口，拨号层兜底比取消任务友好。
func OpenerDirect(ctx context.Context, firstHop api.Hop, tlsConf *tls.Config) StreamOpener {
	return func() (Stream, func(), error) {
		s, closeFn, err := DialStream(ctx, firstHop.Addr, firstHop.Proto, firstHop.TCPPort, tlsConf)
		if err == nil || firstHop.Proto != "quic" {
			return s, closeFn, err
		}
		return DialStream(ctx, firstHop.Addr, "tcp", firstHop.TCPPort, tlsConf)
	}
}

// OpenerSwitch 返回交换台模式的建流函数：出站拨交换台并完成
// FFSW 配对握手，返回的流在协议上与直连流完全同构。
func OpenerSwitch(ctx context.Context, sw api.Hop, tlsConf *tls.Config, grant *api.TransferGrant) StreamOpener {
	return func() (Stream, func(), error) {
		return DialSwitch(ctx, sw.Addr, sw.Proto, sw.TCPPort, tlsConf, grant)
	}
}

// DialSwitch 出站拨向交换台，发送 FFSW + grant 完成配对，等 OK。
func DialSwitch(ctx context.Context, addr, proto string, tcpPort int, tlsConf *tls.Config, grant *api.TransferGrant) (Stream, func(), error) {
	stream, closeConn, err := DialStream(ctx, addr, proto, tcpPort, tlsConf)
	if err != nil {
		return nil, nil, err
	}
	gj, err := json.Marshal(grant)
	if err != nil {
		closeConn()
		return nil, nil, err
	}
	if _, err := fmt.Fprintf(stream, "FFSW%s\n", gj); err != nil {
		closeConn()
		return nil, nil, err
	}
	if s, ok := stream.(interface{ SetReadDeadline(time.Time) error }); ok {
		s.SetReadDeadline(time.Now().Add(75 * time.Second))
	}
	reply := make([]byte, 3)
	if _, err := io.ReadFull(stream, reply); err != nil {
		closeConn()
		return nil, nil, fmt.Errorf("等待交换台配对失败：%w", err)
	}
	if string(reply) != "OK\n" {
		closeConn()
		return nil, nil, fmt.Errorf("交换台拒绝：%q", reply)
	}
	return stream, closeConn, nil
}

// sendShare 发送第 r 条连接的份额：块序号 r, r+n, r+2n...交错分布，
// 保证各连接进度均衡。流头为 grant 行 + manifest 行，然后是数据帧。
func sendShare(ctx context.Context, f *os.File, open StreamOpener, grant *api.TransferGrant, mf *Manifest, enc *streamCipher, startCh, endCh int64, r, n int, rate *taskRate) error {
	// 连接失败/中断 → 重连重发整个份额（最多 3 次）：多流交错下
	// 单条连接的块缺口会让收发两端同时死等，必须自愈
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if err := sendShareOnce(ctx, f, open, grant, mf, enc, startCh, endCh, r, n, rate); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}
	return fmt.Errorf("份额 [%d,%d) 第 %d 流 3 次尝试均失败: %w", startCh, endCh, r, lastErr)
}

func sendShareOnce(ctx context.Context, f *os.File, open StreamOpener, grant *api.TransferGrant, mf *Manifest, enc *streamCipher, startCh, endCh int64, r, n int, rate *taskRate) error {
	tA := time.Now()
	stream, closeConn, err := open()
	if err != nil {
		return fmt.Errorf("建流失败: %w", err)
	}
	defer closeConn()
	tB := time.Now()

	gj, err := json.Marshal(grant)
	if err != nil {
		return err
	}
	mj, err := json.Marshal(mf)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(stream, "FFJ1%s\n%s\n", gj, mj); err != nil {
		return err
	}
	log.Printf("[tl] %s 流%d 建流%v 写头完成", grant.ID, r, tB.Sub(tA))
	// 断点续传：读接收端的 HAVE 位图（HAVE <base64>）。逐字节读行
	// 避免缓冲吞掉后续 ACK；3 秒无反馈=旧版/无进度，全发。
	have := map[int64]bool{}
	if rd, ok := stream.(interface{ SetReadDeadline(time.Time) error }); ok {
		rd.SetReadDeadline(time.Now().Add(3 * time.Second))
		line, lerr := readLine(stream)
		log.Printf("[tl] %s 流%d HAVE读取完成 err=%v", grant.ID, r, lerr)
		if lerr == nil && strings.HasPrefix(line, "HAVE ") {
			if bits, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(line, "HAVE ")); err == nil {
				for i := 0; i*8 < len(bits); i++ {
					for b := 0; b < 8; b++ {
						if bits[i]&(1<<b) != 0 {
							have[int64(i*8+b)] = true
						}
					}
				}
			}
		}
	}

	buf := make([]byte, ChunkSize)
	if wd, ok := stream.(interface{ SetWriteDeadline(time.Time) error }); ok {
		wd.SetWriteDeadline(time.Now().Add(90 * time.Second)) // 写阻塞自断，交给份额重试
	}
	for idx := startCh + int64(r); endCh < 0 || idx < endCh; idx += int64(n) {
		if have[idx] {
			continue // 断点续传：接收端已有此块
		}
		nread, rerr := f.ReadAt(buf, idx*ChunkSize)
		if nread > 0 {
			data := buf[:nread]
			if enc != nil {
				data = enc.seal(idx, data) // 端到端加密：帧哈希对密文（传输完整性），manifest 对明文
			}
			if err := WriteFrame(stream, idx, data); err != nil {
				return err
			}
			rate.take(int64(len(data)))
		}
		if rerr == io.EOF || rerr == io.ErrUnexpectedEOF {
			break
		}
		if rerr != nil {
			return rerr
		}
	}
	// 完成哨兵：零长度帧。接收端收齐全部份额的哨兵才落盘改名并回 ACK；
	// QUIC 下直接关连接会丢弃对端未读完的数据，必须等 ACK。
	if err := WriteFrame(stream, -1, []byte{}); err != nil {
		return err
	}
	ack := make([]byte, 4)
	if s, ok := stream.(interface{ SetReadDeadline(time.Time) error }); ok {
		s.SetReadDeadline(time.Now().Add(10 * time.Minute))
	}
	if _, err := io.ReadFull(stream, ack); err != nil {
		return fmt.Errorf("等待接收端 ACK 失败：%w", err)
	}
	if string(ack) != "ACK\n" {
		return fmt.Errorf("bad ack %q", ack)
	}
	return nil
}

// GrantVerifier 在数据面本地验签 grant（agent 注入 controller 公钥实现）。
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
func resolveCN(stream Stream, cn string) string {
	if cn != "" {
		return cn
	}
	if tc, ok := stream.(*tls.Conn); ok {
		if pcs := tc.ConnectionState().PeerCertificates; len(pcs) > 0 {
			return pcs[0].Subject.CommonName
		}
	}
	return ""
}

// —— M7 交换台：两端各自出站拨入，凭同一份签名 grant 配对对接 ——

type swWaiter struct {
	stream Stream
	br     *bufio.Reader
	cn     string
	paired chan struct{} // 配对成功
	done   chan struct{} // 管道结束
}

type switchboard struct {
	mu  sync.Mutex
	src map[string][]*swWaiter // grantID -> Src 侧待配对
	dst map[string][]*swWaiter // grantID -> Dst 侧待配对
}

var swBoard = &switchboard{src: map[string][]*swWaiter{}, dst: map[string][]*swWaiter{}}

// handleSwitchJoin 处理一条 FFSW 流：验签、校验参与方身份、按
// 行别（Src 侧 × Dst 侧）配对——同侧绝不互配，配对成功后双向管道
// 直到传输结束。对端未到则超时退出。
func handleSwitchJoin(br *bufio.Reader, stream Stream, verify GrantVerifier, peerCNStr string) {
	line, err := readHeaderLine(br)
	if err != nil {
		return
	}
	var grant api.TransferGrant
	if err := json.Unmarshal([]byte(line), &grant); err != nil {
		fmt.Println("交换台 grant 解析失败：", err)
		return
	}
	if verify == nil || !verify(&grant) {
		fmt.Printf("交换台拒绝未授权对接 %s\n", grant.ID)
		return
	}
	cn := resolveCN(stream, peerCNStr)
	if cn != grant.Src && cn != grant.Dst {
		fmt.Printf("交换台拒绝 %s：%s 不是传输参与方\n", grant.ID, cn)
		return
	}
	w := &swWaiter{stream: stream, br: br, cn: cn, paired: make(chan struct{}), done: make(chan struct{})}

	pool := swBoard.dst
	if cn == grant.Src {
		pool = swBoard.src
	}
	var pairs [][2]*swWaiter
	swBoard.mu.Lock()
	list := append(pool[grant.ID], w)
	pool[grant.ID] = list
	// Src 侧与 Dst 侧各有一名时配对（可能一次消化多对）
	for len(swBoard.src[grant.ID]) > 0 && len(swBoard.dst[grant.ID]) > 0 {
		a := swBoard.src[grant.ID][0]
		b := swBoard.dst[grant.ID][0]
		swBoard.src[grant.ID] = swBoard.src[grant.ID][1:]
		swBoard.dst[grant.ID] = swBoard.dst[grant.ID][1:]
		if len(swBoard.src[grant.ID]) == 0 {
			delete(swBoard.src, grant.ID)
		}
		if len(swBoard.dst[grant.ID]) == 0 {
			delete(swBoard.dst, grant.ID)
		}
		pairs = append(pairs, [2]*swWaiter{a, b})
	}
	swBoard.mu.Unlock()

	// 写 OK 与起管道都放在锁外：之前 a.stream.Write 在 swBoard.mu 里，
	// 一个慢对端（TCP 零窗口、QUIC 流控打满）就阻塞整个交换台的所有
	// 新配对，进而拖垮所有走交换台的传输。
	for _, pr := range pairs {
		a, b := pr[0], pr[1]
		a.stream.Write([]byte("OK\n"))
		b.stream.Write([]byte("OK\n"))
		close(a.paired)
		close(b.paired)
		go func(a, b *swWaiter) {
			pipeWaiters(a, b)
			close(a.done)
			close(b.done)
		}(a, b)
	}

	select {
	case <-w.paired:
		<-w.done // 等管道结束，避免外层 defer 提前关流
	case <-time.After(75 * time.Second):
		swBoard.remove(grant.ID, w)
		fmt.Printf("交换台配对超时：%s（%s）\n", grant.ID, cn)
	}
}

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
func pipeWaiters(a, b *swWaiter) {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { // 正向：a -> b
		defer wg.Done()
		io.Copy(b.stream, a.br)
		closeWrite(b.stream)
	}()
	io.Copy(a.stream, b.br) // 反向：b -> a
	closeWrite(a.stream)
	wg.Wait()
}

// pathGuard 由 agent 注入：返回 false 表示该路径不在白名单内，
// 拒绝写入。nil 表示不限制。
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
func RecvStream(br *bufio.Reader, stream Stream, grant *api.TransferGrant, roots *x509.CertPool) {
	line, err := readHeaderLine(br) // manifest 行（grant 行由调用方已读）
	if err != nil {
		fmt.Println("manifest 读取失败：", err)
		return
	}
	var mf Manifest
	if err := json.Unmarshal([]byte(line), &mf); err != nil {
		fmt.Println("manifest 解析失败：", err)
		return
	}
	if err := mf.Verify(grant, roots); err != nil {
		fmt.Printf("拒绝传输 %s：%v\n", grant.ID, err)
		return
	}
	// 解密器由接收组持有（建组时取一次，各并行流共用）。controller
	// 对密钥是一次性发放，放在这里每流各取一次必然有流失败。
	g, err := groupFor(grant, &mf)
	if err == nil {
		// 断点续传握手：告知发送端已收块位图（HAVE 行），对端跳块；
		// 旧版发送端不读此行也无碍（多写一行被当数据丢弃的风险——
		// 发送端在写头后主动读一行，见 sendShareOnce）
		if w, ok := stream.(interface{ SetWriteDeadline(time.Time) error }); ok {
			w.SetWriteDeadline(time.Now().Add(5 * time.Second))
		}
		fmt.Fprintf(stream, "HAVE %s\n", base64.StdEncoding.EncodeToString(g.haveBits()))
		// 必须立刻清掉这个写超时：它会把**后面所有写**（尤其末尾的
		// ACK）都限制在 5 秒内。实测限速 1MB/s 传 5MB 时，接收端写
		// ACK 已距 HAVE 超过 5 秒 → "i/o timeout" → 对端看到 EOF →
		// 文件其实已完整落盘却报失败，并触发 3 次无谓重试（3 分钟）。
		// 这不是限速专属：任何耗时 >5 秒的真实链路传输都会中招。
		if w, ok := stream.(interface{ SetWriteDeadline(time.Time) error }); ok {
			w.SetWriteDeadline(time.Time{})
		}
	}
	if err == ErrAlreadyDone {
		// 先 ACK 让对端收尾，再 drain 到对端关闭——否则对端仍在写数据，
		// 连接一关就是 broken pipe，重试也全撞墙（多流卡死的根因）
		stream.Write([]byte("ACK\n"))
		fmt.Printf("迟到流确认：%s（文件此前已完整落盘）\n", grant.ID)
		if s, ok := stream.(interface{ SetReadDeadline(time.Time) error }); ok {
			s.SetReadDeadline(time.Now().Add(10 * time.Minute))
		}
		if s, ok := stream.(interface{ SetReadDeadline(time.Time) error }); ok {
			s.SetReadDeadline(time.Now().Add(90 * time.Second))
		}
		io.Copy(io.Discard, stream)
		return
	}
	if err != nil {
		fmt.Printf("接收 %s 建组失败：%v\n", grant.ID, err)
		return
	}
	if err := g.feed(br, g.deckey); err != nil {
		fmt.Printf("接收 %s 失败：%v\n", grant.ID, err)
		return
	}
	select {
	case <-g.finished:
	case <-time.After(10 * time.Minute):
		fmt.Printf("接收 %s 超时：未收齐全部块\n", grant.ID)
		return
	}
	if g.finErr != nil {
		fmt.Printf("接收 %s 校验失败：%v（文件已丢弃）\n", grant.ID, g.finErr)
		return
	}
	// ACK 单独给一个明确的超时，而不是继承 HAVE 阶段的 5 秒（见上）。
	if w, ok := stream.(interface{ SetWriteDeadline(time.Time) error }); ok {
		w.SetWriteDeadline(time.Now().Add(30 * time.Second))
	}
	if _, err := stream.Write([]byte("ACK\n")); err != nil {
		fmt.Printf("接收完成但 ACK 写失败 %s：%v（文件已落盘）\n", grant.ID, err)
		return
	}
	fmt.Printf("接收完成：%s（src=%s，%d 字节）-> %s\n", grant.ID, grant.Src, mf.Size, grant.DstPath)
}

// recvOne 是数据面监听上的接收入口（已读 head 与 grant 行）。
func recvOne(br *bufio.Reader, stream Stream, grant *api.TransferGrant, tlsConf *tls.Config) {
	var roots *x509.CertPool
	if tlsConf != nil {
		roots = tlsConf.RootCAs
	}
	RecvStream(br, stream, grant, roots)
}

// recvGroup 按"唯一块计数"协调并行接收：收齐 manifest 声明的全部
// 块才校验全文件哈希、原子改名并唤醒等待者。重放旧流只会重复写
// 相同的块（WriteAt 幂等），无法提前触发完成，也无法篡改内容。
type recvGroup struct {
	mu        sync.Mutex
	grantID   string
	wantSHA   string
	finalPath string
	tmp       *os.File
	tmpName   string
	expected  int64
	got       map[int64]bool
	finished  chan struct{}
	finErr    error
	done      bool
	deckey    *streamCipher // 端到端解密器（组级共享，建组时取一次）
	size      int64         // 文件精确字节数（进度键）
	dirty     int           // 距上次位图落盘的新块数
}

// ErrAlreadyDone 表示该 grant 的文件已完整落盘（迟到的重试流）。
var ErrAlreadyDone = errors.New("grant 已完成")

var (
	recvMu     sync.Mutex
	recvGroups = map[string]*recvGroup{}
	completed  = map[string]time.Time{} // 已完成的 grant，2h 内拒绝重放
)

func groupFor(grant *api.TransferGrant, mf *Manifest) (*recvGroup, error) {
	// 取件码落盘映射（仅接收端）：inbox:xxx → <data-dir>/inbox/xxx
	if strings.HasPrefix(grant.DstPath, "inbox:") {
		p, err := SafeInboxPath(inboxRoot, grant.DstPath)
		if err != nil {
			return nil, err
		}
		grant.DstPath = p
	}
	// 兜底：目标已存在且是目录时补上源文件名。controller 只能按
	// 末尾分隔符判断，像 `node-2:/data` 这种不带斜杠的目录写法只有
	// 接收端知道；不补的话 os.Rename 到目录会报 file exists。
	if st, err := os.Stat(grant.DstPath); err == nil && st.IsDir() {
		// Base("") 会返回 "."，拼接等于没拼——必须校验出真实文件名
		if base := filepath.Base(grant.SrcPath); base != "" && base != "." &&
			base != string(filepath.Separator) {
			grant.DstPath = filepath.Join(grant.DstPath, base)
		}
	}
	if !PathAllowed(grant.DstPath) {
		return nil, fmt.Errorf("目的路径不在白名单内：%s", grant.DstPath)
	}
	// 第一次加锁：只做内存查询。取密钥是 HTTP 调用，绝不能持锁做——
	// 否则一条流取密钥就会卡住全网所有接收组。
	recvMu.Lock()
	for k, t := range completed { // 陈年条目卫生清扫
		if time.Since(t) > 2*time.Hour {
			delete(completed, k)
		}
	}
	if t, ok := completed[grant.ID]; ok && time.Since(t) < 2*time.Hour {
		// 文件已完整落盘：不是攻击，是发送端重试流晚到。回 ACK 让
		// 对端成功收尾（"文件到达但任务报失败"的收尾问题）。
		recvMu.Unlock()
		return nil, ErrAlreadyDone
	}
	if g, ok := recvGroups[grant.ID]; ok {
		recvMu.Unlock()
		return g, nil // 后续并行流：复用组（含它已取到的解密器）
	}
	recvMu.Unlock()

	// 锁外取密钥：每个 grant 只取一次，各并行流共用
	var deckey *streamCipher
	if grant.Enc {
		var kerr error
		if deckey, kerr = cipherForGrant(grant.ID); kerr != nil {
			return nil, fmt.Errorf("取密钥失败: %w", kerr)
		}
	}

	// 第二次加锁：建组。并发流可能已经建好，再查一次。
	recvMu.Lock()
	defer recvMu.Unlock()
	if g, ok := recvGroups[grant.ID]; ok {
		return g, nil
	}
	dir := filepath.Dir(grant.DstPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	tmp, err := os.CreateTemp(dir, ".ff-*")
	if err != nil {
		return nil, err
	}
	// 块数按清单大小精确计算。空文件是 0 块——之前钳成 1 会让接收端
	// 永远等一个不会到来的块 0，收发两端一起卡到 10 分钟超时。
	n := (mf.Size + ChunkSize - 1) / ChunkSize
	wantSHA := mf.SHA256
	if grant.FileSHA256 != "" {
		// 优先用 controller 签名钉死的摘要（Verify 已确认二者一致）
		wantSHA = grant.FileSHA256
	}
	g := &recvGroup{
		grantID:   grant.ID,
		wantSHA:   wantSHA,
		size:      mf.Size,
		deckey:    deckey,
		finalPath: grant.DstPath,
		tmp:       tmp,
		tmpName:   tmp.Name(),
		expected:  n,
		got:       map[int64]bool{},
		finished:  make(chan struct{}),
	}
	g.loadProgress() // 断点续传：加载同目标文件的历史进度（位图+临时文件）
	recvGroups[grant.ID] = g
	return g, nil
}

// partPath 断点进度文件路径。
func (g *recvGroup) partPath() string { return g.finalPath + ".ffpart" }

// loadProgress 读取历史进度：若存在同目标同大小的进度文件，恢复
// 位图并接管其临时文件（跳过已收块）。
func (g *recvGroup) loadProgress() {
	type progress struct {
		Size    int64  `json:"size"`
		SHA256  string `json:"sha256"`
		TmpName string `json:"tmp"`
		Bits    []byte `json:"bits"`
	}
	b, err := os.ReadFile(g.partPath())
	if err != nil {
		return
	}
	var p progress
	if json.Unmarshal(b, &p) != nil || p.Size <= 0 || p.TmpName == "" {
		return
	}
	if p.Size != g.size || p.SHA256 != g.wantSHA {
		return // 目标变了，作废旧进度
	}
	// 接管旧临时文件：丢弃本次新建的，用进度里的
	g.tmp.Close()
	os.Remove(g.tmpName)
	if f, err := os.OpenFile(p.TmpName, os.O_RDWR, 0o600); err == nil {
		g.tmp = f
		g.tmpName = p.TmpName
	} else {
		// 临时文件丢了但位图仍有效（重建 tmp 重新收缺块）
		nf, err := os.CreateTemp(filepath.Dir(g.finalPath), ".ff-*")
		if err != nil {
			return
		}
		g.tmp = nf
		g.tmpName = nf.Name()
	}
	for i := int64(0); i < g.expected && i/8 < int64(len(p.Bits)); i++ {
		if p.Bits[i/8]&(1<<(i%8)) != 0 {
			g.got[i] = true
		}
	}
}

// saveProgress 位图落盘（断点续传依据）。
// saveProgress 必须自行加锁：多流共享同一个 recvGroup，调用点都在
// 释放锁之后，直接遍历 g.got 会与其他流的写入并发——Go 的 map 并发
// 读写会直接 panic（race detector 实测在 40MB 多流场景触发）。
func (g *recvGroup) saveProgress() {
	g.mu.Lock()
	defer g.mu.Unlock()
	bits := make([]byte, (g.expected+7)/8)
	for i := range g.got {
		if i >= 0 && i/8 < int64(len(bits)) {
			bits[i/8] |= 1 << (i % 8)
		}
	}
	type progress struct {
		Size    int64  `json:"size"`
		SHA256  string `json:"sha256"`
		TmpName string `json:"tmp"`
		Bits    []byte `json:"bits"`
	}
	b, _ := json.Marshal(progress{Size: g.size, SHA256: g.wantSHA, TmpName: g.tmpName, Bits: bits})
	os.WriteFile(g.partPath(), b, 0o600)
}

// clearProgress 进度完成或作废时清理。
func (g *recvGroup) clearProgress() { os.Remove(g.partPath()) }

// haveBits 返回当前已收块位图（发送端跳块用）。
func (g *recvGroup) haveBits() []byte {
	g.mu.Lock()
	defer g.mu.Unlock()
	bits := make([]byte, (g.expected+7)/8)
	for i := range g.got {
		if i >= 0 && i/8 < int64(len(bits)) {
			bits[i/8] |= 1 << (i % 8)
		}
	}
	return bits
}

// hasChunk 报告块是否已收。
func (g *recvGroup) hasChunk(idx int64) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.got[idx]
}

// feed 消费一条连接的帧流直到哨兵或 EOF；每收到新块检查是否集齐。
// deckey 非空时先解密（端到端加密）。
func (g *recvGroup) feed(r io.Reader, deckey *streamCipher) error {
	for {
		idx, data, err := ReadFrame(r)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if len(data) == 0 { // 本连接份额完成哨兵
			// 空文件没有任何块，哨兵即是"全部到齐"，必须在这里收尾，
			// 否则 finished 永远不会被关闭。
			g.mu.Lock()
			empty := g.expected == 0 && !g.done
			if empty {
				g.done = true
			}
			g.mu.Unlock()
			if empty {
				g.finalize()
			}
			return nil
		}
		// 块号必须落在清单声明的范围内：否则 WriteAt 会在超大偏移处
		// 写一个稀疏文件，一个恶意（或出 bug 的）对端就能把接收端
		// 磁盘写满。
		g.mu.Lock()
		expected := g.expected
		g.mu.Unlock()
		if idx < 0 || idx >= expected {
			return fmt.Errorf("块号 %d 超出范围 [0,%d)", idx, expected)
		}
		if deckey != nil {
			if data, err = deckey.open(idx, data); err != nil {
				return fmt.Errorf("块 %d 解密失败: %w", idx, err)
			}
		}
		if _, err := g.tmp.WriteAt(data, idx*int64(ChunkSize)); err != nil {
			return err
		}
		g.mu.Lock()
		g.got[idx] = true
		g.dirty++
		// 进度落盘节奏：每 8 块（32MB）一次；但**块数少的文件必须每块
		// 都存**——否则总块数 <8 的文件（<32MB）永远存不了进度，重启后
		// 已收数据全丢。实测 20MB 文件传到 16MB 时中断，因为只有 5 块
		// 而从未写过进度文件，续传退化成从头再来。
		shouldSave := g.dirty >= 8 || g.expected <= 16
		if shouldSave {
			g.dirty = 0
		}
		complete := int64(len(g.got)) >= g.expected && !g.done
		if complete {
			g.done = true
		}
		g.mu.Unlock()
		if shouldSave {
			g.saveProgress()
		}
		if complete {
			g.finalize()
		}
	}
}

// finalize 收尾：全文件 SHA-256 对清单核验，通过才原子改名。
func (g *recvGroup) finalize() {
	defer close(g.finished)
	fail := func(err error) {
		g.tmp.Close()
		os.Remove(g.tmpName)
		g.clearProgress() // 内容验证失败：进度不可信，全作废
		g.finErr = err
		recvMu.Lock()
		delete(recvGroups, g.grantID)
		recvMu.Unlock()
	}
	if err := g.tmp.Sync(); err != nil {
		fail(err)
		return
	}
	if err := g.tmp.Close(); err != nil {
		fail(err)
		return
	}
	// 全文件哈希核验
	f, err := os.Open(g.tmpName)
	if err != nil {
		fail(err)
		return
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		f.Close()
		fail(err)
		return
	}
	f.Close()
	if g.wantSHA != "" && hex.EncodeToString(h.Sum(nil)) != g.wantSHA {
		fail(fmt.Errorf("全文件哈希与清单不符"))
		return
	}
	if err := os.Rename(g.tmpName, g.finalPath); err != nil {
		fail(err)
		return
	}
	g.clearProgress()
	recvMu.Lock()
	delete(recvGroups, g.grantID)
	completed[g.grantID] = time.Now()
	recvMu.Unlock()
}

// relayStream 中继转发：确认自己在签名路径上，拨下一跳，双向管道。
// 纯内存转发不落盘；ACK 哨兵沿反向管道回流，发送端无感知。
func relayStream(br *bufio.Reader, stream Stream, grant *api.TransferGrant, selfID string, tlsConf *tls.Config) {
	pos := -1
	for i, h := range grant.Hops {
		if h.NodeID == selfID {
			pos = i
			break
		}
	}
	// 必须是路径中间一跳（首尾都不是中继），否则视为滥用代理
	if pos <= 0 || pos >= len(grant.Hops)-1 {
		fmt.Printf("拒绝中继 %s：%s 不在路径上\n", grant.ID, selfID)
		return
	}
	next := grant.Hops[pos+1]
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ns, closeNext, err := DialStream(ctx, next.Addr, next.Proto, next.TCPPort, tlsConf)
	if err != nil {
		fmt.Printf("中继 %s 拨下一跳 %s(%s) 失败：%v\n", grant.ID, next.NodeID, next.Addr, err)
		return
	}
	defer closeNext()

	// 转发 grant 头
	gj, err := json.Marshal(grant)
	if err != nil {
		return
	}
	if _, err := fmt.Fprintf(ns, "FFJ1%s\n", gj); err != nil {
		fmt.Printf("中继 %s 转发头失败：%v\n", grant.ID, err)
		return
	}
	fmt.Printf("中继 %s：%s -> %s(%s)\n", grant.ID, selfID, next.NodeID, next.Addr)

	// 双向管道。反向结束时向源端半关闭（FIN 在 ACK 之后，数据不丢）。
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { // 正向：源 -> 下一跳
		defer wg.Done()
		io.Copy(ns, br)
		closeWrite(ns)
	}()
	io.Copy(stream, ns) // 反向：下一跳 -> 源（ACK 在这里回流）
	closeWrite(stream)
	wg.Wait()
}

// Probe 探测一个数据面地址：QUIC 与 TCP 各测一次往返，都通时若
// TCP 的 RTT 不劣于 QUIC 的 1.5 倍则选 TCP——UDP 被策略限速的网络
// 里 TCP 吞吐常有数量级优势（实测 4.5×），RTT 相近时应优选；
// UDP 被禁则自然回退 TCP。返回往返时延与选定协议。
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
