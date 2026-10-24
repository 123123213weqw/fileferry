// Package transfer 实现数据面：分块传输、逐块校验、中继转发，
// 底层按探测结果走 QUIC（UDP）或 TCP+TLS，同一套流协议。
//
// 一个流（QUIC stream 或 TCP 连接）按首 4 字节分发：
//   "PING" —— 探测流，回 "PONG\n"，供拓扑回填可达边（rtt）
//   "FFJ1" —— 传输流，首行为 grant JSON：
//             目的端 → 验签 + 收文件 + 原子落盘 + 回 ACK
//             中继节点 → 验签 + 确认自己在路径上 → 拨下一跳、双向转发
//
// 帧格式：[4B magic "FFCH"][4B chunk idx][8B length][data][32B sha256(data)]
// 每个 chunk 独立校验；接收端先写临时文件再原子改名，落盘路径只
// 来自 controller 签名的 grant——陌生节点无法向任意路径投递文件。
package transfer

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
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
		MaxIdleTimeout:              30 * time.Second,
		InitialStreamReceiveWindow:  8 * mb,
		MaxStreamReceiveWindow:      16 * mb,
		InitialConnectionReceiveWindow: 16 * mb,
		MaxConnectionReceiveWindow:  32 * mb,
	}
}

// sharedTransport：M6 打洞要求"监听、探测、拨号、WHOAMI"共用同一
// 个 UDP socket，NAT 映射才一致。Transport 按连接 ID 在一个 socket
// 上多路分解全部 QUIC 连接（监听 + 各次拨号），agent 启动时注入
//（Conn 是带嗅探的外壳，截流 WHOAMI 回复）；nil 时退回独立 socket。
var sharedTransport *quic.Transport

// SetTransport 注入共享 Transport（监听与拨号同 socket）。
func SetTransport(t *quic.Transport) { sharedTransport = t }

// SendOpeners 从指定 UDP socket 向 target 周期发送开洞包。
// 包内容无意义（对端 QUIC 视为垃圾丢弃），意义仅在"本 socket 向
// target 发过包"这条 NAT 放行记录。dur 结束后停止。
func SendOpeners(udp net.PacketConn, target string, dur time.Duration) {
	addr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		return
	}
	deadline := time.Now().Add(dur)
	for time.Now().Before(deadline) {
		udp.WriteTo([]byte("FFOPEN\n"), addr)
		time.Sleep(200 * time.Millisecond)
	}
}

// DialStream 按协议拨到 addr 并打开一条流。返回的 closer 关闭底层
// 连接（QUIC conn / TCP conn），流本身的写侧由调用者按需半关闭。
func DialStream(ctx context.Context, addr, proto string, tlsConf *tls.Config) (Stream, func(), error) {
	switch proto {
	case "tcp":
		host, portStr, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, nil, err
		}
		// TCP 端口约定 = 数据面 UDP 端口 + 1
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, nil, err
		}
		d := net.Dialer{Timeout: 5 * time.Second}
		conn, err := tls.DialWithDialer(&d, "tcp", net.JoinHostPort(host, strconv.Itoa(port+1)), tlsConf)
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
	if n > ChunkSize {
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
	GrantID  string `json:"grant_id"`
	SHA256   string `json:"sha256"`
	Size     int64  `json:"size"`
	CertB64  string `json:"cert"` // 源端证书 DER
	SigB64   string `json:"sig"`  // ed25519 签名 over grantID|sha256|size
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
	if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: time.Now()}); err != nil {
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
	errCh := make(chan error, n)
	var wg sync.WaitGroup
	for r := 0; r < n; r++ {
		wg.Add(1)
		go func(r int) {
			defer wg.Done()
			errCh <- sendShare(ctx, f, open, grant, mf, startCh, endCh, r, n)
		}(r)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			return 0, err
		}
	}
	return mf.Size, nil
}

// OpenerDirect 返回常规模式的建流函数（拨 firstHop）。
func OpenerDirect(ctx context.Context, firstHop api.Hop, tlsConf *tls.Config) StreamOpener {
	return func() (Stream, func(), error) {
		return DialStream(ctx, firstHop.Addr, firstHop.Proto, tlsConf)
	}
}

// OpenerSwitch 返回交换台模式的建流函数：出站拨交换台并完成
// FFSW 配对握手，返回的流在协议上与直连流完全同构。
func OpenerSwitch(ctx context.Context, sw api.Hop, tlsConf *tls.Config, grant *api.TransferGrant) StreamOpener {
	return func() (Stream, func(), error) {
		return DialSwitch(ctx, sw.Addr, sw.Proto, tlsConf, grant)
	}
}

// DialSwitch 出站拨向交换台，发送 FFSW + grant 完成配对，等 OK。
func DialSwitch(ctx context.Context, addr, proto string, tlsConf *tls.Config, grant *api.TransferGrant) (Stream, func(), error) {
	stream, closeConn, err := DialStream(ctx, addr, proto, tlsConf)
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
func sendShare(ctx context.Context, f *os.File, open StreamOpener, grant *api.TransferGrant, mf *Manifest, startCh, endCh int64, r, n int) error {
	// 连接失败/中断 → 重连重发整个份额（最多 3 次）：多流交错下
	// 单条连接的块缺口会让收发两端同时死等，必须自愈
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if err := sendShareOnce(ctx, f, open, grant, mf, startCh, endCh, r, n); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}
	return fmt.Errorf("份额 [%d,%d) 第 %d 流 3 次尝试均失败: %w", startCh, endCh, r, lastErr)
}

func sendShareOnce(ctx context.Context, f *os.File, open StreamOpener, grant *api.TransferGrant, mf *Manifest, startCh, endCh int64, r, n int) error {
	stream, closeConn, err := open()
	if err != nil {
		return fmt.Errorf("建流失败: %w", err)
	}
	defer closeConn()

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

	buf := make([]byte, ChunkSize)
	if wd, ok := stream.(interface{ SetWriteDeadline(time.Time) error }); ok {
		wd.SetWriteDeadline(time.Now().Add(5 * time.Minute)) // 写阻塞自断，交给份额重试
	}
	for idx := startCh + int64(r); endCh < 0 || idx < endCh; idx += int64(n) {
		nread, rerr := f.ReadAt(buf, idx*ChunkSize)
		if nread > 0 {
			if err := WriteFrame(stream, idx, buf[:nread]); err != nil {
				return err
			}
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
		line, err := br.ReadString('\n') // grant JSON 行
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
	line, err := br.ReadString('\n')
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
	swBoard.mu.Unlock()

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

// RecvStream 按认证清单接收：读 manifest 行并验签，然后进组收块。
// 这是接收端（直连与交换台路径共用的入口）。
func RecvStream(br *bufio.Reader, stream Stream, grant *api.TransferGrant, roots *x509.CertPool) {
	line, err := br.ReadString('\n') // manifest 行（grant 行由调用方已读）
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
	g, err := groupFor(grant, &mf)
	if err != nil {
		fmt.Printf("接收 %s 建组失败：%v\n", grant.ID, err)
		return
	}
	if err := g.feed(br); err != nil {
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
	stream.Write([]byte("ACK\n"))
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
}

var (
	recvMu     sync.Mutex
	recvGroups = map[string]*recvGroup{}
	completed  = map[string]time.Time{} // 已完成的 grant，2h 内拒绝重放
)

func groupFor(grant *api.TransferGrant, mf *Manifest) (*recvGroup, error) {
	if !PathAllowed(grant.DstPath) {
		return nil, fmt.Errorf("目的路径不在白名单内：%s", grant.DstPath)
	}
	recvMu.Lock()
	defer recvMu.Unlock()
	if t, ok := completed[grant.ID]; ok && time.Since(t) < 2*time.Hour {
		return nil, fmt.Errorf("grant 已完成，拒绝重放")
	}
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
	n := (mf.Size + ChunkSize - 1) / ChunkSize
	if n < 1 {
		n = 1 // 空文件：仅哨兵
	}
	g := &recvGroup{
		grantID:   grant.ID,
		wantSHA:   mf.SHA256,
		finalPath: grant.DstPath,
		tmp:       tmp,
		tmpName:   tmp.Name(),
		expected:  n,
		got:       map[int64]bool{},
		finished:  make(chan struct{}),
	}
	recvGroups[grant.ID] = g
	return g, nil
}

// feed 消费一条连接的帧流直到哨兵或 EOF；每收到新块检查是否集齐。
func (g *recvGroup) feed(r io.Reader) error {
	for {
		idx, data, err := ReadFrame(r)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if len(data) == 0 { // 本连接份额完成哨兵
			return nil
		}
		if _, err := g.tmp.WriteAt(data, idx*int64(ChunkSize)); err != nil {
			return err
		}
		g.mu.Lock()
		g.got[idx] = true
		complete := int64(len(g.got)) >= g.expected && !g.done
		if complete {
			g.done = true
		}
		g.mu.Unlock()
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
	ns, closeNext, err := DialStream(ctx, next.Addr, next.Proto, tlsConf)
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

// Probe 探测一个数据面地址：先 QUIC（UDP），失败回退 TCP（约定端口
// +1）。返回往返时延与实际可用的协议。
func Probe(ctx context.Context, addr string, tlsConf *tls.Config) (rtt time.Duration, proto string, err error) {
	start := time.Now()
	s, closeConn, derr := DialStream(ctx, addr, "quic", tlsConf)
	if derr == nil {
		defer closeConn()
		if _, err = pingPong(s); err == nil {
			return time.Since(start), "quic", nil
		}
	}
	start = time.Now()
	s, closeConn, derr = DialStream(ctx, addr, "tcp", tlsConf)
	if derr != nil {
		return 0, "", derr
	}
	defer closeConn()
	if _, err = pingPong(s); err != nil {
		return 0, "", err
	}
	return time.Since(start), "tcp", nil
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
