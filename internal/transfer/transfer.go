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

// SendFile 把 path 的内容经 firstHop 发出，grant 头随流首行传递。
// 直连时 firstHop 就是目的端；有中继时是第一跳中继，后续跳对发送端
// 透明（ACK 沿管道回流）。
// grant.Streams > 1 时并行开多条连接（各自独立五元组），交错发送
// 分块——绕过按流的 UDP 限速、填满带宽延迟积。
// TODO(M2.5)：限速（grant.RateLimit）、按已完成块续传。
func SendFile(ctx context.Context, path string, firstHop api.Hop, tlsConf *tls.Config, grant *api.TransferGrant) error {
	f, err := os.Open(path)
	if err != nil {
		return err
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
			errCh <- sendShare(ctx, f, firstHop, tlsConf, grant, r, n)
		}(r)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			return err
		}
	}
	return nil
}

// sendShare 发送第 r 条连接的份额：块序号 r, r+n, r+2n...交错分布，
// 保证各连接进度均衡。完成后发哨兵帧并等 ACK（接收端在全部份额
// 落盘后才统一回 ACK）。
func sendShare(ctx context.Context, f *os.File, firstHop api.Hop, tlsConf *tls.Config, grant *api.TransferGrant, r, n int) error {
	stream, closeConn, err := DialStream(ctx, firstHop.Addr, firstHop.Proto, tlsConf)
	if err != nil {
		return fmt.Errorf("dial %s(%s): %w", firstHop.Addr, firstHop.Proto, err)
	}
	defer closeConn()

	gj, err := json.Marshal(grant)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(stream, "FFJ1%s\n", gj); err != nil {
		return err
	}

	buf := make([]byte, ChunkSize)
	var count int64
	for idx := int64(r); ; idx += int64(n) {
		nread, rerr := f.ReadAt(buf, idx*ChunkSize)
		if nread > 0 {
			if err := WriteFrame(stream, idx, buf[:nread]); err != nil {
				return err
			}
			count++
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

// ServeQUIC 在 QUIC 监听上分发流。tlsConf 用于中继时拨下一跳。
func ServeQUIC(ln *quic.Listener, selfID string, verify GrantVerifier, tlsConf *tls.Config) error {
	for {
		conn, err := ln.Accept(context.Background())
		if err != nil {
			return err
		}
		go func() {
			defer conn.CloseWithError(0, "")
			for {
				stream, err := conn.AcceptStream(context.Background())
				if err != nil {
					return
				}
				go HandleStream(stream, selfID, verify, tlsConf)
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
		go HandleStream(conn, selfID, verify, tlsConf)
	}
}

// HandleStream 处理一条数据面流：探测 / 接收 / 中继。
func HandleStream(stream Stream, selfID string, verify GrantVerifier, tlsConf *tls.Config) {
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
			recvStream(br, stream, &grant)
		default:
			relayStream(br, stream, &grant, selfID, tlsConf)
		}
	default:
		fmt.Printf("未知流类型 %q\n", head)
	}
}

// recvStream 接收一个连接份额：帧按块号稀疏写入共享临时文件，
// 本连接哨兵到齐后等全局完成再回 ACK。
func recvStream(br *bufio.Reader, stream Stream, grant *api.TransferGrant) {
	g, err := groupFor(grant)
	if err != nil {
		fmt.Printf("接收 %s 建组失败：%v\n", grant.ID, err)
		return
	}
	feedErr := g.feed(br)
	var doneCh <-chan struct{}
	if feedErr == nil {
		doneCh, err = g.done(grant.ID)
	}
	if feedErr != nil || err != nil {
		fmt.Printf("接收 %s 失败：%v\n", grant.ID, feedErr)
		return
	}
	<-doneCh // 等全部份额落盘、原子改名完成
	stream.Write([]byte("ACK\n"))
	fmt.Printf("接收完成：%s（src=%s）-> %s\n", grant.ID, grant.Src, grant.DstPath)
}

// recvGroup 协调同一 grant 的并行接收：N 条连接交错写同一临时文件，
// 收齐 N 个哨兵才 sync + 原子改名，然后唤醒所有等待者回 ACK。
// 块号在帧头里，WriteAt 稀疏落盘天然支持乱序到达。
// TODO(M4)：失败份额的组回收（当前依赖 grant 过期清理）。
type recvGroup struct {
	mu        sync.Mutex
	finalPath string
	tmp       *os.File
	tmpName   string
	streams   int
	sentinels int
	waiters   []chan struct{}
	finished  bool
	finErr    error
}

var (
	recvMu     sync.Mutex
	recvGroups = map[string]*recvGroup{}
)

func groupFor(grant *api.TransferGrant) (*recvGroup, error) {
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
	n := grant.Streams
	if n < 1 {
		n = 1
	}
	g := &recvGroup{finalPath: grant.DstPath, tmp: tmp, tmpName: tmp.Name(), streams: n}
	recvGroups[grant.ID] = g
	return g, nil
}

// feed 消费一条连接的帧流直到哨兵。WriteAt 并发安全（各写各的偏移）。
func (g *recvGroup) feed(r io.Reader) error {
	for {
		idx, data, err := ReadFrame(r)
		if err == io.EOF {
			return nil // 对端未发哨兵直接 FIN（旧版本兼容）
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
	}
}

// done 登记本连接哨兵；返回的通道在全部哨兵集齐且改名完成后关闭。
func (g *recvGroup) done(grantID string) (<-chan struct{}, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	ch := make(chan struct{})
	g.waiters = append(g.waiters, ch)
	if !g.finished {
		g.sentinels++
		if g.sentinels >= g.streams {
			g.finished = true
			if err := g.tmp.Sync(); err != nil {
				g.finErr = err
			} else if err := g.tmp.Close(); err != nil {
				g.finErr = err
			} else if err := os.Rename(g.tmpName, g.finalPath); err != nil {
				g.finErr = err
			} else {
				recvMu.Lock()
				delete(recvGroups, grantID)
				recvMu.Unlock()
			}
		}
	}
	if g.finished {
		if g.finErr != nil {
			return nil, g.finErr
		}
		for _, w := range g.waiters {
			close(w)
		}
		g.waiters = nil
	}
	return ch, nil
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
