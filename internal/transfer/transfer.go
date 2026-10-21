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
// TODO(M2.5)：限速（grant.RateLimit）、按已完成块续传。
func SendFile(ctx context.Context, path string, firstHop api.Hop, tlsConf *tls.Config, grant *api.TransferGrant) error {
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

	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	buf := make([]byte, ChunkSize)
	var idx int64
	for {
		n, rerr := io.ReadFull(f, buf)
		if n > 0 {
			if err := WriteFrame(stream, idx, buf[:n]); err != nil {
				return err
			}
			idx++
		}
		if rerr == io.EOF || rerr == io.ErrUnexpectedEOF {
			break
		}
		if rerr != nil {
			return rerr
		}
	}
	// 完成哨兵：零长度帧。QUIC 下直接关连接会丢弃对端未读完的
	// 流数据，必须等接收端落盘后回 ACK 才能关闭。
	if err := WriteFrame(stream, idx, []byte{}); err != nil {
		return err
	}
	ack := make([]byte, 4)
	if s, ok := stream.(interface{ SetReadDeadline(time.Time) error }); ok {
		s.SetReadDeadline(time.Now().Add(60 * time.Second))
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

// recvStream 接收文件：临时文件 + 原子改名 + 回 ACK。
func recvStream(br *bufio.Reader, stream Stream, grant *api.TransferGrant) {
	if err := recvInto(br, stream, grant.DstPath); err != nil {
		fmt.Printf("接收 %s 失败：%v\n", grant.ID, err)
	} else {
		fmt.Printf("接收完成：%s（src=%s）-> %s\n", grant.ID, grant.Src, grant.DstPath)
	}
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

// recvInto 把帧流写入临时文件；收到零长度哨兵帧后原子改名为最终
// 路径并向发送端回 ACK。
func recvInto(r io.Reader, w io.Writer, finalPath string) error {
	dir := filepath.Dir(finalPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".ff-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	finalize := func() error {
		if err := tmp.Sync(); err != nil {
			tmp.Close()
			return err
		}
		if err := tmp.Close(); err != nil {
			return err
		}
		return os.Rename(tmp.Name(), finalPath)
	}
	for {
		_, data, err := ReadFrame(r)
		if err == io.EOF {
			return finalize() // 对端未发哨兵直接 FIN（旧版本兼容）
		}
		if err != nil {
			tmp.Close()
			return err
		}
		if len(data) == 0 { // 完成哨兵
			if err := finalize(); err != nil {
				return err
			}
			if _, err := w.Write([]byte("ACK\n")); err != nil {
				return err
			}
			return nil
		}
		if _, err := tmp.Write(data); err != nil {
			tmp.Close()
			return err
		}
	}
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
