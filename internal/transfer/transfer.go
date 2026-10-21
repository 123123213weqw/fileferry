// Package transfer 实现数据面：QUIC 流式分块传输、逐块校验、
// 断点续传与中继转发。
//
// 一个 QUIC 连接上按流的首 4 字节分发：
//   "PING" —— 探测流，回 "PONG\n"，供拓扑回填可达边（rtt）
//   "FFJ1" —— 传输流，首行为 grant JSON，验签通过后才接收文件
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
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/quic-go/quic-go"

	"fileferry/internal/api"
)

const (
	ChunkSize = 4 << 20 // 4 MiB
	Magic     = "FFCH"
	headerLen = 4 + 4 + 8
	hashLen   = 32
)

var ErrNotImplemented = errors.New("transfer: 未实现（见里程碑）")

// Manifest 记录目标端已验证完成的块位图，断点续传的依据。
// TODO(M2.5)：接收端按块更新、发送端续传时跳过已完成块。
type Manifest struct {
	Path      string `json:"path"`
	Size      int64  `json:"size"`
	ChunkBits []byte `json:"chunk_bits"` // bit i = 第 i 块已验证
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
	var sum [hashLen]byte
	if _, err := io.ReadFull(r, sum[:]); err != nil {
		return 0, nil, err
	}
	if sha256.Sum256(data) != sum {
		return 0, nil, fmt.Errorf("chunk %d: hash mismatch", idx)
	}
	return idx, data, nil
}

// SendFile 经 QUIC 把 path 的内容发给 raddr，先发送 grant 头。
// TODO(M2.5)：限速（grant.RateLimit）、按 Manifest 跳过已传块。
func SendFile(ctx context.Context, path, raddr string, tlsConf *tls.Config, grant *api.TransferGrant) error {
	addr, err := net.ResolveUDPAddr("udp", raddr)
	if err != nil {
		return err
	}
	udp, err := net.ListenUDP("udp", nil)
	if err != nil {
		return err
	}
	defer udp.Close()
	conn, err := quic.Dial(ctx, udp, addr, tlsConf, &quic.Config{MaxIdleTimeout: 30 * time.Second})
	if err != nil {
		return fmt.Errorf("dial %s: %w", raddr, err)
	}
	defer conn.CloseWithError(0, "")
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return err
	}
	defer stream.Close()

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
	stream.SetReadDeadline(time.Now().Add(60 * time.Second))
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

// Serve 在数据面监听上分发流：探测回 PONG；传输先验 grant 再落盘。
// selfID 用于校验"这份授权确实是发给我这台机器的"。
func Serve(ln *quic.Listener, selfID string, verify GrantVerifier) error {
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
				go handleStream(stream, selfID, verify)
			}
		}()
	}
}

func handleStream(stream *quic.Stream, selfID string, verify GrantVerifier) {
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
		if verify == nil || !verify(&grant) || grant.Dst != selfID {
			fmt.Printf("拒绝未授权传输 %s（src=%s）\n", grant.ID, grant.Src)
			return
		}
		if err := recvInto(br, stream, grant.DstPath); err != nil {
			fmt.Printf("接收 %s 失败：%v\n", grant.ID, err)
		} else {
			fmt.Printf("接收完成：%s -> %s\n", grant.ID, grant.DstPath)
		}
	default:
		fmt.Printf("未知流类型 %q\n", head)
	}
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

// Probe 探测一个数据面地址的可达性与往返时延（QUIC 通道）。
// UDP 被防火墙拦截时在此失败，由调用方尝试 TCP 回退（M3）。
func Probe(ctx context.Context, addr string, tlsConf *tls.Config) (rtt time.Duration, err error) {
	a, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return 0, err
	}
	udp, err := net.ListenUDP("udp", nil)
	if err != nil {
		return 0, err
	}
	defer udp.Close()
	start := time.Now()
	conn, err := quic.Dial(ctx, udp, a, tlsConf, &quic.Config{
		MaxIdleTimeout:         5 * time.Second,
		HandshakeIdleTimeout:   2 * time.Second,
	})
	if err != nil {
		return 0, err
	}
	defer conn.CloseWithError(0, "")
	st, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return 0, err
	}
	defer st.Close()
	if _, err := st.Write([]byte("PING\n")); err != nil {
		return 0, err
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(st, buf); err != nil {
		return 0, err
	}
	if string(buf) != "PONG\n" {
		return 0, fmt.Errorf("bad pong")
	}
	return time.Since(start), nil
}

// RelayPipe 让本节点作为一跳中继：一边收一边转发，纯内存不落盘。
// TODO(M3)：按 grant.Relays 建立逐跳链、双向 io.Copy、限速。
func RelayPipe(ctx context.Context, left, right string, tlsConf *tls.Config) error {
	return ErrNotImplemented
}
