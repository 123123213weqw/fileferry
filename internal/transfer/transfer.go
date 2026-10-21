// Package transfer 实现数据面：QUIC 流式分块传输、逐块校验、
// 断点续传与中继转发。
//
// 帧格式：[4B magic "FFCH"][4B chunk idx][8B length][data][32B sha256(data)]
// 每个 chunk 独立校验、独立确认，链路中途换链（M3）后从第一个
// 未完成块继续，不重传整个文件。
package transfer

import (
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
	"time"

	"github.com/quic-go/quic-go"
)

const (
	ChunkSize = 4 << 20 // 4 MiB
	Magic     = "FFCH"
	headerLen = 4 + 4 + 8
	hashLen   = 32
)

var ErrNotImplemented = errors.New("transfer: 未实现（见里程碑）")

// Manifest 记录目标端已验证完成的块位图，断点续传的依据。
type Manifest struct {
	Path      string `json:"path"`
	Size      int64  `json:"size"`
	ChunkBits []byte `json:"chunk_bits"` // bit i = 第 i 块已验证
}

// LoadManifest 读取 dstPath 对应的 .ffpart 清单；不存在则新建空清单。
func LoadManifest(dstPath string, size int64) *Manifest {
	p := dstPath + ".ffpart"
	var m Manifest
	if b, err := os.ReadFile(p); err == nil && json.Unmarshal(b, &m) == nil {
		return &m
	}
	n := (size + ChunkSize - 1) / ChunkSize
	return &Manifest{Path: dstPath, Size: size, ChunkBits: make([]byte, (n+7)/8)}
}

func (m *Manifest) Save() error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return os.WriteFile(m.Path+".ffpart", b, 0o600)
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

// SendFile 把 path 的内容经 QUIC 发给 raddr。
// TODO(M2)：限速（grant.RateLimit）、按 Manifest 跳过已传块。
func SendFile(ctx context.Context, path, raddr string, tlsConf *tls.Config) error {
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
			return nil
		}
		if rerr != nil {
			return rerr
		}
	}
}

// Serve 在数据面监听上收文件，落盘到 outDir，逐块校验。
// TODO(M2)：grant 验签、临时名 + 原子改名、Manifest 维护与断点续传。
func Serve(ln *quic.Listener, outDir string) error {
	for {
		conn, err := ln.Accept(context.Background())
		if err != nil {
			return err
		}
		go func() {
			defer conn.CloseWithError(0, "")
			stream, err := conn.AcceptStream(context.Background())
			if err != nil {
				return
			}
			defer stream.Close()
			if err := recvInto(stream, outDir); err != nil {
				fmt.Println("recv:", err)
			}
		}()
	}
}

func recvInto(stream io.Reader, outDir string) error {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(outDir, ".ff-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	for {
		_, data, err := ReadFrame(stream)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if _, err := tmp.Write(data); err != nil {
			return err
		}
	}
}

// RelayPipe 让本节点作为一跳中继：一边收一边转发，纯内存不落盘。
// TODO(M3)：按 grant.Relays 建立逐跳链、双向 io.Copy、限速。
func RelayPipe(ctx context.Context, left, right string, tlsConf *tls.Config) error {
	return ErrNotImplemented
}
