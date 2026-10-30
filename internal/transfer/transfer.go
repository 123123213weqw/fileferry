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
	"log"
	"strings"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
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
	"sync/atomic"
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
// 同时向映射端口 ±32 扇形喷洒（对称 NAT 的端口预测：对端出口
// 映射端口通常在已观测映射附近递增），提高对穿成功率。
func SendOpeners(udp net.PacketConn, target string, dur time.Duration) {
	addr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		return
	}
	spray := []*net.UDPAddr{addr}
	if port := addr.Port; port > 33 && port < 65500 {
		for _, d := range []int{-32, -16, -8, -4, -2, -1, 1, 2, 4, 8, 16, 32} {
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
	if n > ChunkSize+4096 { // 密文多 16B AEAD 标签；delta COPY 帧（密文 32B）也在限内
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
// 目录模式（grant.IsDir）额外携带 Path（树内相对路径，**参与签名**，
// 防中继改写落盘位置）与 Mode/Mtime（属性保留，不参与签名——
// 属性不构成内容完整性边界）。单文件模式 Path 为空，payload 与
// 旧版完全一致，新旧版本互通。
type Manifest struct {
	GrantID  string `json:"grant_id"`
	SHA256   string `json:"sha256"`
	Size     int64  `json:"size"`
	Path     string `json:"path,omitempty"` // 目录模式：树内相对路径（参与签名）
	Mode     uint32 `json:"mode,omitempty"` // 权限位（不参与签名）
	Mtime    int64  `json:"mtime,omitempty"` // 修改时间 Unix 秒（不参与签名）
	CertB64  string `json:"cert"` // 源端证书 DER
	SigB64   string `json:"sig"`  // ed25519 签名 over manifestPayload
}

func manifestPayload(m *Manifest) []byte {
	if m.Path != "" {
		return []byte(m.GrantID + "|" + m.Path + "|" + m.SHA256 + "|" + strconv.FormatInt(m.Size, 10))
	}
	return []byte(m.GrantID + "|" + m.SHA256 + "|" + strconv.FormatInt(m.Size, 10))
}

// BuildManifest 计算文件指纹并用 tlsConf 中的节点证书签名（发送端）。
func BuildManifest(grantID, path, relPath string, tlsConf *tls.Config) (*Manifest, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
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
		Path:    relPath,
		Mode:    uint32(st.Mode().Perm()),
		Mtime:   st.ModTime().Unix(),
		CertB64: base64.StdEncoding.EncodeToString(cert.Certificate[0]),
	}
	m.SigB64 = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, manifestPayload(m)))
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
	if !ed25519.Verify(pub, manifestPayload(m), sig) {
		return fmt.Errorf("manifest: 签名无效")
	}
	if m.GrantID != grant.ID {
		return fmt.Errorf("manifest: grantID 不符")
	}
	if m.Path != "" && !grant.IsDir {
		return fmt.Errorf("manifest: 带相对路径但 grant 非目录模式")
	}
	if m.Path == "" && grant.IsDir {
		return fmt.Errorf("manifest: 目录模式清单缺少相对路径")
	}
	if m.Path != "" && !SafeRelPath(m.Path) {
		return fmt.Errorf("manifest: 非法相对路径 %q", m.Path)
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
	mf, err := BuildManifest(grant.ID, path, "", tlsConf)
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
	if grant.Delta {
		n = 1 // delta 配方是顺序语义（字面量/COPY 序列），单流承载
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
	lim := newBandwidth(grant.RateLimit, int64(n))
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
			errCh <- sendShare(ctx, f, o, grant, mf, enc, startCh, endCh, r, n, lim)
		}(r, thisOpen)
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

// SendTree 目录模式发送：递归枚举 root 下的常规文件，逐个签名清单
//（带树内相对路径，防篡改落盘位置），K 个 worker 并行发送（K=
// grant.Streams，每文件单流）。目录模式下 grant 只签发一次，密钥
// 只上报一次；每文件密钥由主密钥 + 相对路径 HKDF 派生（共用密钥会
// 跨文件重用 nonce，破坏 AEAD）。限速预算整树均分。
// 跳过软链接与非常规文件（v1 不复制符号链接）；错误即中止，已到
// 文件保留在目的端（断点续传按 HAVE 位图补齐）。
func SendTree(ctx context.Context, root string, open StreamOpener, tlsConf *tls.Config, grant *api.TransferGrant) (int64, int, error) {
	root = filepath.Clean(root)
	type item struct {
		path, rel string
	}
	var files []item
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() { // 跳过软链接/设备等
			return nil
		}
		if strings.HasPrefix(d.Name(), ".ff-") || strings.HasSuffix(d.Name(), ".ffpart") {
			return nil // 传输中间产物
		}
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil {
			return rerr
		}
		if !SafeRelPath(filepath.ToSlash(rel)) {
			return fmt.Errorf("相对路径异常 %q", rel)
		}
		files = append(files, item{p, filepath.ToSlash(rel)})
		return nil
	})
	if err != nil {
		return 0, 0, err
	}
	k := grant.Streams
	if k < 1 {
		k = 1
	}
	if k > 8 {
		k = 8
	}
	// 密钥只上报一次：目录模式整树一把主密钥，文件密钥按相对路径派生
	var masterKey []byte
	var prefix []byte
	if grant.Enc {
		var c *streamCipher
		var err error
		if c, masterKey, err = newStreamCipher(); err != nil {
			return 0, 0, err
		}
		prefix = c.noncePrefix
		if keyDeliverer == nil {
			return 0, 0, fmt.Errorf("grant 要求加密但未配置密钥上报")
		}
		if err := keyDeliverer(grant.ID, append(append([]byte{}, masterKey...), prefix...)); err != nil {
			return 0, 0, fmt.Errorf("密钥上报失败: %w", err)
		}
	}
	lim := newBandwidth(grant.RateLimit, int64(k))
	items := make(chan item, len(files))
	errCh := make(chan error, k)
	var wg sync.WaitGroup
	var bytes int64
	var count int64
	for w := 0; w < k; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			// 每 worker 一条持久 QUIC 连接，文件流在其上按需开
			//（省逐文件握手）；TCP/交换台退化为逐文件直拨
			var op *dirOpener
			if grant.Mode == "switch" {
				op = newDirOpener(ctx, api.Hop{}, tlsConf, open) // 交换台：经台配对
			} else {
				op = newDirOpener(ctx, grant.Hops[1], tlsConf, nil) // 直连/中继：池化 QUIC
			}
			defer op.closeAll()
			// 批量打包：本 worker 的全部文件在**同一条流**上依次发段
			//（清单+数据+哨兵+ACK），省掉逐文件建流/握手——TCP 回退
			// 与交换台模式收益最大（免逐文件 TLS/配对），WAN 上小文件
			// 每文件 4 RTT → 2 RTT。流断则重拨续发（HAVE 位图跳块）。
			var st Stream
			var stClose func()
			stAlive := false
			openTree := func() error {
				s, c, err := op.openFor()
				if err != nil {
					return err
				}
				st, stClose, stAlive = s, c, true
				return nil
			}
			closeTree := func() {
				if stAlive {
					stClose()
				}
				st, stClose, stAlive = nil, nil, false
			}
			defer closeTree()
			if err := openTree(); err != nil {
				errCh <- fmt.Errorf("建树流失败: %w", err)
				return
			}
			for it := range items {
				if ctx.Err() != nil {
					return
				}
				var delivered bool
				var lastSize int64
				for attempt := 0; attempt < 3 && !delivered; attempt++ {
					f, err := os.Open(it.path)
					if err != nil {
						errCh <- err
						return
					}
					mf, err := BuildManifest(grant.ID, it.path, it.rel, tlsConf)
					if err != nil {
						f.Close()
						errCh <- err
						return
					}
					var enc *streamCipher
					if grant.Enc {
						if enc, err = cipherFromMaterial(DeriveFileKey(masterKey, it.rel), prefix); err != nil {
							f.Close()
							errCh <- err
							return
						}
					}
					serr := sendFileOnStream(ctx, st, f, grant, mf, enc, 0, -1, 0, 1, lim)
					f.Close()
					if serr == nil {
						delivered = true
						lastSize = mf.Size
						break
					}
					// 流已坏：重拨整树流重发本文件（接收端 HAVE 跳过已收块）
					closeTree()
					op.drop()
					if aerr := openTree(); aerr != nil {
						errCh <- fmt.Errorf("%s: %w（重拨失败: %v）", it.rel, serr, aerr)
						return
					}
				}
				if !delivered {
					errCh <- fmt.Errorf("%s: 3 次尝试均失败", it.rel)
					return
				}
				atomic.AddInt64(&bytes, lastSize)
				atomic.AddInt64(&count, 1)
			}
			// 树收尾哨兵：接收端读到 FFEND 即知全树完成（交换台目的端
			// 据此停止建连）。ACK 尽力读，读不到无妨。
			if stAlive {
				if wd, ok := st.(interface{ SetWriteDeadline(time.Time) error }); ok {
					wd.SetWriteDeadline(time.Now().Add(10 * time.Second))
				}
				st.Write([]byte("FFEND\n"))
				if rd, ok := st.(interface{ SetReadDeadline(time.Time) error }); ok {
					rd.SetReadDeadline(time.Now().Add(10 * time.Second))
				}
				_, _ = io.ReadFull(st, make([]byte, 4))
			}
		}(w)
	}
	for _, it := range files {
		items <- it
	}
	close(items)
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			return bytes, int(count), err
		}
	}
	return bytes, int(count), nil
}

// dirOpener 目录模式的每 worker 连接池：QUIC 下第一条文件流时建连，
// 后续文件在**同一连接**上开新流（省掉逐文件 TLS 握手，小文件场景
// 吞吐提升一个量级）；QUIC 不可用自动回退 TCP（逐文件，端口+1），
// 交换台模式（base 非空）逐文件经台配对——交换台的配对语义是
// 一连接一流，无法池化。发送失败后 drop() 丢弃连接，下个文件重建。
type dirOpener struct {
	ctx     context.Context
	hop     api.Hop
	tlsConf *tls.Config
	base    StreamOpener // 交换台模式专用
	mu      sync.Mutex
	conn    *quic.Conn
}

func newDirOpener(ctx context.Context, hop api.Hop, tlsConf *tls.Config, base StreamOpener) *dirOpener {
	return &dirOpener{ctx: ctx, hop: hop, tlsConf: tlsConf, base: base}
}

func (p *dirOpener) openFor() (Stream, func(), error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.base != nil { // 交换台：配对语义决定一连接一流
		return p.base()
	}
	if p.conn != nil {
		st, err := p.conn.OpenStreamSync(p.ctx)
		if err == nil {
			return st, func() { st.Close() }, nil
		}
		p.conn.CloseWithError(0, "")
		p.conn = nil
	}
	// 优先 QUIC 池化；失败回退 TCP（DialStream 端口+1 约定）
	if p.hop.Proto != "tcp" && p.hop.Addr != "" {
		if udpAddr, err := net.ResolveUDPAddr("udp", p.hop.Addr); err == nil {
			var conn *quic.Conn
			if sharedTransport != nil {
				conn, err = sharedTransport.Dial(p.ctx, udpAddr, p.tlsConf, quicConf())
			} else {
				udp, lerr := net.ListenUDP("udp", nil)
				if lerr == nil {
					_ = udp.SetReadBuffer(4 << 20)
					_ = udp.SetWriteBuffer(4 << 20)
					conn, err = quic.Dial(p.ctx, udp, udpAddr, p.tlsConf, quicConf())
					if err != nil {
						udp.Close()
					}
				}
			}
			if err == nil {
				st, serr := conn.OpenStreamSync(p.ctx)
				if serr == nil {
					p.conn = conn
					return st, func() { st.Close() }, nil
				}
				conn.CloseWithError(0, "")
			}
		}
	}
	return DialStream(p.ctx, p.hop.Addr, "tcp", p.tlsConf)
}

func (p *dirOpener) drop() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.conn != nil {
		p.conn.CloseWithError(0, "")
		p.conn = nil
	}
}

func (p *dirOpener) closeAll() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.conn != nil {
		p.conn.CloseWithError(0, "")
		p.conn = nil
	}
}

// OpenerDirect 返回常规模式的建流函数（拨 firstHop）。QUIC 建流
// 失败时自动降级 TCP 重试——签发时刻的边协议可能与当前网络状态
// 有 30 秒竞态窗口，拨号层兜底比取消任务友好。
func OpenerDirect(ctx context.Context, firstHop api.Hop, tlsConf *tls.Config) StreamOpener {
	return func() (Stream, func(), error) {
		s, closeFn, err := DialStream(ctx, firstHop.Addr, firstHop.Proto, tlsConf)
		if err == nil || firstHop.Proto != "quic" {
			return s, closeFn, err
		}
		return DialStream(ctx, firstHop.Addr, "tcp", tlsConf)
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
// lim 为本 grant 全体流共享的限速器（nil=不限速）。
func sendShare(ctx context.Context, f *os.File, open StreamOpener, grant *api.TransferGrant, mf *Manifest, enc *streamCipher, startCh, endCh int64, r, n int, lim *bandwidth) error {
	// 连接失败/中断 → 重连重发整个份额（最多 3 次）：多流交错下
	// 单条连接的块缺口会让收发两端同时死等，必须自愈
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if err := sendShareOnce(ctx, f, open, grant, mf, enc, startCh, endCh, r, n, lim); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}
	return fmt.Errorf("份额 [%d,%d) 第 %d 流 3 次尝试均失败: %w", startCh, endCh, r, lastErr)
}

// bandwidth 是 grant 级令牌桶限速器（M4）：RateLimit 字节/秒在全部
// 并行流间共享，整树/整文件总量不超配额。0 = 不限速。
type bandwidth struct {
	mu     sync.Mutex
	rate   int64   // 字节/秒
	budget float64 // 当前可用字节
	last   time.Time
}

func newBandwidth(totalPerSec int64, shares int64) *bandwidth {
	if totalPerSec <= 0 {
		return nil
	}
	if shares < 1 {
		shares = 1
	}
	return &bandwidth{rate: totalPerSec / shares, last: time.Now(), budget: float64(totalPerSec/shares) * 0.2}
}

// wait 消费 n 字节，必要时睡眠到配额恢复。
func (b *bandwidth) wait(n int) {
	if b == nil || b.rate <= 0 {
		return
	}
	for {
		b.mu.Lock()
		now := time.Now()
		b.budget += now.Sub(b.last).Seconds() * float64(b.rate)
		b.last = now
		if b.budget > float64(b.rate)*0.5 {
			b.budget = float64(b.rate) * 0.5 // 突发上限：半秒配额
		}
		if b.budget >= float64(n) {
			b.budget -= float64(n)
			b.mu.Unlock()
			return
		}
		need := (float64(n) - b.budget) / float64(b.rate)
		b.mu.Unlock()
		if need > 0 {
			time.Sleep(time.Duration(need * float64(time.Second)))
		}
	}
}

func sendShareOnce(ctx context.Context, f *os.File, open StreamOpener, grant *api.TransferGrant, mf *Manifest, enc *streamCipher, startCh, endCh int64, r, n int, lim *bandwidth) error {
	stream, closeConn, err := open()
	if err != nil {
		return fmt.Errorf("建流失败: %w", err)
	}
	defer closeConn()
	return sendFileOnStream(ctx, stream, f, grant, mf, enc, startCh, endCh, r, n, lim)
}

// sendFileOnStream 在**既有流**上发送一个文件段：FFJ1 头（grant+清单）、
// HAVE 交换、数据帧、完成哨兵、等 ACK。批量打包时同一流上依次发多个
// 文件段（各段 ACK 独立），最后由调用方写 FFEND 收尾。
func sendFileOnStream(ctx context.Context, stream Stream, f *os.File, grant *api.TransferGrant, mf *Manifest, enc *streamCipher, startCh, endCh int64, r, n int, lim *bandwidth) error {
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
	// 流头握手：接收端回一行——BASE（delta 校验和清单 / "-" 无基准）
	// 或 HAVE（断点续传位图）。3 秒无反馈=旧版接收端，全发。
	have := map[int64]bool{}
	deadline := 3 * time.Second
	if grant.Delta {
		deadline = 15 * time.Second // basis 清单可能较大
	}
	var line string
	var lerr error
	if rd, ok := stream.(interface{ SetReadDeadline(time.Time) error }); ok {
		rd.SetReadDeadline(time.Now().Add(deadline))
		line, lerr = readLine(stream)
		log.Printf("[tl] %s 段%d 握手行完成 err=%v head=%.12s", grant.ID, r, lerr, line)
	}
	if grant.Delta && lerr == nil && strings.HasPrefix(line, "BASE ") {
		rest := strings.TrimSpace(strings.TrimPrefix(line, "BASE "))
		if rest == "-" {
			log.Printf("[tl] %s 段%d delta 无基准，全量传输", grant.ID, r)
		} else {
			// 分块清单：BASE <size> + 若干 BASEC <b64> + BASEEND
			basisSize, perr1 := strconv.ParseInt(rest, 10, 64)
			var raw []byte
			if perr1 == nil {
				var parts []byte
				for {
					pl, plerr := readLine(stream)
					if plerr != nil {
						break
					}
					pl = strings.TrimSpace(pl)
					if pl == "BASEEND" {
						break
					}
					if b64, ok := strings.CutPrefix(pl, "BASEC "); ok {
						if b, derr := base64.StdEncoding.DecodeString(b64); derr == nil {
							parts = append(parts, b...)
						}
					}
				}
				raw = parts
			}
			sums, sumerr := parseBasis(raw)
			if perr1 != nil || sumerr != nil || len(sums) == 0 {
				// 接收端已在配方模式（回了 BASE）：绝不能错位回块路径——
				// 退化为**纯字面量配方**（协议兼容，等价全量，仍走 delta 帧语义）
				log.Printf("[tl] %s 段%d delta 清单解析失败，字面量配方全量", grant.ID, r)
				em := &streamEmitter{stream: stream, enc: enc, lim: lim}
				if ferr := buildRecipe(ctx, f, mf.Size, newIndex(nil, 0), em); ferr != nil {
					return fmt.Errorf("delta 字面量配方失败: %w", ferr)
				}
				return finishFile(stream, grant, r)
			}
			em := &streamEmitter{stream: stream, enc: enc, lim: lim}
			if rerr := buildRecipe(ctx, f, mf.Size, newIndex(sums, basisSize), em); rerr != nil {
				return fmt.Errorf("delta 配方构建失败: %w", rerr)
			}
			return finishFile(stream, grant, r) // 配方发完：哨兵+ACK
		}
	}
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
			lim.wait(len(data)) // 限速按密文计（真实线上字节数）
			if err := WriteFrame(stream, idx, data); err != nil {
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
	return finishFile(stream, grant, r)
}

// finishFile 完成哨兵 + ACK 握手：接收端收齐全部份额（或 delta 配方）
// 才落盘改名并回 ACK；QUIC 下直接关连接会丢弃对端未读完的数据，必须等 ACK。
func finishFile(stream Stream, grant *api.TransferGrant, r int) error {
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

// streamEmitter 把 delta 配方写上流：字面量/COPY 帧（加密时按配方序号
// 密封，与接收端 feedDelta 的计数器对齐），限速按线上字节数。
type streamEmitter struct {
	stream Stream
	enc    *streamCipher
	lim    *bandwidth
	nonce  int64
}

func (e *streamEmitter) literal(b []byte) error {
	data := b
	if e.enc != nil {
		data = e.enc.seal(e.nonce, data)
	}
	e.nonce++
	e.lim.wait(len(data))
	return WriteFrame(e.stream, frameDeltaLiteral, data)
}

func (e *streamEmitter) copy(off, length int64) error {
	data := encodeCopyToken(off, length)
	if e.enc != nil {
		data = e.enc.seal(e.nonce, data)
	}
	e.nonce++
	e.lim.wait(len(data))
	return WriteFrame(e.stream, frameDeltaCopy, data)
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

// syncWrite 控制落盘是否 fsync：开启 = 掉电也保证已确认文件完整
//（强持久性）；关闭 = 对齐 rsync/cp 的默认语义（完整性仍由逐块+
// 全文件 SHA-256 与原子改名保证），小文件吞吐提升一个量级。
var syncWrite bool

func SetSyncWrite(v bool) { syncWrite = v }

// PathAllowed 报告路径是否被允许（发送端源路径与接收端目的路径通用）。
func PathAllowed(p string) bool { return pathGuard == nil || pathGuard(p) }

// SafeRelPath 校验目录模式的树内相对路径：非绝对、无 ".."、Clean 后
// 不升级——防止恶意清单把文件写到目的根之外。
func SafeRelPath(p string) bool {
	if p == "" || filepath.IsAbs(p) || strings.HasPrefix(p, "/") {
		return false
	}
	c := filepath.Clean(p)
	if c == ".." || strings.HasPrefix(c, "../") || strings.Contains(c, "\x00") {
		return false
	}
	return true
}

// basisCache delta 基准校验和缓存：按路径记忆上次求和结果，**追加
// 增量维护**（tail/日志场景的核心）：文件变长时只补算新增块+重算
// 尾部短块，O(追加量) 而非 O(全文件)。安全性：校验和是内容寻址的，
// 前缀若实际被改，旧块的强和对不上新内容 → 匹配退化为字面量全传
//（自愈），绝不会 COPY 出错内容；文件变短则整表作废重算。
type basisEntry struct {
	size int64
	sums []blockSum
}

var basisCache = struct {
	mu sync.Mutex
	m  map[string]basisEntry
}{m: map[string]basisEntry{}}

// cachedBasisSums 返回 path 当前可用的校验和（命中含增量补算）。
// f 由调用方打开（读偏移用）；miss 时返回 ok=false。
func cachedBasisSums(path string, st os.FileInfo, f *os.File) ([]blockSum, bool) {
	basisCache.mu.Lock()
	e, ok := basisCache.m[path]
	basisCache.mu.Unlock()
	if !ok || st.Size() < e.size {
		return nil, false // 无记录或文件变短：整表重算
	}
	if st.Size() == e.size {
		return e.sums, true
	}
	// 追加增量：从最后一个完整块边界起重算（尾部短块因变长必须重算），
	// 新增区间串行补算（追加量通常很小）
	from := (e.size / DeltaBlock) * DeltaBlock
	sums := e.sums[:from/DeltaBlock]
	buf := make([]byte, DeltaBlock)
	for off := from; off < st.Size(); off += DeltaBlock {
		n := DeltaBlock
		if st.Size()-off < int64(n) {
			n = int(st.Size() - off)
		}
		if _, err := f.ReadAt(buf[:n], off); err != nil {
			return nil, false // 读失败退回全量路径
		}
		rs := newRollingSum(DeltaBlock)
		sums = append(sums, blockSum{Weak: rs.init(buf[:n]), Strong: strongSum(buf[:n])})
	}
	basisCache.mu.Lock()
	basisCache.m[path] = basisEntry{size: st.Size(), sums: sums}
	basisCache.mu.Unlock()
	return sums, true
}

func cacheBasisSums(path string, st os.FileInfo, bs []blockSum) {
	basisCache.mu.Lock()
	defer basisCache.mu.Unlock()
	if len(basisCache.m) > 256 {
		basisCache.m = map[string]basisEntry{}
	}
	basisCache.m[path] = basisEntry{size: st.Size(), sums: bs}
}

// groupKey 接收组/完成缓存的键：单文件模式只看 grantID；目录模式
// 一个 grant 承载多文件，按相对路径区分。
func groupKey(grant *api.TransferGrant, mf *Manifest) string {
	if mf.Path == "" {
		return grant.ID
	}
	return grant.ID + "\x00" + mf.Path
}

// RecvStream 按认证清单接收：循环读 manifest 行并验签、进组收块，
// 直到对端发 FFEND（批量树的收尾哨兵）或关流（EOF，旧版单文件发送端）。
// 一条流可依次承载多个文件（批量打包）：目录模式发送端在同一流上
// 连发多个 清单+数据+哨兵+ACK 段，省掉逐文件建流/握手。
// 返回 ended=true 表示读到 FFEND（树接收完毕）。
func RecvStream(br *bufio.Reader, stream Stream, grant *api.TransferGrant, roots *x509.CertPool) (ended bool) {
	for {
		line, err := br.ReadString('\n') // manifest 行（grant 行由调用方已读）
		if err == io.EOF {
			return false // 对端关流：旧版单文件发送端，或树已发完
		}
		if err != nil {
			fmt.Println("manifest 读取失败：", err)
			return false
		}
		if strings.TrimSpace(line) == "FFEND" {
			stream.Write([]byte("ACK\n")) // 让源端哨兵流尽快收尾（尽力而为）
			return true
		}
		var mf Manifest
		if err := json.Unmarshal([]byte(line), &mf); err != nil {
			fmt.Println("manifest 解析失败：", err)
			return false
		}
		if err := mf.Verify(grant, roots); err != nil {
			fmt.Printf("拒绝传输 %s：%v\n", grant.ID, err)
			return false
		}
		var deckey *streamCipher
		if grant.Enc {
			var kerr error
			// 目录模式按清单相对路径派生文件密钥（与发送端 SendTree 对称）
			if deckey, kerr = cipherForGrant(grant.ID, mf.Path); kerr != nil {
				fmt.Printf("接收 %s 取密钥失败：%v\n", grant.ID, kerr)
				return false
			}
		}
		g, err := groupFor(grant, &mf, deckey)
		if err == ErrAlreadyDone {
			// 文件此前已完整落盘（重试流的迟到份额）。握手必须与发送端
			// 的期待对齐，否则双方各自错位（历史"任务报失败"收尾问题）：
			//   delta：发送端等 BASE 行 → 回 "BASE -"，排空其全量块到
			//          哨兵再 ACK，批量流上的后续文件不受影响
			//   常规：发送端等 HAVE 行但拿到 ACK 即全发 → 排空到 EOF
			if grant.Delta {
				stream.Write([]byte("BASE -\n"))
				for {
					_, data, derr := ReadFrame(br)
					if derr != nil || len(data) == 0 {
						break
					}
				}
				stream.Write([]byte("ACK\n"))
			} else {
				stream.Write([]byte("ACK\n"))
				if s2, ok := stream.(interface{ SetReadDeadline(time.Time) error }); ok {
					s2.SetReadDeadline(time.Now().Add(90 * time.Second))
				}
				io.Copy(io.Discard, br)
				return false
			}
			fmt.Printf("迟到流确认：%s %q（文件此前已完整落盘）\n", grant.ID, mf.Path)
			continue
		}
		if err != nil {
			fmt.Printf("接收 %s 建组失败：%v\n", grant.ID, err)
			return false
		}
		// 流头握手（发送端在写头后主动读一行，见 sendFileOnStream）：
		//   delta 配方模式 → BASE 行（basis 逐块校验和清单，或 BASE - 无基准）
		//   常规模式       → HAVE 行（断点续传位图）
		if w, ok := stream.(interface{ SetWriteDeadline(time.Time) error }); ok {
			w.SetWriteDeadline(time.Now().Add(15 * time.Second))
		}
		if g.recipe {
			payload, perr := encodeBasis(g.basisSums)
			if perr != nil {
				fmt.Printf("接收 %s 编码 basis 失败：%v\n", grant.ID, perr)
				g.closeBasis()
				return false
			}
			// 分块行协议：readLine 有 8KB 上限，大 basis 的清单必须拆行
			//（100GB basis ≈ 88MB 清单，单行不可行）。BASE 行给基准大小，
			// BASEC 行承载 base64 分片，BASEEND 收口。
			fmt.Fprintf(stream, "BASE %d\n", g.basisSize)
			const chunk = 4 * 1024 // base64 后 5461 字符，留足 readLine 8KB 上限余量
			for len(payload) > 0 {
				n := len(payload)
				if n > chunk {
					n = chunk
				}
				fmt.Fprintf(stream, "BASEC %s\n", base64.StdEncoding.EncodeToString(payload[:n]))
				payload = payload[n:]
			}
			fmt.Fprintf(stream, "BASEEND\n")
			if err := g.feedDelta(br, g.deckey); err != nil {
				fmt.Printf("接收 %s（delta）失败：%v\n", grant.ID, err)
				g.closeBasis()
				return false
			}
		} else {
			if grant.Delta {
				fmt.Fprintf(stream, "BASE -\n") // 无基准：发送端立即全量，不等超时
			} else {
				fmt.Fprintf(stream, "HAVE %s\n", base64.StdEncoding.EncodeToString(g.haveBits()))
			}
			if err := g.feed(br, g.deckey); err != nil {
				fmt.Printf("接收 %s 失败：%v\n", grant.ID, err)
				return false
			}
		}
		select {
		case <-g.finished:
		case <-time.After(10 * time.Minute):
			fmt.Printf("接收 %s 超时：未收齐全部块\n", grant.ID)
			return false
		}
		if g.finErr != nil {
			fmt.Printf("接收 %s 校验失败：%v（文件已丢弃）\n", grant.ID, g.finErr)
			return false
		}
		stream.Write([]byte("ACK\n"))
		fmt.Printf("接收完成：%s（src=%s，%d 字节）-> %s\n", grant.ID, grant.Src, mf.Size, g.finalPath)
	}
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
	size      int64 // 文件精确字节数（进度键）
	dirty     int   // 距上次位图落盘的新块数
	mode      uint32 // 权限位保留（0 = 不设置）
	mtime     int64  // 修改时间保留（0 = 不设置）
	key       string // recvGroups/completed 的键（groupKey 计算）
	recipe    bool   // delta 配方模式：完成由哨兵触发，不走块计数/HAVE
	basis     *os.File // delta 基准文件（目的端已有内容），用毕关闭
	basisSize int64
	basisSums []blockSum // BASE 行负载（delta 时发给发送端）
}

// ErrAlreadyDone 表示该 grant 的文件已完整落盘（迟到的重试流）。
var ErrAlreadyDone = errors.New("grant 已完成")

var (
	recvMu     sync.Mutex
	recvGroups = map[string]*recvGroup{}
	completed  = map[string]time.Time{} // 已完成的 grant，2h 内拒绝重放
)

func groupFor(grant *api.TransferGrant, mf *Manifest, deckey *streamCipher) (*recvGroup, error) {
	// 目录模式：落盘路径 = 目的根 + 树内相对路径（清单签名覆盖路径，
	// SafeRelPath 防 .. 逃逸；路径仍须过白名单）
	finalPath := grant.DstPath
	if mf.Path != "" {
		if !grant.IsDir || !SafeRelPath(mf.Path) {
			return nil, fmt.Errorf("目录模式路径校验失败：%q", mf.Path)
		}
		finalPath = filepath.Join(grant.DstPath, filepath.FromSlash(mf.Path))
	}
	if !PathAllowed(finalPath) {
		return nil, fmt.Errorf("目的路径不在白名单内：%s", finalPath)
	}
	key := groupKey(grant, mf)
	recvMu.Lock()
	defer recvMu.Unlock()
	for k, t := range completed { // 陈年条目卫生清扫
		if time.Since(t) > 2*time.Hour {
			delete(completed, k)
		}
	}
	if t, ok := completed[key]; ok && time.Since(t) < 2*time.Hour {
		// 文件已完整落盘：不是攻击，是发送端重试流晚到。回 ACK 让
		// 对端成功收尾（"文件到达但任务报失败"的收尾问题）。
		return nil, ErrAlreadyDone
	}
	if g, ok := recvGroups[key]; ok {
		return g, nil
	}
	dir := filepath.Dir(finalPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	tmp, err := os.CreateTemp(dir, ".ff-*")
	if err != nil {
		return nil, err
	}
	n := (mf.Size + ChunkSize - 1) / ChunkSize // 空文件 = 0 块：哨兵即完成
	// delta 模式：目的端已有同路径文件则作为基准，回 BASE 校验和清单
	//（发送端只发差异）；无基准回 BASE -（发送端立即全量，省 3s 等待）。
	// 基准损坏时弱/强和匹配不上 → 发送端退化为字面量（自愈），最终
	// 内容仍由整文件 SHA-256 把关。
	var basis *os.File
	var basisSize int64
	var basisSums []blockSum
	basisErr := error(nil)
	if grant.Delta {
		if bf, err := os.Open(finalPath); err == nil {
			if bst, serr := bf.Stat(); serr == nil && bst.Size() > 0 {
				bs, hit := cachedBasisSums(finalPath, bst, bf)
				if !hit {
					bs, serr = BasisSumsFile(bf)
					if serr != nil {
						bf.Close()
						basisErr = serr
						bs = nil
					} else {
						cacheBasisSums(finalPath, bst, bs)
					}
				}
				if basisErr == nil {
					basis, basisSize, basisSums = bf, bst.Size(), bs
				}
			} else {
				bf.Close()
			}
		}
	}
	g := &recvGroup{
		grantID:   grant.ID,
		key:       key,
		wantSHA:   mf.SHA256,
		size:      mf.Size,
		deckey:    deckey,
		finalPath: finalPath,
		tmp:       tmp,
		tmpName:   tmp.Name(),
		expected:  n,
		got:       map[int64]bool{},
		finished:  make(chan struct{}),
		mode:      mf.Mode,
		mtime:     mf.Mtime,
	}
	if grant.Delta {
		g.recipe = basis != nil && basisErr == nil
		g.basis, g.basisSize = basis, basisSize
		g.basisSums = basisSums
	} else {
		g.loadProgress() // 断点续传：加载同目标文件的历史进度（位图+临时文件）
	}
	recvGroups[key] = g
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
func (g *recvGroup) saveProgress() {
	// g.got 会被并行流并发写（多份额交错收块），迭代必须持锁——
	// 否则 runtime fatal: concurrent map iteration and map write，
	// 进程直接死亡（压测 1GB 多流实锤）。快照后立即放锁再落盘。
	g.mu.Lock()
	bits := make([]byte, (g.expected+7)/8)
	for i := range g.got {
		if i >= 0 && i/8 < int64(len(bits)) {
			bits[i/8] |= 1 << (i % 8)
		}
	}
	size, sha, tmpName := g.size, g.wantSHA, g.tmpName
	g.mu.Unlock()
	type progress struct {
		Size    int64  `json:"size"`
		SHA256  string `json:"sha256"`
		TmpName string `json:"tmp"`
		Bits    []byte `json:"bits"`
	}
	b, _ := json.Marshal(progress{Size: size, SHA256: sha, TmpName: tmpName, Bits: bits})
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
			g.checkDone()
			return nil
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
		shouldSave := g.dirty >= 8
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

// closeBasis 关闭并清空 delta 基准句柄（finalize/失败路径都要调）。
func (g *recvGroup) closeBasis() {
	if g.basis != nil {
		g.basis.Close()
		g.basis = nil
	}
}

// feedDelta 按配方重建：-2 字面量帧（顺序追加）、-3 COPY 帧（从 basis
// 区间复制）、哨兵（len==0）→ finalize。加密时字面量按配方序号解密
//（发送端同序计数器），COPY 内容不出网无需解密。重建结果由 finalize
// 的整文件 SHA-256 对清单把关——任何错配/损坏/篡改都在这里被拒绝。
func (g *recvGroup) feedDelta(br *bufio.Reader, deckey *streamCipher) error {
	off := int64(0) // 重建写出偏移
	nonce := int64(0)
	for {
		fri, data, err := ReadFrame(br)
		if err != nil {
			if err == io.EOF {
				return fmt.Errorf("delta 流意外 EOF（哨兵未到）")
			}
			return err
		}
		if len(data) == 0 { // 完成哨兵
			g.closeBasis()
			g.forceDone()
			return nil
		}
		// 帧头 idx 是 uint32 线格式：负值 token 读回来是 2^32+idx，
		// 统一转回 int64 再匹配（4294967294→-2 字面量、…293→-3 COPY）
		if fri > 0x7fffffff {
			fri -= 1 << 32
		}
		switch fri {
		case frameDeltaLiteral:
			if deckey != nil {
				if data, err = deckey.open(nonce, data); err != nil {
					return fmt.Errorf("delta 字面量解密失败: %w", err)
				}
			}
			if _, err := g.tmp.WriteAt(data, off); err != nil {
				return err
			}
			off += int64(len(data))
		case frameDeltaCopy:
			if deckey != nil {
				if data, err = deckey.open(nonce, data); err != nil {
					return fmt.Errorf("delta COPY 解密失败: %w", err)
				}
			}
			boff, blen, terr := decodeCopyToken(data)
			if terr != nil {
				return terr
			}
			if boff < 0 || blen < 0 || boff+blen > g.basisSize {
				return fmt.Errorf("delta COPY 越界: off=%d len=%d basis=%d", boff, blen, g.basisSize)
			}
			if err := copyRangeAt(g.tmp, off, g.basis, boff, blen); err != nil {
				return fmt.Errorf("delta COPY 复制失败: %w", err)
			}
			off += blen
		default:
			return fmt.Errorf("delta 流未知帧 idx=%d", fri)
		}
		nonce++
	}
}

// checkDone 哨兵/EOF 时刻的完成复核：空文件（0 块）只等哨兵；
// 多份额下最后一份的哨兵也可能先于 finalize 到达。
func (g *recvGroup) checkDone() {
	g.mu.Lock()
	complete := int64(len(g.got)) >= g.expected && !g.done
	if complete {
		g.done = true
	}
	g.mu.Unlock()
	if complete {
		g.finalize()
	}
}

// copyRangeAt 分块复制 basis 区间到重建文件（限内存，256KB 步长）。
func copyRangeAt(dst *os.File, dstOff int64, src *os.File, srcOff, length int64) error {
	buf := make([]byte, 256<<10)
	var done int64
	for done < length {
		n := int64(len(buf))
		if length-done < n {
			n = length - done
		}
		if _, err := src.ReadAt(buf[:n], srcOff+done); err != nil {
			return err
		}
		if _, err := dst.WriteAt(buf[:n], dstOff+done); err != nil {
			return err
		}
		done += n
	}
	return nil
}

// forceDone delta 配方模式：哨兵即完成（无块计数语义）。
func (g *recvGroup) forceDone() {
	g.mu.Lock()
	if g.done {
		g.mu.Unlock()
		return
	}
	g.done = true
	g.mu.Unlock()
	g.finalize()
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
	if syncWrite {
		if err := g.tmp.Sync(); err != nil {
			fail(err)
			return
		}
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
	// 属性保留（清单携带，不参与签名）：权限位与修改时间，对齐
	// scp -p / rsync -a 的基本语义（属主/组需要 root，v1 不保留）
	if g.mode != 0 {
		_ = os.Chmod(g.finalPath, os.FileMode(g.mode))
	}
	if g.mtime != 0 {
		_ = os.Chtimes(g.finalPath, time.Unix(g.mtime, 0), time.Unix(g.mtime, 0))
	}
	g.clearProgress()
	recvMu.Lock()
	delete(recvGroups, g.key)
	completed[g.key] = time.Now()
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

// Probe 探测一个数据面地址：QUIC 与 TCP 各测一次往返，都通时若
// TCP 的 RTT 不劣于 QUIC 的 1.5 倍则选 TCP——UDP 被策略限速的网络
// 里 TCP 吞吐常有数量级优势（实测 4.5×），RTT 相近时应优选；
// UDP 被禁则自然回退 TCP。返回往返时延与选定协议。
func Probe(ctx context.Context, addr string, tlsConf *tls.Config) (time.Duration, string, error) {
	rtt, proto, _, err := ProbeWithAlt(ctx, addr, tlsConf)
	return rtt, proto, err
}

// ProbeWithAlt 返回（胜者协议, 副协议或空, rtt, err）。两者皆通时
// 副协议非空——混流将各流分散到两条协议通道。
func ProbeWithAlt(ctx context.Context, addr string, tlsConf *tls.Config) (time.Duration, string, string, error) {
	qRTT, qErr := probeOne(ctx, addr, "quic", tlsConf)
	tRTT, tErr := probeOne(ctx, addr, "tcp", tlsConf)
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

func probeOne(ctx context.Context, addr, proto string, tlsConf *tls.Config) (time.Duration, error) {
	start := time.Now()
	s, closeConn, err := DialStream(ctx, addr, proto, tlsConf)
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
