package transfer

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fileferry/internal/api"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

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
// frameIdleTimeout：一帧之内多久收不到任何字节就判定流已被破坏。
//
// 存在的理由：被墙网络里最常见的干扰形式是**截断或吞掉流的中段**，
// 而不是干净地关连接。此时接收端会一直等"还没到的字节"，原来只有
// 调用方的 90 秒写超时 / 10 分钟 ACK 超时兜底——实测一次 1MB 传输
// 因此卡了 91 秒才报失败，用户完全无法判断是卡死还是在慢慢传。
//
// 取 30 秒：正常链路单帧（4MB）即使 1MB/s 也只要 4 秒，30 秒静默
// 只可能是流断了。
//
// 声明为 var 便于测试覆盖（生产值 30s）。
var frameIdleTimeout = 30 * time.Second

// idleReader 在每次 Read 前设置读超时，实现"帧内静默即失败"。
type idleReader struct {
	r  io.Reader
	to time.Duration
}

func (ir *idleReader) Read(p []byte) (int, error) {
	if d, ok := ir.r.(interface{ SetReadDeadline(time.Time) error }); ok && ir.to > 0 {
		_ = d.SetReadDeadline(time.Now().Add(ir.to))
	}
	return ir.r.Read(p)
}

// tracef 打印数据面跟踪日志。默认关闭：`ffctl put` 是给人和脚本用的
// 命令，默认刷这些内部时序日志会淹没真正的输出（scp 不会这么吵）。
// 排查时设 FF_DEBUG=1 打开。
func tracef(format string, args ...any) {
	if os.Getenv("FF_DEBUG") == "" {
		return
	}
	log.Printf(format, args...)
}

func ReadFrame(r io.Reader) (idx int64, data []byte, err error) {
	ir := &idleReader{r: r, to: frameIdleTimeout}
	rh := io.Reader(ir)
	if _, ok := r.(interface{ SetReadDeadline(time.Time) error }); !ok {
		rh = r // 不支持 deadline 的实现（测试用 buffer 等）保持原样
	}
	hdr := make([]byte, headerLen)
	if _, err := io.ReadFull(rh, hdr); err != nil {
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
	if _, err := io.ReadFull(rh, data); err != nil {
		return 0, nil, err
	}
	var sum [32]byte
	if _, err := io.ReadFull(rh, sum[:]); err != nil {
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

// progressWriteSlice 是进度/限速的计数粒度。
//
// 为什么不直接按 Write 调用计数：一帧数据是 4MB，底层一次 Write 就是
// 4MB；在 300KB/s 的链路上这一写要阻塞 13 秒，期间计数不会动。于是
// 进度条按 20% 跳变，停滞检测更会把"300KB/s 稳定推进"误判成
// "0 KB/s 完全没动"（实测日志确实是这么打的）。
//
// 切成 64KB 后，任务限速与进度都按真实写入量平滑推进。TCP/QUIC 的流
// 都是字节流，分片写不改变线格式。
const progressWriteSlice = 64 << 10

// countingWriter 把**实际写出去的字节**累加进限速器与进度回调。
type countingWriter struct {
	w    io.Writer
	rate *taskRate
}

func (c *countingWriter) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > progressWriteSlice {
			chunk = chunk[:progressWriteSlice]
		}
		n, err := c.w.Write(chunk)
		if n > 0 {
			total += n
			if c.rate != nil {
				c.rate.take(int64(n))
			}
		}
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, io.ErrShortWrite
		}
		p = p[n:]
	}
	return total, nil
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
	tracef("[tl] %s 流%d 建流%v 写头完成", grant.ID, r, tB.Sub(tA))
	// 断点续传：读接收端的 HAVE 位图（HAVE <base64>）。逐字节读行
	// 避免缓冲吞掉后续 ACK；3 秒无反馈=旧版/无进度，全发。
	have := map[int64]bool{}
	// 增量：接收端已有文件的「块哈希 → 偏移」。命中就发引用帧，不传数据。
	var reuseIdx map[string]int64
	reusedBlocks := 0
	if rd, ok := stream.(interface{ SetReadDeadline(time.Time) error }); ok {
		// 15s 而不是 3s：接收端发 HAVE 前要扫描已有文件算分块哈希（增量
		// 协商），大文件可能要一两秒；3 秒会直接放弃协商，增量永远不生效。
		// 旧版接收端会立刻回 HAVE，不会让正常路径变慢。
		rd.SetReadDeadline(time.Now().Add(15 * time.Second))
		line, lerr := readLine(stream)
		if os.Getenv("FF_DEBUG_HAVE") != "" {
			n := len(line)
			head := line
			if len(head) > 40 {
				head = head[:40]
			}
			log.Printf("[have] 流%d len=%d err=%v head=%q", r, n, lerr, head)
		}
		tracef("[tl] %s 流%d HAVE读取完成 err=%v", grant.ID, r, lerr)
		if lerr == nil && strings.HasPrefix(line, "HAVE ") {
			// 行格式：HAVE <bits> [<reuse>]
			// 旧版接收端只有 bits 段；旧版发送端读到带 reuse 的行会
			// base64 解码失败 → 位图为空 → 全量发送（正确但无优化）。
			rest := strings.TrimPrefix(line, "HAVE ")
			if sp := strings.IndexByte(rest, ' '); sp >= 0 {
				if rt := decodeReuseTable(rest[sp+1:]); rt != nil {
					reuseIdx = rt.index()
				}
				rest = rest[:sp]
			}
			if bits, err := base64.StdEncoding.DecodeString(rest); err == nil {
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
			// 增量：本块内容在接收端已有文件里存在（按 SHA-256 比对）
			// 就不传数据，只发 8 字节偏移。
			if len(reuseIdx) > 0 {
				if off, ok := reuseIdx[blockHash(data)]; ok {
					cw := &countingWriter{w: stream, rate: rate}
					if err := WriteRefFrame(cw, idx, off); err != nil {
						return err
					}
					reusedBlocks++
					continue
				}
			}
			if enc != nil {
				data = enc.seal(idx, data) // 端到端加密：帧哈希对密文（传输完整性），manifest 对明文
			}
			// 用逐次写入计数的流包装：进度与限速按"实际写出去的字节"
			// 累计，而不是按整块。
			//
			// 为什么必须这样：块大小 4MB，在 300KB/s 的慢链路上一块要写
			// 13 秒。按块计数的话，前 6 秒进度是 0、进度条按 20% 跳，
			// 停滞检测也会把"正在稳定慢传"误判成"完全没动"（实测日志
			// 打出 "quic 太慢（0 KB/s）"，其实是 300KB/s 在稳定推进）。
			cw := &countingWriter{w: stream, rate: rate}
			if err := WriteFrame(cw, idx, data); err != nil {
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
	if reusedBlocks > 0 {
		log.Printf("[tl] %s 流%d 增量：%d 块由接收端本地复用（省 %d 字节）",
			grant.ID, r, reusedBlocks, int64(reusedBlocks)*int64(ChunkSize))
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
