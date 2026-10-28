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
	sent  int64 // 线缆字节（限速与吞吐统计用）
	done  int64 // 逻辑字节（进度用；增量传输时远大于 sent）
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
	// Cap 是发送端能力声明。目前只用于告诉接收端"我能处理分段帧"。
	// 放在这里而不是新开一行是刻意的：旧接收端会忽略未知 JSON 字段，
	// 所以在 FFJ1 头里多加一行会让旧接收端把它当帧数据读，直接崩坏。
	Cap     []string `json:"cap,omitempty"`
	SHA256  string   `json:"sha256"`
	Size    int64    `json:"size"`
	CertB64 string   `json:"cert"` // 源端证书 DER
	SigB64  string   `json:"sig"`  // ed25519 签名 over grantID|sha256|size
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
		Cap:     []string{"seg"},
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
		// 加密时不宣告 "seg" 能力：分段帧里的**字面量是明文**，发送侧本来
		// 就会禁用（见 sendShareOnce），但接收端听到 "seg" 就会只回滚动
		// 签名、不回整块复用表 —— 结果加密路径既拿不到 seg 计划、也拿不到
		// reuseIdx，增量彻底失效（实测加密下内容相同的 32MiB 重传仍全量发
		// 33.5MB）。不宣告 seg，接收端就回退到复用表，而引用帧只搬接收端
		// 自己的数据、不含明文，加密下仍然安全可用。
		mf.Cap = nil
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

// writeStallTimeout 是"连续这么久没有一次写成功"的判定阈值，**不是**整条
// 份额的寿命上限。
//
// 之前这个 90 秒被当成绝对死线、在发送循环外设置一次（循环内从不续期），
// 于是份额的**总耗时**被夹死在 90 秒：1GB@2MB/s = 500 秒的份额，从第 90 秒
// 起每次 Write 立刻 i/o timeout。sendShare 只有 3 次尝试，每次也只能靠
// HAVE 位图前进约 90 秒，单份额上限约 270 秒——大文件在慢链路上必然失败，
// 而且不是"卡住才失败"，是稳定慢也失败。
//
// 声明为 var 便于测试覆盖（生产值 90s，与读侧 frameIdleTimeout 对称）。
var writeStallTimeout = 90 * time.Second

// armWriteDeadline 把写超时重新推到 now+writeStallTimeout，实现"停滞即失败"。
//
// 与读侧 idleReader（每帧静默即失败）是同一套语义：监控的是"停住了没有"，
// 而不是"总共花了多久"。不支持 deadline 的实现（测试用 buffer 等）静默跳过。
func armWriteDeadline(w io.Writer) {
	if w == nil || writeStallTimeout <= 0 {
		return
	}
	if d, ok := w.(interface{ SetWriteDeadline(time.Time) error }); ok {
		_ = d.SetWriteDeadline(time.Now().Add(writeStallTimeout))
	}
}

// countingWriter 把**实际写出去的字节**累加进限速器与进度回调。
type countingWriter struct {
	w    io.Writer
	rate *taskRate
	// progress=false 时只计线缆字节与限速，不推进逻辑进度
	// （增量帧的进度由调用方按整块长度单独 advance）。
	progress bool
}

func (c *countingWriter) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > progressWriteSlice {
			chunk = chunk[:progressWriteSlice]
		}
		// 每一片写之前续期：写超时的语义是"这一片卡住多久算死"，
		// 不是"整条份额最多活多久"（见 writeStallTimeout）。
		armWriteDeadline(c.w)
		n, err := c.w.Write(chunk)
		if n > 0 {
			total += n
			if c.rate != nil {
				c.rate.take(int64(n))
				if c.progress {
					c.rate.advance(int64(n))
				}
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
	// 滚动校验签名索引（rsync 风格）：可在**任意偏移**上匹配，块小得多，
	// 所以错位和 4KB 小改都能只传改动部分。
	var sigIdx *sigIndex
	reusedBlocks := 0
	segFrames := 0
	var segSaved int64
	if rd, ok := stream.(interface{ SetReadDeadline(time.Time) error }); ok {
		// 15s 而不是 3s：接收端发 HAVE 前要扫描已有文件算分块哈希（增量
		// 协商），大文件可能要一两秒；3 秒会直接放弃协商，增量永远不生效。
		// 旧版接收端会立刻回 HAVE，不会让正常路径变慢。
		rd.SetReadDeadline(time.Now().Add(30 * time.Second))
		line, lerr := readLineMax(stream, haveLineMax)
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
			// 行格式演进（全部向后兼容）：
			//   HAVE <bits>                      最早版本：只有续传位图
			//   HAVE <bits> <reuse>              上一版：整块复用表
			//   HAVE <bits> - <sig>              本版：rsync 风格签名
			//   HAVE <bits> - -                  本版：签名在同一 grant 的
			//                                    另一条流上（只发一次以省带宽）
			fields := strings.Split(strings.TrimPrefix(line, "HAVE "), " ")
			var reuseStr, sigStr string
			if len(fields) > 1 {
				reuseStr = fields[1]
			}
			if len(fields) > 2 {
				sigStr = fields[2]
			}
			if bits, derr := base64.StdEncoding.DecodeString(fields[0]); derr == nil {
				for i := 0; i*8 < len(bits); i++ {
					for b := 0; b < 8; b++ {
						if bits[i]&(1<<b) != 0 {
							have[int64(i*8+b)] = true
						}
					}
				}
			}
			switch {
			case sigStr != "" && sigStr != "-":
				if sig := decodeSignature(sigStr); sig != nil {
					sigIdx = sig.index()
					putSigIndex(grant.ID, sigIdx)
				}
			case sigStr == "-":
				// 接收端明确表示"本流不带签名"：签名在另一条流上。
				// 只有这种情况才需要等，否则（目标不存在/旧版对端）
				// 绝不能等——实测会把首传白白拖慢 3 秒。
				if ix := getSigIndex(grant.ID, 3*time.Second); ix != nil {
					sigIdx = ix
				}
			case reuseStr != "" && reuseStr != "-":
				if rt := decodeReuseTable(reuseStr); rt != nil {
					reuseIdx = rt.index()
				}
			}
		}
	}

	buf := make([]byte, ChunkSize)
	// 增量计划：整文件预扫描一次（跨分块连续匹配），各流只查表。
	// 不能每流各扫各的——多流是按 idx%n 交错分配分块的，流内相邻块并不
	// 相邻，跨块状态续写会错位（实测第 12~15 块重建哈希全部不符）。
	// 如果接收端已经"全都有"（HAVE 位图覆盖本份额要发的每一块），就没必要
	// 再跑整文件滚动预扫描——那是纯 CPU 浪费。实测 64MiB 内容完全相同的
	// 重传：全量传 1.14s，而增量路径因为预扫描要 1.96s，越"优化"越慢。
	// 上界取块数，不能沿用发送循环的"endCh<0 就一直加到 EOF"写法：
	// 那个循环靠 ReadAt 返回 EOF 才 break，这里的纯计数循环没有 break 条件，
	// 会变成死循环（空文件第一个就中）。
	chunks := (mf.Size + int64(ChunkSize) - 1) / int64(ChunkSize)
	pending := 0
	for idx := startCh + int64(r); idx < chunks && (endCh < 0 || idx < endCh); idx += int64(n) {
		if !have[idx] {
			pending++
		}
	}
	var segPlan map[int64][]byte
	if pending == 0 {
		tracef("[tl] %s 流%d 无待发块（接收端已完整持有），跳过增量预扫描", grant.ID, r)
	}
	if sigIdx != nil && enc == nil && pending > 0 {
		segPlan = getSegPlan(grant.ID, func() map[int64][]byte {
			return planSegChunks(f, sigIdx, mf.Size)
		})
		if segPlan != nil {
			log.Printf("[tl] %s 分段计划：%d/%d 块可用增量（跨分块连续匹配）",
				grant.ID, len(segPlan), (mf.Size+int64(ChunkSize)-1)/int64(ChunkSize))
		}
	}
	// 写超时不再在这里设一次绝对死线：由 countingWriter 在**每一片**写入
	// 之前续期（见 writeStallTimeout / armWriteDeadline），否则整条份额的
	// 总耗时被夹死在 90 秒，慢链路必失败。
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
					cw := &countingWriter{w: stream, rate: rate, progress: false}
					if err := WriteRefFrame(cw, idx, off); err != nil {
						return err
					}
					rate.advance(int64(len(data)))
					reusedBlocks++
					continue
				}
			}
			// rsync 风格分段：用滚动校验在**任意偏移**上找匹配，把本块表达成
			// 「从接收端旧文件拷贝若干段 + 少量字面量」。只有编码比原文更小时
			// 才值得发（内容全新时立刻回退普通帧）。
			// 加密传输（share/get 的密钥专递）时禁用分段帧：
			// 分段帧里的**字面量**是明文，若照发就会绕过端到端加密。
			// 引用/复用帧不涉及明文（只搬接收端自己的数据），仍可用。
			// rsync 风格分段：整文件预扫描（跨分块连续滚动匹配）已算出
			// 每个分块的「拷贝指令 + 字面量」编码，且只保留比原文更小的。
			if payload, ok := segPlan[idx]; ok {
				cw := &countingWriter{w: stream, rate: rate, progress: false}
				if err := WriteSegFrame(cw, idx, payload); err != nil {
					return err
				}
				rate.advance(int64(len(data)))
				segFrames++
				segSaved += int64(len(data) - len(payload))
				continue
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
			cw := &countingWriter{w: stream, rate: rate, progress: true}
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
	// 哨兵直写 stream（不过计数包装），所以这里也要单独续期一次写超时。
	armWriteDeadline(stream)
	if err := WriteFrame(stream, -1, []byte{}); err != nil {
		return err
	}
	if reusedBlocks > 0 {
		log.Printf("[tl] %s 流%d 增量：%d 块由接收端本地复用（省 %d 字节）",
			grant.ID, r, reusedBlocks, int64(reusedBlocks)*int64(ChunkSize))
	}
	if segFrames > 0 {
		log.Printf("[tl] %s 流%d 滚动匹配：%d 块走分段帧（省 %d 字节）",
			grant.ID, r, segFrames, segSaved)
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
