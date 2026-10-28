package transfer

import (
	"bufio"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fileferry/internal/api"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// RecvStream 按认证清单接收一条流的份额。返回 error 表示**这个份额没有
// 成功收下**（清单验签失败、建组失败、链路提前断开、校验不符、等待超时）。
//
// 为什么必须返回 error：之前它返回 void，失败只打一行日志，交换台模式的
// switchRecvShare 于是无条件 `return nil`，上层计数永远为 0，运维看到的是
// "接收完成"——验签失败、块不齐、哈希不符全都报成功。文件是否落盘与"这条
// 流是否成功"必须能被上层判定，否则失败会被静默吞掉。
func RecvStream(br *bufio.Reader, stream Stream, grant *api.TransferGrant, roots *x509.CertPool) error {
	line, err := readHeaderLine(br) // manifest 行（grant 行由调用方已读）
	if err != nil {
		return fmt.Errorf("manifest 读取失败：%w", err)
	}
	var mf Manifest
	if err := json.Unmarshal([]byte(line), &mf); err != nil {
		return fmt.Errorf("manifest 解析失败：%w", err)
	}
	if err := mf.Verify(grant, roots); err != nil {
		return fmt.Errorf("拒绝传输：%w", err)
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
		// 增量：把目标位置**已有文件**的分块哈希一并带过去，发送端
		// 据此跳过相同块。旧版发送端会因整行 base64 解码失败而退化为
		// 全量发送，行为仍然正确。
		g.reuseOnce.Do(func() {
			// 已经全都有（断点续传的最后一条流、或内容完全相同的重传）：
			// 不必再扫一遍旧文件算分块哈希/滚动签名。64MiB 扫描约 0.2s，
			// 而这一轮根本没有数据要发。
			if got, want := g.progress(); want > 0 && got >= want {
				tracef("[tl] %s 已持有全部 %d 块，跳过增量协商扫描", grant.ID, want)
				return
			}
			// 发送端声明支持分段帧时，改用 rsync 风格签名：块更小、
			// 且可由发送端在**任意偏移**上滚动匹配，能处理错位。
			// 不支持的话退回上一版的整块复用表（只认 4MB 对齐）。
			if hasCap(mf.Cap, "seg") {
				st, serr := os.Stat(g.dstPath)
				if serr == nil && st.Mode().IsRegular() && st.Size() > 0 {
					bs := chooseBlockSize(st.Size())
					if sig, err := buildSignature(g.dstPath, bs); err == nil {
						g.sigEnc = sig.encode()
						if g.sigEnc != "" {
							log.Printf("%s 增量协商：旧文件 %d 字节，按 %d 字节分块生成 %d 块签名",
								grant.ID, st.Size(), bs, sig.Count)
						}
					}
				}
			}
			if g.sigEnc == "" {
				reuse := buildReuseTable(g.dstPath, grant.ChunkSize)
				g.reuseEnc = reuse.encode()
				if g.reuseEnc != "" {
					log.Printf("%s 增量协商：目标已有 %d 块可复用（%d 字节）",
						grant.ID, len(reuse.Blocks), reuse.Size)
				}
			}
		})
		bits := base64.StdEncoding.EncodeToString(g.haveBits())
		// 只有第一条流带完整签名；其余用 "-" 占位，发送端从共享缓存取。
		sendSig := g.sigEnc != "" && g.sigSent.CompareAndSwap(false, true)
		switch {
		case sendSig:
			// 第三字段是签名；第二字段填 "-" 占位（保持字段位稳定）
			fmt.Fprintf(stream, "HAVE %s - %s\n", bits, g.sigEnc)
		case g.sigEnc != "":
			fmt.Fprintf(stream, "HAVE %s - -\n", bits)
		case g.reuseEnc != "":
			fmt.Fprintf(stream, "HAVE %s %s\n", bits, g.reuseEnc)
		default:
			fmt.Fprintf(stream, "HAVE %s\n", bits)
		}
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
		// drain 到对端关闭。只设一个 deadline：之前连着设两次
		// （10 分钟紧接 90 秒），实际生效的是后者，10 分钟那行是死代码。
		if s, ok := stream.(interface{ SetReadDeadline(time.Time) error }); ok {
			s.SetReadDeadline(time.Now().Add(90 * time.Second))
		}
		io.Copy(io.Discard, stream)
		return nil // 文件此前已完整落盘，这条迟到流本来就该成功收尾
	}
	if err != nil {
		return fmt.Errorf("建组失败：%w", err)
	}
	if err := g.feed(br); err != nil {
		return fmt.Errorf("收块失败：%w", err)
	}
	select {
	case <-g.finished:
	case <-time.After(10 * time.Minute):
		got, want := g.progress()
		return fmt.Errorf("等待收齐全部块超时（已收 %d/%d）", got, want)
	}
	if g.finErr != nil {
		return fmt.Errorf("校验失败（文件已丢弃）：%w", g.finErr)
	}
	// ACK 单独给一个明确的超时，而不是继承 HAVE 阶段的 5 秒（见上）。
	if w, ok := stream.(interface{ SetWriteDeadline(time.Time) error }); ok {
		w.SetWriteDeadline(time.Now().Add(30 * time.Second))
	}
	if _, err := stream.Write([]byte("ACK\n")); err != nil {
		// 文件已完整落盘并核验过，ACK 丢了对端会重试，重试时走
		// ErrAlreadyDone 分支重发 ACK。这里不该把成果报成失败。
		fmt.Printf("接收完成但 ACK 写失败 %s：%v（文件已落盘）\n", grant.ID, err)
		return nil
	}
	fmt.Printf("接收完成：%s（src=%s，%d 字节）-> %s\n", grant.ID, grant.Src, mf.Size, grant.DstPath)
	return nil
}

// recvOne 是数据面监听上的接收入口（已读 head 与 grant 行）。
func recvOne(br *bufio.Reader, stream Stream, grant *api.TransferGrant, tlsConf *tls.Config) {
	var roots *x509.CertPool
	if tlsConf != nil {
		roots = tlsConf.RootCAs
	}
	if err := RecvStream(br, stream, grant, roots); err != nil {
		fmt.Printf("接收 %s 失败：%v\n", grant.ID, err)
	}
}

// recvGroup 按"唯一块计数"协调并行接收：收齐 manifest 声明的全部
// 块才校验全文件哈希、原子改名并唤醒等待者。重放旧流只会重复写
// 相同的块（WriteAt 幂等），无法提前触发完成，也无法篡改内容。
type recvGroup struct {
	mu        sync.Mutex
	grantID   string
	wantSHA   string
	keys      map[api.NodeID]*streamCipher // 多源：每个源一把；单源只有主源
	ranges    []api.SourceSpec             // grant 里的分片区间（块 → 源）
	finalPath string
	dstPath   string // 最终落盘路径（增量扫描已有文件用）
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
	reused    int64         // 由增量引用填充的块数（仅统计用）
	// reuseOnce/reuseEnc 缓存增量协商行：扫描已有文件要读全文件算哈希，
	// 每个并行流各扫一遍会成倍放大（4 流 × 100MB）。只算一次。
	reuseOnce sync.Once
	reuseEnc  string
	sigEnc    string // rsync 风格签名（与 reuseEnc 二选一）
	// sigSent 保证签名只随**第一条**流发出：HAVE 是每流各发一次的，
	// 4 条流各带 102KB 签名就是 410KB 下行（实测比 rsync 的校验量还大）。
	sigSent atomic.Bool
}

// ErrAlreadyDone 表示该 grant 的文件已完整落盘（迟到的重试流）。
var ErrAlreadyDone = errors.New("grant 已完成")

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

	// 锁外取密钥：每个源取一次，各并行流共用。
	// 多源模式下每个源有自己的密钥，必须各取一把并按块区间选用。
	keys := map[api.NodeID]*streamCipher{}
	if grant.Enc {
		for _, src := range grant.AllSources() {
			key, kerr := cipherForGrant(grant.ID, string(src))
			if kerr != nil {
				return nil, fmt.Errorf("取密钥失败（源 %s）: %w", src, kerr)
			}
			keys[src] = key
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
		keys:      keys,
		finalPath: grant.DstPath,
		dstPath:   grant.DstPath,
		tmp:       tmp,
		tmpName:   tmp.Name(),
		expected:  n,
		ranges:    grant.Sources,
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
		// 目标变了：旧位图与它记录的临时文件都已无用。之前直接 return，
		// 于是放弃的任务会在目的目录里留下与源文件等大的 .ff-* 和 .ffpart，
		// 谁也不会再清理。
		g.discardStaleProgress(p.TmpName)
		return
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

// discardStaleProgress 删除作废的进度 sidecar 与它记录的临时文件。
//
// TmpName 来自 sidecar JSON，是不可信输入：只接受"与目标文件同目录、且
// 文件名形如 .ff-*"的路径，否则拒绝删除（不然一个伪造的 sidecar 就能让
// 接收端删掉任意文件）。
func (g *recvGroup) discardStaleProgress(tmpName string) {
	if tmpName != "" {
		dir := filepath.Dir(g.finalPath)
		if filepath.Dir(tmpName) == dir && strings.HasPrefix(filepath.Base(tmpName), ".ff-") {
			os.Remove(tmpName)
		} else {
			log.Printf("%s 进度文件记录的临时路径可疑，拒绝删除：%q", g.grantID, tmpName)
		}
	}
	g.clearProgress()
}

// saveProgress 位图落盘（断点续传依据）。
// saveProgress 必须自行加锁：多流共享同一个 recvGroup，调用点都在
// 释放锁之后，直接遍历 g.got 会与其他流的写入并发——Go 的 map 并发
// 读写会直接 panic（race detector 实测在 40MB 多流场景触发）。
func (g *recvGroup) saveProgress() {
	// 先把临时文件刷到盘，再写位图。
	//
	// 顺序不能反：位图声称"块 N 已收"必须以保证块 N 的数据真的落盘为前提。
	// 之前直接写位图、数据还留在 page cache 里，断电后位图与临时文件内容
	// 不一致 —— 续传接管临时文件时 len(got)==expected 立刻成立，直接进
	// finalize，全文件哈希不符，白跑一整遍并硬失败一次。
	//
	// Sync 不持 g.mu：它可能要等磁盘，持锁会把同组其他流一起堵住。
	g.mu.Lock()
	tmp := g.tmp
	g.mu.Unlock()
	if tmp != nil {
		_ = tmp.Sync()
	}

	g.mu.Lock()
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
	part := g.partPath()
	g.mu.Unlock()

	// 原子写：中途崩溃/ENOSPC 时留下的是旧位图或没有位图，而不是被截断的
	// 半行 JSON（截断的 JSON 解析失败 → 整个进度作废，等于从头再来）。
	writeFileAtomic(part, b, 0o600)
}

// writeFileAtomic 以 tmp+rename 写入，避免读者看到写了一半的文件。
func writeFileAtomic(path string, b []byte, perm os.FileMode) {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".ffpart-*")
	if err != nil {
		return
	}
	name := f.Name()
	if _, err := f.Write(b); err != nil {
		f.Close()
		os.Remove(name)
		return
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(name)
		return
	}
	if err := f.Close(); err != nil {
		os.Remove(name)
		return
	}
	if err := os.Chmod(name, perm); err != nil {
		os.Remove(name)
		return
	}
	if err := os.Rename(name, path); err != nil {
		os.Remove(name)
	}
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

// progress 返回"已收块数 / 总块数"（持锁读，供日志与判据使用）。
func (g *recvGroup) progress() (got, want int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.got), int(g.expected)
}

// markComplete 尝试把组标记为"已收齐全部块"，只有**唯一一个**调用者会拿到
// true，也只有它有权调用 finalize。
//
// 为什么必须是"唯一一个"：finalize 第一行就是 close(g.finished)，第二次调用
// 会 panic: close of closed channel，而 agent 没有 recover——整进程退出，
// 不是单任务失败。
//
// 为什么判定和置位必须在同一个临界区：之前 fillFromLocal 在锁外读
// len(g.got)，与并发 storeBlock/fillFromLocal 的写入竞争，会触发
// fatal error: concurrent map read and map write（同样不可 recover）。
// 触发形状很日常：4 条流并行，最后一块由某条流的 ref 帧补齐，同时另一条
// 流超时重试、重发了同一条 ref 帧。
func (g *recvGroup) markComplete() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.done || len(g.got) != int(g.expected) {
		return false
	}
	g.done = true
	return true
}

// storeBlock 写入一个已就绪的明文分块，并推进进度/完成判定。
//
// 抽出来是因为三条路径（普通帧、引用帧、分段帧）的落盘逻辑必须完全一致，
// 否则会出现"某种帧永远不触发落盘"这类只在特定路径复现的问题。
func (g *recvGroup) storeBlock(idx int64, data []byte) error {
	if _, err := g.tmp.WriteAt(data, idx*int64(ChunkSize)); err != nil {
		return err
	}
	g.mu.Lock()
	if !g.got[idx] {
		g.got[idx] = true
		g.dirty++
	}
	needFlush := g.dirty >= 8 || len(g.got) == int(g.expected)
	if needFlush {
		g.dirty = 0
	}
	g.mu.Unlock()
	if needFlush {
		g.saveProgress()
	}
	if g.markComplete() {
		g.finalize()
	}
	return nil
}

// fillFromLocal 用**本机已有文件**里的一段内容填充第 idx 块（增量）。
//
// 这是"引用"而不是"传输"：数据从旧文件直接搬到临时文件，不过网络、
// 也不解密（发送端没加密它，因为没有传输）。
//
// 完整性：这里不做逐块校验——引用帧只有 8 字节偏移，没有块哈希可比。
// 终态由整文件 SHA-256（manifest，源端签名）兜底：若旧文件在协商后
// 被改动，最终校验会失败并丢弃结果，不会静默产出错误文件。
func (g *recvGroup) fillFromLocal(idx, srcOff int64) error {
	if srcOff < 0 {
		return fmt.Errorf("引用偏移为负：%d", srcOff)
	}
	src, err := os.Open(g.dstPath)
	if err != nil {
		return fmt.Errorf("引用块 %d 失败（无法打开已有文件）：%w", idx, err)
	}
	defer src.Close()
	// 只读本块需要的字节数：最后一块可能不足 ChunkSize
	want := int64(ChunkSize)
	g.mu.Lock()
	if (idx+1)*int64(ChunkSize) > g.size {
		want = g.size - idx*int64(ChunkSize)
	}
	g.mu.Unlock()
	if want <= 0 {
		return fmt.Errorf("引用块 %d 的期望长度非法：%d", idx, want)
	}
	buf := make([]byte, want)
	n, rerr := src.ReadAt(buf, srcOff)
	if int64(n) != want {
		// 旧文件被截短，或对端给了越界偏移——回退为失败，让上层重试，
		// 而不是写入不完整的数据。
		return fmt.Errorf("引用块 %d 读取不足：需 %d 实得 %d（%v）", idx, want, n, rerr)
	}
	if _, err := g.tmp.WriteAt(buf, idx*int64(ChunkSize)); err != nil {
		return err
	}
	g.mu.Lock()
	if !g.got[idx] {
		g.got[idx] = true
		g.dirty++
		g.reused++
	}
	needFlush := g.dirty >= 8 || len(g.got) == int(g.expected)
	pending := g.dirty
	g.mu.Unlock()
	if needFlush {
		g.saveProgress()
		g.mu.Lock()
		g.dirty -= pending
		g.mu.Unlock()
	}
	// 完成判定必须走 markComplete：它把"最后一块是谁补上的"这个竞争
	// 收进同一个临界区，保证 finalize 只被调用一次（见其注释）。
	if g.markComplete() {
		g.finalize()
	}
	return nil
}

// feed 消费一条连接的帧流直到哨兵或 EOF；每收到新块检查是否集齐。
// deckey 非空时先解密（端到端加密）。
// cipherFor 返回负责第 idx 块的源所使用的解密器。
//
// 块 → 源的映射来自 controller 签名钉死的 grant.Sources[].Start/End，
// 所以它不可被中继改写；空映射（单源或未加密）返回 nil。
func (g *recvGroup) cipherFor(idx int64) *streamCipher {
	if len(g.keys) == 0 {
		return nil
	}
	if len(g.keys) == 1 {
		for _, c := range g.keys {
			return c
		}
	}
	g.mu.Lock()
	ranges := g.ranges
	g.mu.Unlock()
	for _, sp := range ranges {
		if idx >= sp.Start && idx < sp.End {
			return g.keys[sp.NodeID]
		}
	}
	return nil
}

func (g *recvGroup) feed(r io.Reader) error {
	for {
		idx, data, err := ReadFrame(r)
		if err == io.EOF {
			// 干净 EOF 只说明"这条连接结束了"，不等于"这个份额的数据到齐"。
			// 之前直接返回 nil，上层就去等 g.finished：块没齐时白等 10 分钟
			// （发送端同时卡在 10 分钟 ACK 上），把"中继重启/链路切换"这种
			// 本该快速失败的场景变成十分钟静默。
			got, want := g.progress()
			if got < want {
				return fmt.Errorf("连接在份额完成前关闭（已收 %d/%d 块，无完成哨兵）", got, want)
			}
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
		// 分段帧：负载是「从本机旧文件拷贝若干段 + 少量字面量」的指令流，
		// 由发送端用滚动校验在任意偏移上匹配得到。重建后校验分块哈希，
		// 因此不需要走解密路径（负载本身不含明文分块内容）。
		if isSegFrame(idx) {
			realIdx := int64(uint32(idx) &^ (segFlag | refFlag))
			g.mu.Lock()
			expected := g.expected
			size := g.size
			g.mu.Unlock()
			if realIdx < 0 || realIdx >= expected {
				return fmt.Errorf("分段帧块号 %d 超出范围 [0,%d)", realIdx, expected)
			}
			chunkLen := int64(ChunkSize)
			if (realIdx+1)*int64(ChunkSize) > size {
				chunkLen = size - realIdx*int64(ChunkSize)
			}
			path := g.dstPath
			rebuilt, err := decodeSegOps(data, int(chunkLen), func() (io.ReaderAt, func(), error) {
				f, ferr := os.Open(path)
				if ferr != nil {
					return nil, nil, ferr
				}
				return f, func() { f.Close() }, nil
			})
			if err != nil {
				return fmt.Errorf("重建分块 %d 失败: %w", realIdx, err)
			}
			if err := g.storeBlock(realIdx, rebuilt); err != nil {
				return err
			}
			continue
		}
		// 增量引用帧：数据段是 8 字节源偏移，内容取自本机**已有文件**，
		// 不经过网络也不经过加密层。
		if isRefFrame(idx) {
			realIdx := int64(uint32(idx) &^ refFlag)
			srcOff, oerr := refOffset(data)
			if oerr != nil {
				return oerr
			}
			g.mu.Lock()
			expected := g.expected
			g.mu.Unlock()
			if realIdx < 0 || realIdx >= expected {
				return fmt.Errorf("引用帧块号 %d 超出范围 [0,%d)", realIdx, expected)
			}
			if err := g.fillFromLocal(realIdx, srcOff); err != nil {
				return err
			}
			continue
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
		if deckey := g.cipherFor(idx); deckey != nil {
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
