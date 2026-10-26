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
	"time"
)

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
		// 增量：把目标位置**已有文件**的分块哈希一并带过去，发送端
		// 据此跳过相同块。旧版发送端会因整行 base64 解码失败而退化为
		// 全量发送，行为仍然正确。
		g.reuseOnce.Do(func() {
			reuse := buildReuseTable(g.dstPath, grant.ChunkSize)
			g.reuseEnc = reuse.encode()
			if g.reuseEnc != "" {
				// 这行对用户有意义（决定了要传多少），始终输出
				log.Printf("%s 增量协商：目标已有 %d 块可复用（%d 字节）",
					grant.ID, len(reuse.Blocks), reuse.Size)
			}
		})
		if g.reuseEnc != "" {
			fmt.Fprintf(stream, "HAVE %s %s\n", base64.StdEncoding.EncodeToString(g.haveBits()), g.reuseEnc)
		} else {
			fmt.Fprintf(stream, "HAVE %s\n", base64.StdEncoding.EncodeToString(g.haveBits()))
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
		dstPath:   grant.DstPath,
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
	if len(g.got) == int(g.expected) && !g.done {
		g.mu.Lock()
		if !g.done {
			g.done = true
		}
		g.mu.Unlock()
		g.finalize()
	}
	return nil
}

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
