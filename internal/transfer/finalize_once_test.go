package transfer

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// 回归：markComplete 只能有一个胜出者。
//
// finalize 第一行是 close(g.finished)，第二次调用直接 panic: close of
// closed channel；agent 没有 recover，等于整机传输能力被一条迟到流打死。
func TestMarkCompleteHasSingleWinner(t *testing.T) {
	g := &recvGroup{
		expected: 1,
		got:      map[int64]bool{0: true},
		finished: make(chan struct{}),
	}
	var wins int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if g.markComplete() {
				atomic.AddInt32(&wins, 1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if wins != 1 {
		t.Fatalf("%d 个调用者判定为胜出，期望恰好 1 个", wins)
	}
	if !g.done {
		t.Fatal("done 未被置位")
	}
}

// 回归：ref（增量引用）帧补齐最后一块时，finalize 只能执行一次。
//
// 旧实现里 fillFromLocal 在**锁外**读 len(g.got) 判定"收齐了"，然后在锁外
// 无条件调 finalize。日常触发形状：4 条流并行，最后一块由某条流的 ref 帧
// 补齐，同时另一条流超时重试、重发了同一条 ref 帧。后果二选一：
//   - 锁外读 map 与并发写入竞争 → fatal error: concurrent map read and map
//     write（不可 recover）；
//   - 两个 goroutine 都通过判定 → 第二次 close(g.finished) → panic。
//
// 这里用 8 条并发"重试流"重复补齐同一个块来复现该形状，并校验：
// 不 panic、收尾只发生一次、落盘内容正确。
func TestFillFromLocalFinalizesOnce(t *testing.T) {
	dir := t.TempDir()
	finalPath := filepath.Join(dir, "dst.bin")

	content := make([]byte, 1024) // 一个块的整文件（块长取 size，不必是 4MiB）
	for i := range content {
		content[i] = byte(i*31 + 7)
	}
	if err := os.WriteFile(finalPath, content, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)

	tmp, err := os.CreateTemp(dir, ".ff-*")
	if err != nil {
		t.Fatal(err)
	}
	defer tmp.Close()

	g := &recvGroup{
		grantID:   "regress-finalize-once",
		wantSHA:   hex.EncodeToString(sum[:]),
		size:      int64(len(content)),
		finalPath: finalPath,
		dstPath:   finalPath,
		tmp:       tmp,
		tmpName:   tmp.Name(),
		expected:  1,
		got:       map[int64]bool{},
		finished:  make(chan struct{}),
	}

	// 1024 条并发"重试流"：窗口从纳秒级放大到能被稳定命中——旧实现在这个
	// 规模下每次都会 panic: close of closed channel（已实测）。
	const workers = 1024
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			// 收尾之后迟到的写会返回 "file already closed"，属预期，
			// 这里只关心"不 panic、不重复收尾"。
			_ = g.fillFromLocal(0, 0)
		}()
	}
	close(start)
	wg.Wait()

	select {
	case <-g.finished:
	case <-time.After(5 * time.Second):
		t.Fatal("5 秒内没有完成收尾")
	}

	got, err := os.ReadFile(finalPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, content) {
		t.Fatal("落盘内容与源不符")
	}

	g.mu.Lock()
	done := g.done
	n := len(g.got)
	g.mu.Unlock()
	if !done || n != 1 {
		t.Fatalf("状态异常：done=%v got=%d（期望 true/1）", done, n)
	}
	if g.finErr != nil {
		t.Fatalf("收尾报错：%v", g.finErr)
	}
}
