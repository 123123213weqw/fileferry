package transfer

import (
	"bytes"
	"os"
	"sync"
	"testing"
	"time"
)

// slowStream 模拟"稳定但慢"的链路：每次 Write 阻塞 perWrite，并像真连接那样
// 在当前写超时已过时返回超时错误（而不是默默成功）。
type slowStream struct {
	mu       sync.Mutex
	deadline time.Time
	armed    []time.Time
	writes   int
	perWrite time.Duration
}

func (s *slowStream) SetWriteDeadline(t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deadline = t
	s.armed = append(s.armed, t)
	return nil
}

func (s *slowStream) Write(p []byte) (int, error) {
	s.mu.Lock()
	dl := s.deadline
	s.writes++
	s.mu.Unlock()
	if !dl.IsZero() && time.Now().After(dl) {
		return 0, os.ErrDeadlineExceeded
	}
	time.Sleep(s.perWrite)
	return len(p), nil
}

func (s *slowStream) snapshot() (armed, writes int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.armed), s.writes
}

// 回归：写超时必须是"停滞"语义，而不是"整条份额的寿命"。
//
// 旧实现只在发送循环**外**设一次 SetWriteDeadline(now+90s)，循环内从不续期。
// 于是份额的总耗时被夹死在 90 秒：1GB@2MB/s（500 秒）从第 90 秒起每次 Write
// 都 i/o timeout；sendShare 只有 3 次尝试、每次也只能靠 HAVE 位图前进约
// 90 秒，单份额上限约 270 秒 —— 大文件在慢链路上必然失败，而且不是"卡住才
// 失败"，是稳定慢也失败。
//
// 现在 countingWriter 每写一片就续期，所以"总耗时远超阈值、但每一片都很短"
// 必须成功；同时断言续期次数不少于写入次数（旧实现恒为 1）。
func TestWriteDeadlineIsPerStallNotTotal(t *testing.T) {
	old := writeStallTimeout
	writeStallTimeout = 60 * time.Millisecond
	defer func() { writeStallTimeout = old }()

	s := &slowStream{perWrite: 40 * time.Millisecond}
	cw := &countingWriter{w: s}

	// 6 片 × 40ms = 240ms，是阈值（60ms）的 4 倍；但每一片都只有 40ms。
	payload := bytes.Repeat([]byte("x"), progressWriteSlice)
	start := time.Now()
	for i := 0; i < 6; i++ {
		if _, err := cw.Write(payload); err != nil {
			t.Fatalf("第 %d 片写失败（写超时没有续期？）：%v", i, err)
		}
	}
	elapsed := time.Since(start)
	if elapsed < writeStallTimeout {
		t.Fatalf("测试本身无效：总耗时 %v 未超过停滞阈值 %v", elapsed, writeStallTimeout)
	}

	armed, writes := s.snapshot()
	if writes != 6 {
		t.Fatalf("写入次数 = %d，期望 6", writes)
	}
	if armed < writes {
		t.Fatalf("写超时只设置了 %d 次却写了 %d 次：仍是绝对死线，不是停滞检测",
			armed, writes)
	}
}

// armWriteDeadline 对不支持 deadline 的 writer 必须是无害的 no-op
// （单测里大量用 bytes.Buffer 当流）。
func TestArmWriteDeadlineOnPlainWriter(t *testing.T) {
	var buf bytes.Buffer
	armWriteDeadline(&buf)
	if _, err := buf.WriteString("ok"); err != nil {
		t.Fatal(err)
	}
	if buf.String() != "ok" {
		t.Fatalf("缓冲被写坏：%q", buf.String())
	}
	armWriteDeadline(nil) // 不能 panic
}
