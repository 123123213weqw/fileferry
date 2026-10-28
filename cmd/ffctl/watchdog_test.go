package main

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"fileferry/internal/transfer"
)

// 回归：停滞判定必须区分"还在慢启动"和"真的不动了"。
// QUIC 在高丢包下会静默地慢 60 倍但不报错，只靠出错回退永远触发不了。
func TestShouldSwitch(t *testing.T) {
	const total = 10 << 20 // 10MB
	cases := []struct {
		name    string
		elapsed time.Duration
		sent    int64
		want    bool
	}{
		{"宽限期内不动也不换", 3 * time.Second, 0, false},
		{"宽限期刚过但很快", stallWarmup + time.Second, 8 << 20, false},
		{"宽限期后极慢 → 换", stallWarmup + time.Second, 100 << 10, true},
		{"宽限期后正常速度 → 不换", stallWarmup, 8 << 20, false},
		{"已传过大半 → 不换（换协议更亏）", stallWarmup * 2, total * 6 / 10, false},
		{"边界：恰好 512KB/s", stallWarmup, int64(stallMinBPS) * int64(stallWarmup/time.Second), false},
	}
	for _, c := range cases {
		if got := shouldSwitch(c.elapsed, c.sent, total); got != c.want {
			t.Errorf("%s: shouldSwitch(%v, %d) = %v，期望 %v", c.name, c.elapsed, c.sent, got, c.want)
		}
	}
	// 总大小为 0（空文件/未知）时永不切换
	if shouldSwitch(time.Hour, 0, 0) {
		t.Error("空文件不应触发切换")
	}
	if shouldSwitch(time.Hour, 100, -1) {
		t.Error("总大小为负（未知）不应触发切换")
	}
}

// 回归：ctx 取消必须能真正打断一个正在阻塞的流。
//
// 这是看门狗能生效的前提——SendFile 内部的写不带 ctx，只有关掉底层
// 连接才能让写立即失败。
func TestCancellableOpenerClosesOnCancel(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c2.Close()

	closed := make(chan struct{})
	inner := func() (transfer.Stream, func(), error) {
		return c1, func() { close(closed); c1.Close() }, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	open := cancellableOpener(ctx, inner)
	stream, closeFn, err := open()
	if err != nil {
		t.Fatal(err)
	}
	_ = stream

	// 不取消：不应关闭
	select {
	case <-closed:
		t.Fatal("未取消时不应关闭连接")
	case <-time.After(200 * time.Millisecond):
	}

	cancel()
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("取消 ctx 后应在 2s 内关闭连接（回归：看门狗无法打断流）")
	}
	closeFn() // 幂等：不能 panic

	// 正常关闭路径也必须只关一次
	ctx2 := context.Background()
	closed2 := make(chan struct{}, 4)
	open2 := cancellableOpener(ctx2, func() (transfer.Stream, func(), error) {
		cc1, cc2 := net.Pipe()
		cc2.Close()
		return cc1, func() { closed2 <- struct{}{}; cc1.Close() }, nil
	})
	_, cf2, _ := open2()
	cf2()
	cf2()
	if n := len(closed2); n != 1 {
		t.Fatalf("关闭函数应幂等，实际调用 %d 次", n)
	}
}

// 回归：progressState 的速率计算必须按"本次尝试"重置。
// 若累计跨尝试，换协议后会被之前的高速率掩盖，看门狗永远不触发。
func TestProgressStateResetsPerAttempt(t *testing.T) {
	p := &progressState{}
	p.reset()
	p.add(5 << 20)
	time.Sleep(2 * time.Millisecond) // 让 elapsed 明显大于 0
	s1, e1 := p.snapshot()
	if s1 != 5<<20 {
		t.Fatalf("sent 应为 5MB，实际 %d", s1)
	}
	if e1 <= 0 {
		t.Fatal("elapsed 应大于 0")
	}
	// 换协议：重置
	p.reset()
	s2, _ := p.snapshot()
	if s2 != 0 {
		t.Fatalf("reset 后 sent 应为 0，实际 %d（回归：跨尝试累计会掩盖慢速）", s2)
	}
}

var _ = errors.New

// 回归：必须能区分"慢"和"卡住"。
//
// QUIC 流控窗口 16MB：小于窗口的文件瞬间塞满窗口、进度到 100%，之后
// 全靠等 ACK。此时平均速率看起来不低（早期高速），但 isStalled 能发现
// "已经很久没有进展"。
func TestIsStalled(t *testing.T) {
	const total = 16 << 20
	if isStalled(time.Second, 0, total) {
		t.Error("刚过 1 秒不算卡住")
	}
	if !isStalled(stallWarmup*2, 0, total) {
		t.Error("长时间零进展应判为卡住")
	}
	// 已传完（在等 ACK）不算"卡住"——由 90s/10min 超时兜底
	if isStalled(time.Hour, total, total) {
		t.Error("已发完不应判为卡住")
	}
	// 总大小未知不判断
	if isStalled(time.Hour, 0, 0) {
		t.Error("总大小未知不判断")
	}
}

// sinceAdvance 必须随计数增长而刷新。
func TestProgressSinceAdvance(t *testing.T) {
	p := &progressState{}
	p.reset()
	time.Sleep(120 * time.Millisecond)
	if d := p.sinceAdvance(); d < 100*time.Millisecond {
		t.Fatalf("无进展时 sinceAdvance 应增长，实际 %v", d)
	}
	p.add(1024)
	if d := p.sinceAdvance(); d > 60*time.Millisecond {
		t.Fatalf("有进展后 sinceAdvance 应重置，实际 %v", d)
	}
	// add(0) 不应刷新时间
	before := p.sinceAdvance()
	time.Sleep(60 * time.Millisecond)
	p.add(0)
	after := p.sinceAdvance()
	if after <= before {
		t.Fatalf("add(0) 不应刷新进展时间：before=%v after=%v", before, after)
	}
}
