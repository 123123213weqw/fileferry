package main

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"fileferry/internal/transfer"
)

// 停滞检测参数。
//
// 背景：QUIC 在高丢包链路下吞吐会塌陷 60~150 倍（实测 2% 丢包时 10MB
// 从 0.49s 变 25~30s），但它**不报错**——于是"只在出错时回退"的逻辑
// 永远不会触发，用户只能等完，或手动加 -proto tcp 再跑一遍。
//
// 这里加看门狗：握手能通但实际跑得很慢时，主动切断并换下一种协议。
// 断点续传的进度是持久化的（.ffpart + HAVE 位图），换协议后接着传，
// 不从头开始。
const (
	// stallWarmup 给带宽爬升留时间。TCP/QUIC 都有慢启动，太早判断会
	// 误杀正常链路。
	stallWarmup = 6 * time.Second
	// stallMinBPS：宽限期过后平均速率仍低于此值就换协议。取 512KB/s：
	// 正常 loopback/局域网是几十到几百 MB/s；被墙链路即使慢通常也在
	// MB/s 量级。低于 512KB/s 基本等于没在动。
	stallMinBPS = 512 << 10
	// stallMinBytes：小于此大小的传输不做停滞检测。小文件本来就该秒级
	// 完成，切换协议的开销（重握手 + 重校验）反而更亏。
	stallMinBytes = 8 << 20
)

// shouldSwitch 判断是否应放弃当前协议。纯函数，便于测试。
//
// 一个重要的能力边界（实测确认，别指望它更多）：
//
//	QUIC 的流控窗口是 16MB。发送端的 Write 只要数据进了 quic-go 的缓冲
//	就返回，**不反映链路速度**。所以：
//	  - 文件 ≤ 窗口：数据瞬间塞满窗口，进度直接到 100%，之后只是等 ACK。
//	    此时 sent>=total，本函数按设计返回 false——它检测不到"活着但很慢"。
//	  - 文件 > 窗口：窗口填满后 Write 开始阻塞，进度才会跟随链路，
//	    这时低速率能被检出。
//
//	实测：16MB 文件经 300KB/s 限速链路跑了 53.9s，看门狗没有触发；
//	而连接完全不通（进度恒为 0）时 6 秒就触发了。
//
// 也就是说它主要防"假活"（连接建立但推不动），不是万能的慢速检测。
func shouldSwitch(elapsed time.Duration, sent, total int64) bool {
	if total <= 0 || elapsed < stallWarmup {
		return false
	}
	// 已传完大半就不换：换协议要重握手 + 重新校验增量，反而更慢
	if sent*2 >= total {
		return false
	}
	return float64(sent)/elapsed.Seconds() < float64(stallMinBPS)
}

// isStalled 判断"完全没有进展"：距上次进展超过 stallWarmup 且尚未传完。
//
// 与 shouldSwitch 互补：shouldSwitch 看平均速率，这里看"是否还在动"。
// 流控窗口填满后 Write 会阻塞，此时 sent 不再增长，isStalled 能捕获；
// 而平均速率可能因早期的高速而仍然很高。
func isStalled(sinceProgress time.Duration, sent, total int64) bool {
	if total <= 0 || sent >= total {
		return false
	}
	return sinceProgress >= stallWarmup
}

// cancellableOpener 包装 StreamOpener：ctx 取消时主动关掉底层连接。
//
// 为什么必需：SendFile 内部的写不带 ctx，单靠取消 ctx 打断不了已经
// 建立、正在缓慢写入的流；只有关掉连接才能让写立即失败。
func cancellableOpener(ctx context.Context, inner transfer.StreamOpener) transfer.StreamOpener {
	return func() (transfer.Stream, func(), error) {
		stream, closeFn, err := inner()
		if err != nil {
			return nil, nil, err
		}
		// ctx 已取消就不必起协程（否则可能永远等不到 Done 之后的信号）
		if ctx.Err() != nil {
			closeFn()
			return nil, nil, ctx.Err()
		}
		// 两个 Once 分别守住"关连接"和"关通知通道"：closer 可能被调用
		// 多次（正常关闭 + defer），直接 close(stop) 第二次会 panic。
		// 这个 bug 是测试里 cf2() 连调两次抓到的。
		var closeOnce, stopOnce sync.Once
		stop := make(chan struct{})
		stopped := make(chan struct{})
		go func() {
			defer close(stopped)
			select {
			case <-ctx.Done():
				closeOnce.Do(closeFn)
			case <-stop:
			}
		}()
		closer := func() {
			closeOnce.Do(closeFn)
			stopOnce.Do(func() { close(stop) })
			<-stopped // 等协程真的退出
		}
		return stream, closer, nil
	}
}

// progressState 汇总一次传输的实时进度：既供显示，也供看门狗判定。
// 每次发送尝试开始时调用 reset，使速率按"本次尝试"计算。
type progressState struct {
	sent  atomic.Int64
	start atomic.Int64 // UnixNano
	// lastAdvance 是最近一次"计数增长"的时间（UnixNano），用于判断停滞。
	lastAdvance atomic.Int64
}

func (p *progressState) reset() {
	now := time.Now().UnixNano()
	p.sent.Store(0)
	p.start.Store(now)
	p.lastAdvance.Store(now)
}

func (p *progressState) add(n int64) {
	if n <= 0 {
		return
	}
	p.sent.Add(n)
	p.lastAdvance.Store(time.Now().UnixNano())
}

// sinceAdvance 返回距上次计数增长的时间。
func (p *progressState) sinceAdvance() time.Duration {
	t := p.lastAdvance.Load()
	if t == 0 {
		return 0
	}
	return time.Since(time.Unix(0, t))
}

// snapshot 返回本次尝试已发字节与已用时间。
func (p *progressState) snapshot() (sent int64, elapsed time.Duration) {
	sent = p.sent.Load()
	startN := p.start.Load()
	if startN == 0 {
		return 0, 0
	}
	return sent, time.Since(time.Unix(0, startN))
}
