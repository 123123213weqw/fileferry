package transfer

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fileferry/internal/api"
	"fmt"
	"io"
	"sync"
	"time"
)

func OpenerDirect(ctx context.Context, firstHop api.Hop, tlsConf *tls.Config) StreamOpener {
	return func() (Stream, func(), error) {
		s, closeFn, err := DialStream(ctx, firstHop.Addr, firstHop.Proto, firstHop.TCPPort, tlsConf)
		if err == nil || firstHop.Proto != "quic" {
			return s, closeFn, err
		}
		return DialStream(ctx, firstHop.Addr, "tcp", firstHop.TCPPort, tlsConf)
	}
}

// OpenerSwitch 返回交换台模式的建流函数：出站拨交换台并完成
// FFSW 配对握手，返回的流在协议上与直连流完全同构。
func OpenerSwitch(ctx context.Context, sw api.Hop, tlsConf *tls.Config, grant *api.TransferGrant) StreamOpener {
	return func() (Stream, func(), error) {
		return DialSwitch(ctx, sw.Addr, sw.Proto, sw.TCPPort, tlsConf, grant)
	}
}

// DialSwitch 出站拨向交换台，发送 FFSW + grant 完成配对，等 OK。
func DialSwitch(ctx context.Context, addr, proto string, tcpPort int, tlsConf *tls.Config, grant *api.TransferGrant) (Stream, func(), error) {
	stream, closeConn, err := DialStream(ctx, addr, proto, tcpPort, tlsConf)
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
	line, err := readHeaderLine(br)
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
	var pairs [][2]*swWaiter
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
		pairs = append(pairs, [2]*swWaiter{a, b})
	}
	swBoard.mu.Unlock()

	// 写 OK 与起管道都放在锁外：之前 a.stream.Write 在 swBoard.mu 里，
	// 一个慢对端（TCP 零窗口、QUIC 流控打满）就阻塞整个交换台的所有
	// 新配对，进而拖垮所有走交换台的传输。
	for _, pr := range pairs {
		a, b := pr[0], pr[1]
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

	select {
	case <-w.paired:
		<-w.done // 等管道结束，避免外层 defer 提前关流
	case <-time.After(75 * time.Second):
		swBoard.remove(grant.ID, w)
		fmt.Printf("交换台配对超时：%s（%s）\n", grant.ID, cn)
	}
}

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
	ns, closeNext, err := DialStream(ctx, next.Addr, next.Proto, next.TCPPort, tlsConf)
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
