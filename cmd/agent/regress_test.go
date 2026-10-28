package main

import (
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"fileferry/internal/api"
	"fileferry/internal/transfer"
)

// 回归：WHOAMI 回声必须能被截流。sniffConn 内嵌 *net.UDPConn 后，
// ReadMsgUDP 被提升 → 满足 quic-go 的 OOBCapablePacketConn → quic-go
// 直接走 ReadMsgUDP，绕过 ReadFrom，回声被当成 QUIC 垃圾丢弃，
// myPublic 永远为空。这里验证两个入口都做嗅探。
func TestRegressSniffBothReadPaths(t *testing.T) {
	raw, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	sn := &sniffConn{UDPConn: raw, whoamiCh: make(chan []byte, 4)}

	if _, ok := interface{}(sn).(quic.OOBCapablePacketConn); !ok {
		t.Skip("当前 quic-go 版本不再使用 OOBCapablePacketConn")
	}

	send := func() {
		cli, err := net.DialUDP("udp", nil, raw.LocalAddr().(*net.UDPAddr))
		if err != nil {
			t.Fatal(err)
		}
		defer cli.Close()
		cli.Write([]byte("FFWHO1\n127.0.0.1:9999\n"))
	}

	// 1) ReadFrom 路径
	send()
	go func() {
		buf := make([]byte, 2048)
		sn.ReadFrom(buf)
	}()
	select {
	case <-sn.whoamiCh:
	case <-time.After(2 * time.Second):
		t.Fatal("ReadFrom 路径未能截流 WHOAMI（回归）")
	}

	// 2) ReadMsgUDP 路径（quic-go 实际走的路径）
	send()
	go func() {
		buf := make([]byte, 2048)
		oob := make([]byte, 64)
		sn.ReadMsgUDP(buf, oob)
	}()
	select {
	case <-sn.whoamiCh:
	case <-time.After(2 * time.Second):
		t.Fatal("ReadMsgUDP 路径未能截流 WHOAMI（回归）")
	}
}

// 回归：撤销名单里的节点必须被数据面拒绝。
func TestRegressRevokedNodeRejected(t *testing.T) {
	revokedMu.Lock()
	revokedIDs = map[string]bool{"bad-node": true}
	revokedMu.Unlock()
	defer func() {
		revokedMu.Lock()
		revokedIDs = map[string]bool{}
		revokedMu.Unlock()
	}()

	if !isRevoked("bad-node") {
		t.Fatal("撤销名单未生效")
	}
	if isRevoked("good-node") {
		t.Fatal("误判正常节点为撤销")
	}
}

// 回归：探测必须指数退避。之前每 30s 无差别重试所有 peer，对端宕机时
// 一台死节点会让全网每 30s 各发 2 次失败连接——在对端/IDS 看来就是
// 分布式端口扫描，实测 8s 内打 13 个端口。
func TestRegressProbeBackoff(t *testing.T) {
	// 退避序列单调递增并封顶
	var prev time.Duration
	for fails := 1; fails <= 12; fails++ {
		d := probeBackoff(fails)
		if fails > 1 && d < prev {
			t.Fatalf("退避时长必须单调不减：fails=%d 得 %s，上一档 %s", fails, d, prev)
		}
		if d > 5*time.Minute {
			t.Fatalf("退避超过 5 分钟上限：%s", d)
		}
		prev = d
	}
	if probeBackoff(0) != 0 {
		t.Fatal("没失败过应立即可探")
	}
	if probeBackoff(20) != 5*time.Minute {
		t.Fatalf("多次失败应封顶 5 分钟，实际 %s", probeBackoff(20))
	}

	// 状态机：失败→退避，成功→清零，日志只在状态变化时打
	probeFailMu.Lock()
	probeFail = map[api.NodeID]*peerBackoff{}
	probeFailMu.Unlock()
	id := api.NodeID("peer-x")

	if !allowProbe(id) {
		t.Fatal("首次应允许探测")
	}
	if !markProbe(id, false) {
		t.Fatal("第一次失败应报告状态变化（要打日志）")
	}
	if allowProbe(id) {
		t.Fatal("失败后应进入退避期，本轮不该再打")
	}
	if markProbe(id, false) {
		t.Fatal("连续第二次失败不应再打日志（否则一天 2880 行）")
	}
	if probeFail[id].fails != 2 {
		t.Fatalf("失败计数应为 2，实际 %d", probeFail[id].fails)
	}
	if !markProbe(id, true) {
		t.Fatal("恢复应报告状态变化")
	}
	if !allowProbe(id) {
		t.Fatal("恢复后应立即可探")
	}
	if markProbe(id, true) {
		t.Fatal("持续成功不应重复打日志")
	}
}

// 回归：已知公网映射时打洞只能打 1 个端口，不能扩散成扫描。
func TestRegressSendOpenersExact(t *testing.T) {
	count := func(exact bool) (pkts int, ports map[int]bool) {
		inner, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer inner.Close()
		cc := &countConn{PacketConn: inner, ports: map[int]bool{}}
		transfer.SendOpeners(cc, "127.0.0.1:17800", 300*time.Millisecond, exact)
		return cc.n, cc.ports
	}

	nExact, pExact := count(true)
	if len(pExact) != 1 {
		t.Fatalf("已知映射时应只打 1 个端口，实际 %d 个：%v（回归）", len(pExact), pExact)
	}
	if _, ok := pExact[17800]; !ok {
		t.Fatalf("应打目标端口 17800，实际 %v", pExact)
	}

	nSpread, pSpread := count(false)
	if len(pSpread) > 4 {
		t.Fatalf("未知映射时扩散也不该超过 4 个端口，实际 %d 个：%v", len(pSpread), pSpread)
	}
	if len(pSpread) <= 1 {
		t.Fatalf("未知映射时应做少量扩散，实际只有 %d 个", len(pSpread))
	}
	t.Logf("精确模式 %d 包/%d 端口；扩散模式 %d 包/%d 端口", nExact, len(pExact), nSpread, len(pSpread))
}

type countConn struct {
	net.PacketConn
	n     int
	ports map[int]bool
}

func (c *countConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	c.n++
	if ua, ok := addr.(*net.UDPAddr); ok {
		c.ports[ua.Port] = true
	}
	return c.PacketConn.WriteTo(b, addr)
}
