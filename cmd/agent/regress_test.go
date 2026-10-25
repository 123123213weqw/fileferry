package main

import (
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
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
