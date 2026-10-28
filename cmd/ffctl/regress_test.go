package main

import "testing"

// 回归：协议选择必须可显式指定。QUIC 在高丢包链路上会被基于丢包的
// 拥塞控制压塌（实测 2% 丢包时 10MB 从 0.5s 变 25.75s），此时必须能
// 强制走 TCP。
func TestPickProtos(t *testing.T) {
	if got := pickProtos("auto", "tcp"); len(got) != 2 || got[0] != "tcp" || got[1] != "quic" {
		t.Fatalf("auto 应以提示值优先：%v", got)
	}
	if got := pickProtos("", "quic"); len(got) != 2 || got[0] != "quic" || got[1] != "tcp" {
		t.Fatalf("空选择等价 auto：%v", got)
	}
	if got := pickProtos("tcp", "quic"); len(got) != 1 || got[0] != "tcp" {
		t.Fatalf("显式 tcp 应只试 tcp：%v", got)
	}
	if got := pickProtos("quic", "tcp"); len(got) != 1 || got[0] != "quic" {
		t.Fatalf("显式 quic 应只试 quic：%v", got)
	}
	// 未知值按 auto 处理，不能返回空（否则一个协议都不试）
	if got := pickProtos("bogus", "quic"); len(got) < 1 {
		t.Fatalf("未知值不应返回空：%v", got)
	}
}

// 回归：dedupProtos 必须去重且丢掉空串。
func TestDedupProtos(t *testing.T) {
	got := dedupProtos("", "quic", "quic", "tcp")
	if len(got) != 2 || got[0] != "quic" || got[1] != "tcp" {
		t.Fatalf("去重结果不对：%v", got)
	}
}
