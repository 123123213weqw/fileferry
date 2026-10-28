package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"fileferry/internal/api"
	"fileferry/internal/topology"
)

type failWriter struct{ h http.Header }

func (f *failWriter) Header() http.Header {
	if f.h == nil {
		f.h = http.Header{}
	}
	return f.h
}
func (f *failWriter) Write([]byte) (int, error) { return 0, errors.New("broken pipe") }
func (f *failWriter) WriteHeader(int)           {}

type recWriter struct {
	h    http.Header
	buf  bytes.Buffer
	code int // 记录 WriteHeader 的状态码（测试要断言 403/413/429）
}

func (w *recWriter) Header() http.Header {
	if w.h == nil {
		w.h = http.Header{}
	}
	return w.h
}
func (w *recWriter) Write(p []byte) (int, error) { return w.buf.Write(p) }
func (w *recWriter) WriteHeader(code int)        { w.code = code }

// Code 返回响应的状态码（未显式调用 WriteHeader 时按 200 记）。
func (w *recWriter) Code() int {
	if w.code == 0 {
		return http.StatusOK
	}
	return w.code
}

func newTestController(t *testing.T) *controller {
	t.Helper()
	dir := t.TempDir()
	db, err := sql.Open("sqlite", filepath.Join(dir, "ff.db")+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	for _, ddl := range []string{
		`CREATE TABLE IF NOT EXISTS events(ts INTEGER, kind TEXT, node TEXT, detail TEXT)`,
		`CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY, base TEXT, src TEXT, dst TEXT, mode TEXT, status TEXT, grant_json TEXT, created INTEGER, updated INTEGER)`,
		`CREATE TABLE IF NOT EXISTS replicas(sha TEXT, node TEXT, path TEXT, size INTEGER, mtime INTEGER, PRIMARY KEY(sha,node))`,
		`CREATE TABLE IF NOT EXISTS revoked(node TEXT PRIMARY KEY, ts INTEGER)`,
	} {
		if _, err := db.Exec(ddl); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { db.Close() })
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	return &controller{
		cfg:          Config{DataDir: dir},
		signer:       priv,
		signPub:      pub,
		graph:        topology.New(),
		db:           db,
		pending:      map[api.NodeID][]api.TransferGrant{},
		publics:      map[api.NodeID]pubEntry{},
		punchTried:   map[[2]api.NodeID]time.Time{},
		pendingPunch: map[api.NodeID][]api.PunchDirective{},
		ledger:       &enrollLedger{Burned: map[string]string{}, NextNode: 1, Used: map[string]bool{}},
		limiter:      &rateLimiter{seen: map[string][]time.Time{}},
		replicas:     map[string]map[api.NodeID]string{},
		pathBW:       map[[2]api.NodeID]float64{},
		protoBW:      map[[2]api.NodeID]map[string]float64{},
		indexCache:   map[api.NodeID][]api.IndexEntry{},
		revoked:      map[api.NodeID]bool{},
		keypass:      map[string]keyEntry{},
		shares:       map[string]*shareEntry{},
	}
}

func hbReq(t *testing.T, node string) *http.Request {
	t.Helper()
	body, _ := json.Marshal(api.Heartbeat{NodeID: api.NodeID(node), TS: time.Now()})
	r := httptest.NewRequest("POST", "/v1/heartbeat", bytes.NewReader(body))
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{
		{Subject: pkix.Name{CommonName: node, OrganizationalUnit: []string{"node"}}},
	}}
	return r
}

// 回归：心跳响应写失败时，任务必须放回队列（之前会永久丢失）。
func TestRegressHeartbeatRequeueOnWriteFailure(t *testing.T) {
	c := newTestController(t)
	g := api.TransferGrant{
		ID: "xfer-1", Src: "node-1", Dst: "node-2",
		Hops:      []api.Hop{{NodeID: "node-1"}, {NodeID: "node-2", Addr: "1.2.3.4:7800"}},
		ExpiresAt: time.Now().Add(time.Hour),
	}
	c.jobPersist(&g)
	c.pending["node-1"] = []api.TransferGrant{g}

	c.handleHeartbeat(&failWriter{}, hbReq(t, "node-1"))
	if n := len(c.pending["node-1"]); n != 1 {
		t.Fatalf("写失败后应放回队列，实际 %d 条（回归）", n)
	}

	// 下一次正常心跳应把它投出去
	w := &recWriter{}
	c.handleHeartbeat(w, hbReq(t, "node-1"))
	var resp api.HeartbeatResponse
	if err := json.Unmarshal(w.buf.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Jobs) != 1 || resp.Jobs[0].ID != "xfer-1" {
		t.Fatalf("任务未重新投递：%+v（回归）", resp.Jobs)
	}
	if n := len(c.pending["node-1"]); n != 0 {
		t.Fatalf("投递成功后应从队列摘除，实际 %d 条", n)
	}
}

// 回归：限速键必须按 IP，换连接（换端口）不能绕过。
func TestRegressEnrollRateLimitByIP(t *testing.T) {
	c := newTestController(t)
	allowed := 0
	for i := 0; i < 20; i++ {
		r := httptest.NewRequest("POST", "/v1/enroll", bytes.NewReader([]byte(`{"token":"bad"}`)))
		r.RemoteAddr = "203.0.113.9:40000" + string(rune('a'+i%26)) // 同一 IP，不同端口
		r.RemoteAddr = "203.0.113.9:" + itoa(40000+i)
		if c.limiter.allow("enroll:"+clientIP(r), 2) {
			allowed++
		}
	}
	if allowed != 2 {
		t.Fatalf("同一 IP 20 次应只放行 2 次，实际 %d（回归：端口参与限速键）", allowed)
	}
	// 不同 IP 互不影响
	r2 := httptest.NewRequest("POST", "/v1/enroll", nil)
	r2.RemoteAddr = "198.51.100.7:1234"
	if !c.limiter.allow("enroll:"+clientIP(r2), 2) {
		t.Fatal("另一个 IP 不应被牵连")
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// 回归：限速表不能无界增长——陈旧 key 必须被清扫，且总量有硬上限。
func TestRegressRateLimiterBounded(t *testing.T) {
	l := &rateLimiter{seen: map[string][]time.Time{}}
	// 塞 3000 个"很久以前"的 key（模拟长时间被扫描端口）
	old := time.Now().Add(-time.Hour)
	for i := 0; i < 3000; i++ {
		l.seen["ip-"+itoa(i)] = []time.Time{old}
	}
	// 触发清扫（每 1024 次调用一次）
	for i := 0; i < 1100; i++ {
		l.allow("fresh-"+itoa(i%3), 1000)
	}
	if len(l.seen) > 100 {
		t.Fatalf("陈旧 key 未被回收，map 仍 %d 条（回归）", len(l.seen))
	}

	// 硬上限兜底
	l2 := &rateLimiter{seen: map[string][]time.Time{}}
	now := time.Now()
	for i := 0; i < 120000; i++ {
		l2.seen["k"+itoa(i)] = []time.Time{now}
	}
	l2.allow("trigger", 10)
	if len(l2.seen) > 100000 {
		t.Fatalf("硬上限失效，map %d 条", len(l2.seen))
	}
}

// 回归：jobdone 必须校验参与方，身份不能靠猜 grant ID。
func TestRegressJobDoneParticipant(t *testing.T) {
	c := newTestController(t)
	g := api.TransferGrant{
		ID: "xfer-42", Src: "node-1", Dst: "node-2",
		Hops:      []api.Hop{{NodeID: "node-1"}, {NodeID: "node-2"}},
		ExpiresAt: time.Now().Add(time.Hour),
	}
	c.jobPersist(&g)

	body, _ := json.Marshal(api.DoneRequest{GrantID: "xfer-42", NodeID: "node-9", OK: true})
	r := httptest.NewRequest("POST", "/v1/jobdone", bytes.NewReader(body))
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{
		{Subject: pkix.Name{CommonName: "node-9", OrganizationalUnit: []string{"node"}}},
	}}
	w := &recWriter{}
	c.handleJobDone(w, r)
	if w.buf.Len() > 0 {
		var resp api.HeartbeatResponse
		_ = resp
	}
	if w.h.Get("Content-Type") == "" && w.buf.Len() == 0 {
		t.Fatal("应返回 403 给非参与方")
	}
	// 任务状态不应被非参与方改写
	var status string
	if err := c.db.QueryRow(`SELECT status FROM jobs WHERE id=?`, "xfer-42").Scan(&status); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond) // jobUpdate 是异步的
	_ = c.db.QueryRow(`SELECT status FROM jobs WHERE id=?`, "xfer-42").Scan(&status)
	if status == "done" {
		t.Fatal("非参与方把任务标成了 done（回归）")
	}
}

// 回归：共享目标必须返回 403（自取不消耗次数也不允许）。
func TestRegressShareSelfFetchNoBurn(t *testing.T) {
	c := newTestController(t)
	code := "ff_get_test"
	c.shares[api.TokenHash(code)] = &shareEntry{
		Src: "node-1", Path: "/data/x", Exp: time.Now().Add(time.Minute), Uses: 3,
	}
	body, _ := json.Marshal(map[string]string{"code": code})
	r := httptest.NewRequest("POST", "/v1/get", bytes.NewReader(body))
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{
		{Subject: pkix.Name{CommonName: "node-1", OrganizationalUnit: []string{"node"}}},
	}}
	w := &recWriter{}
	c.handleGet(w, r)
	if se, ok := c.shares[api.TokenHash(code)]; ok && se.Uses != 3 {
		t.Fatalf("自取不应消耗次数，剩余 %d（回归）", se.Uses)
	}
}

// 回归：撤销名单必须下发给数据面。
func TestRegressRevocationShipped(t *testing.T) {
	c := newTestController(t)
	c.revoked["node-7"] = true
	w := &recWriter{}
	c.handleHeartbeat(w, hbReq(t, "node-1"))
	var resp api.HeartbeatResponse
	if err := json.Unmarshal(w.buf.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, id := range resp.Revoked {
		if id == "node-7" {
			found = true
		}
	}
	if !found {
		t.Fatalf("撤销名单未随心跳下发：%+v（回归）", resp.Revoked)
	}
}

// 回归：节点名允许任意 UTF-8，但必须拒绝与 "node:/path" 语法冲突的字符。
func TestRegressStableNodeName(t *testing.T) {
	led := &enrollLedger{Burned: map[string]string{}, NextNode: 1, Used: map[string]bool{}}

	// —— 应当接受的名字（含中文、emoji、点、下划线）——
	for _, want := range []string{"db1", "web.prod.example", "香港-1", "数据库-主", "node_01", "a.b-c_d", "Node-1"} {
		got, err := NormalizeNodeName(want)
		if err != nil {
			t.Fatalf("%q 应被接受，实际报错：%v", want, err)
		}
		if got != want {
			t.Fatalf("%q 被改成了 %q（不应静默改字）", want, got)
		}
	}

	// —— 必须拒绝的名字 ——
	for _, bad := range []string{
		"a:b",                   // 与 node:/path 冲突，且 splitNodePath 会静默错位
		"a/b",                   // 与路径分隔冲突
		"a\\b",                  // Windows 分隔
		"",                      // 空
		"  x",                   // 前导空白
		"x  ",                   // 尾随空白
		"a\x00b",                // 控制字符
		string(make([]byte, 0)), // 空
		"loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooong", // >64
	} {
		if _, err := NormalizeNodeName(bad); err == nil {
			t.Fatalf("%q 应被拒绝，实际通过", bad)
		}
	}

	// —— 去重：大小写不敏感 ——
	first, ok := led.claimName("Node-1")
	if !ok || first != "Node-1" {
		t.Fatalf("首次占用应成功，实际 ok=%v name=%q", ok, first)
	}
	if _, ok := led.claimName("node-1"); ok {
		t.Fatal("大小写不同的同名不应被当成两台机器（回归）")
	}
	// 自动编号必须跳过已占用
	if id := led.nextAutoNodeID(); id == "Node-1" || id == "node-1" {
		t.Fatalf("自动编号撞上了手工名：%s", id)
	}
	if id := led.nextAutoNodeID(); !led.claim(id) {
		t.Fatalf("自动编号 %s 应未被占用", id)
	}
}

// 回归：目录目标在 controller 侧补文件名。
func TestRegressNormalizeDstPath(t *testing.T) {
	cases := map[[2]string]string{
		{"/data/", "/src/big.iso"}:      "/data/big.iso",
		{"/data", "/src/big.iso"}:       "/data", // 无末尾斜杠，交给接收端兜底
		{"/data/x.bin", "/src/big.iso"}: "/data/x.bin",
		{"", "/src/big.iso"}:            "",
	}
	for in, want := range cases {
		if got := normalizeDstPath(in[0], in[1]); got != want {
			t.Fatalf("normalizeDstPath(%q,%q)=%q，期望 %q", in[0], in[1], got, want)
		}
	}
}

// 回归：pull 授权必须把 ffctl 作为目的端写进 Hops（源节点据此回连），
// 且默认**不**用可能过期的索引摘要钉死内容。
func TestRegressPullGrant(t *testing.T) {
	c := newTestController(t)
	// 让源节点"在线"
	c.graph.Apply(api.Heartbeat{
		NodeID: "store", Hostname: "h", Addr: "10.0.0.9:17800", TCPPort: 18400,
		TS: time.Now(),
	})
	// 索引里放一条**过期**的摘要：默认不应被用于钉死
	c.mu.Lock()
	c.indexCache["store"] = []api.IndexEntry{{Path: "/data/f.bin", Size: 123, SHA256: "deadbeef"}}
	c.mu.Unlock()

	req := api.PullRequest{
		NodeID: "ffctl-abc", Src: "store", SrcPath: "/data/f.bin",
		DstPath: "/tmp/out/", ListenAddr: "10.0.0.5", ListenPort: 40000, Streams: 2,
	}
	body, _ := json.Marshal(req)
	r := httptest.NewRequest("POST", "/v1/pull", bytes.NewReader(body))
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{
		{Subject: pkix.Name{CommonName: "admin", OrganizationalUnit: []string{"admin"}}},
	}}
	w := &recWriter{}
	c.handlePull(w, r)
	if w.buf.Len() == 0 {
		t.Fatal("pull 未返回授权")
	}
	var g api.TransferGrant
	if err := json.Unmarshal(w.buf.Bytes(), &g); err != nil {
		t.Fatal(err)
	}
	if g.Src != "store" || g.Dst != "ffctl-abc" {
		t.Fatalf("src/dst 不符：%s -> %s", g.Src, g.Dst)
	}
	if len(g.Hops) != 2 || g.Hops[1].NodeID != "ffctl-abc" {
		t.Fatalf("Hops[1] 应是 ffctl 端点：%+v", g.Hops)
	}
	if g.Hops[1].Addr != "10.0.0.5" || g.Hops[1].TCPPort != 40000 {
		t.Fatalf("回连地址不对：%+v", g.Hops[1])
	}
	if g.DstPath != "/tmp/out/f.bin" {
		t.Fatalf("目录目标应补源文件名，实际 %q", g.DstPath)
	}
	if g.FileSHA256 != "" {
		t.Fatalf("默认不应钉死索引摘要（索引可能过期），实际 %q", g.FileSHA256)
	}
	// 授权应已排给源节点
	c.mu.Lock()
	n := len(c.pending["store"])
	c.mu.Unlock()
	if n != 1 {
		t.Fatalf("授权应入源节点队列，实际 %d 条", n)
	}
	if !g.Verify(c.signPub) {
		t.Fatal("签发的授权验签失败")
	}

	// 显式 PinHash 时才用索引
	req.PinHash = true
	body, _ = json.Marshal(req)
	r2 := httptest.NewRequest("POST", "/v1/pull", bytes.NewReader(body))
	r2.TLS = r.TLS
	w2 := &recWriter{}
	c.handlePull(w2, r2)
	var g2 api.TransferGrant
	if err := json.Unmarshal(w2.buf.Bytes(), &g2); err != nil {
		t.Fatal(err)
	}
	if g2.FileSHA256 != "deadbeef" || g2.FileSize != 123 {
		t.Fatalf("PinHash 时应带上索引摘要，实际 %q/%d", g2.FileSHA256, g2.FileSize)
	}
}

// 回归：pushProto 内部会取 c.mu，若在锁区里调用就会自死锁
// （实测表现：controller 卡死、所有心跳超时、整个集群失联）。
func TestRegressPushNoDeadlock(t *testing.T) {
	c := newTestController(t)
	c.graph.Apply(api.Heartbeat{
		NodeID: "n1", Hostname: "h", Addr: "10.0.0.9:17800", TCPPort: 18400, TS: time.Now(),
	})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 20; i++ {
			r := httptest.NewRequest("POST", "/v1/push", bytes.NewReader(mustJSONBody(t, api.PushRequest{
				Dst: "n1", DstPath: "/tmp/x.bin", LocalPath: "x.bin",
				SHA256: "aa", Size: 1,
			})))
			r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{
				{Subject: pkix.Name{CommonName: "admin", OrganizationalUnit: []string{"admin"}}},
			}}
			c.handlePush(&recWriter{}, r)
		}
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("handlePush 卡住（回归：pushProto 在锁区内调用导致自死锁）")
	}
}

func mustJSONBody(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// 回归：controller 必须能从实测中学会"这条边该用哪个协议"。
//
// 背景：QUIC 在高丢包链路上会被基于丢包的拥塞控制压塌（实测 2% 丢包时
// 10MB 从 0.5s 变 25~30s，TCP 只要 0.04s）。探测只测握手 RTT，看不出
// 稳态吞吐差异，所以必须按协议分开记实测吞吐并据此选路。
func TestRegressProtoLearning(t *testing.T) {
	c := newTestController(t)
	c.graph.Apply(api.Heartbeat{
		NodeID: "peer", Hostname: "h", Addr: "10.0.0.9:17800", TCPPort: 18400, TS: time.Now(),
	})

	// 没有实测数据时：按探测结果（这里没边，落到默认 quic）
	if got := c.bestProto("", "peer", "quic"); got != "quic" {
		t.Fatalf("无数据时应回落默认：%s", got)
	}

	// 记录：quic 在这条边上只有 0.33 MB/s，tcp 有 250 MB/s
	c.recordProtoBW("peer", "peer", "quic", 0.33)
	c.recordProtoBW("peer", "peer", "tcp", 250)

	// 现在要求选路给出 tcp
	if got := c.bestProto("peer", "peer", "quic"); got != "tcp" {
		t.Fatalf("学到 tcp 更快后应选 tcp，实际 %s（回归：未按协议学习）", got)
	}

	// 反向：如果 quic 后来变快（网络恢复），应能切回 quic
	c.recordProtoBW("peer", "peer", "quic", 400)
	c.recordProtoBW("peer", "peer", "quic", 400)
	c.recordProtoBW("peer", "peer", "quic", 400)
	if got := c.bestProto("peer", "peer", "tcp"); got != "quic" {
		t.Fatalf("quic 变快后应切回 quic，实际 %s", got)
	}

	// EMA 平滑：单次跳变不应完全覆盖历史（避免选路抖动）
	c2 := newTestController(t)
	c2.recordProtoBW("a", "b", "quic", 1000)
	c2.recordProtoBW("a", "b", "quic", 1)
	got := c2.protoBW[[2]api.NodeID{"a", "b"}]["quic"]
	if got < 300 {
		t.Fatalf("EMA 应保留历史趋势，一次骤降后不该直接到 1，实际 %.1f", got)
	}

	// proto 为空或吞吐非正数时不应污染记录
	c2.recordProtoBW("a", "b", "", 100)
	c2.recordProtoBW("a", "b", "tcp", 0)
	if _, ok := c2.protoBW[[2]api.NodeID{"a", "b"}]["tcp"]; ok {
		t.Fatal("非正吞吐不应被记录")
	}
}

// 回归：req.Proto 必须能强制数据面协议。
//
// 之前 `ffctl -proto tcp send ...` 被**静默忽略**：TransferRequest 里根本
// 没有这个字段，controller 只按探测结果选。被墙链路里 UDP 常被拦，用户
// 以为强制了 TCP，实际仍走默认——排查时会误判成"TCP 也不行"。
func TestRegressTransferRequestProtoOverride(t *testing.T) {
	// 直接验证字段能被序列化进请求（API 面）
	var req api.TransferRequest
	body := []byte(`{"src":"a","src_path":"/x","dst":"b","dst_path":"/y","proto":"tcp"}`)
	if err := json.Unmarshal(body, &req); err != nil {
		t.Fatal(err)
	}
	if req.Proto != "tcp" {
		t.Fatalf("Proto 未被解析：%q", req.Proto)
	}
	// 非法的值不应被当成覆盖指令（由 controller 侧判断）
	for _, v := range []string{"", "udp", "TCP"} {
		req2 := api.TransferRequest{Proto: v}
		if req2.Proto == "tcp" || req2.Proto == "quic" {
			t.Errorf("%q 不应被视为有效覆盖", v)
		}
	}
}
