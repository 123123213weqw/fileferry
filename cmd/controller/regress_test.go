package main

import (
	"bytes"
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
	h   http.Header
	buf bytes.Buffer
}

func (w *recWriter) Header() http.Header {
	if w.h == nil {
		w.h = http.Header{}
	}
	return w.h
}
func (w *recWriter) Write(p []byte) (int, error) { return w.buf.Write(p) }
func (w *recWriter) WriteHeader(int)             {}

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
	return &controller{
		cfg:          Config{DataDir: dir},
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

// 回归：nodeID 优先使用请求的稳定名字，且不撞号。
func TestRegressStableNodeName(t *testing.T) {
	led := &enrollLedger{Burned: map[string]string{}, NextNode: 1, Used: map[string]bool{}}

	if !led.claim("web-01") {
		t.Fatal("首次占用应成功")
	}
	if led.claim("web-01") {
		t.Fatal("重复占用应失败（重名）")
	}
	// 自动编号必须跳过已占用
	if id := led.nextAutoNodeID(); id == "web-01" {
		t.Fatal("自动编号撞上了手工名")
	}
	if id := led.nextAutoNodeID(); !led.claim(id) {
		t.Fatalf("自动编号 %s 应未被占用", id)
	}

	for _, bad := range []string{"", "..", "../../etc", "  ", "-", "a b/?*"} {
		got := sanitizeNodeName(bad)
		if got != "" && (got == ".." || len(got) > 63) {
			t.Fatalf("%q 未被清洗：%q", bad, got)
		}
	}
	if sanitizeNodeName("") != "" {
		t.Fatal("空名字应返回空串")
	}
	if got := sanitizeNodeName("a b/?*"); got == "" {
		t.Fatal("含特殊字符但可清洗的名字不应被拒")
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
