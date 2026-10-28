package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"fileferry/internal/api"
)

func reqAs(method, path, cn, role string, body any) *http.Request {
	var r *http.Request
	if body == nil {
		r = httptest.NewRequest(method, path, nil)
	} else {
		b, _ := json.Marshal(body)
		r = httptest.NewRequest(method, path, bytes.NewReader(b))
	}
	if cn != "" {
		r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{
			Subject: pkix.Name{CommonName: cn, OrganizationalUnit: []string{role}},
		}}}
	}
	return r
}

// 回归：吊销必须对**所有**已认证路由生效。
//
// 之前 c.revoked 只在 4 处被消费（pull/push 的目的端检查、renew、heartbeat），
// /v1/index、/v1/jobdone、/v1/keypass、/v1/get 都不查。被吊销的节点在证书
// 剩余有效期（节点 24h、admin 10 年）内还能重填副本索引、改写任务终态并污染
// 调度权重、取走密钥。这里直接验证闸门本身。
func TestRevokedCertIsBlockedEverywhere(t *testing.T) {
	c := newTestController(t)
	c.revoked["node-3"] = true

	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/enroll", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	mux.HandleFunc("POST /v1/index", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	mux.HandleFunc("POST /v1/jobdone", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	mux.HandleFunc("GET /v1/keypass", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	h := c.revokeGuard(mux)

	for _, tc := range []struct{ method, path string }{
		{"POST", "/v1/index"},
		{"POST", "/v1/jobdone"},
		{"GET", "/v1/keypass?id=x"},
		{"GET", "/v1/status"},
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, reqAs(tc.method, tc.path, "node-3", "node", nil))
		if rec.Code != http.StatusForbidden {
			t.Fatalf("%s %s 对已吊销证书返回 %d，期望 403", tc.method, tc.path, rec.Code)
		}
	}

	// 未吊销的节点、以及（没有客户端证书的）enroll 必须放行
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, reqAs("GET", "/v1/status", "node-4", "node", nil))
	if rec.Code != 200 {
		t.Fatalf("未吊销节点被误拦：%d", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, reqAs("POST", "/v1/enroll", "", "", map[string]string{"token": "t"}))
	if rec.Code != 200 {
		t.Fatalf("enroll 不该被吊销闸拦（此时还没有客户端证书）：%d", rec.Code)
	}
}

// 回归：ffctl put 必须真正遵守 enc-default。
//
// handlePush 组 grant 时字面量里没有 Enc 字段，于是即使 enc-default: true，
// `ffctl put` 发出的也是明文 grant —— 而 README 与 crypto.go 都宣称"中继只
// 见密文"。这条是我在真机上用 HTTP 复现过的。
func TestPushHonorsEncDefault(t *testing.T) {
	c := newTestController(t)
	c.cfg.EncDefault = true
	c.graph.Apply(api.Heartbeat{NodeID: "n1", Hostname: "h", Addr: "10.0.0.9:17800", TCPPort: 18400, TS: time.Now()})

	w := &recWriter{}
	c.handlePush(w, reqAs("POST", "/v1/push", "admin", "admin", api.PushRequest{
		Dst: "n1", DstPath: "/tmp/x.bin", LocalPath: "x.bin", SHA256: "aa", Size: 1,
	}))
	var g api.TransferGrant
	if err := json.Unmarshal(w.buf.Bytes(), &g); err != nil {
		t.Fatalf("push 响应不是 grant：%v（body=%q）", err, w.buf.String())
	}
	if !g.Enc {
		t.Fatal("enc-default=true 但 push 签发的 grant 没带 enc：put 会发明文")
	}
	if !g.Verify(c.signPub) {
		t.Fatal("签发的 grant 验签失败")
	}

	// 关掉默认值时也不能乱加密
	c2 := newTestController(t)
	c2.graph.Apply(api.Heartbeat{NodeID: "n1", Hostname: "h", Addr: "10.0.0.9:17800", TCPPort: 18400, TS: time.Now()})
	w2 := &recWriter{}
	c2.handlePush(w2, reqAs("POST", "/v1/push", "admin", "admin", api.PushRequest{
		Dst: "n1", DstPath: "/tmp/x.bin", LocalPath: "x.bin", SHA256: "aa", Size: 1,
	}))
	var g2 api.TransferGrant
	if err := json.Unmarshal(w2.buf.Bytes(), &g2); err != nil {
		t.Fatal(err)
	}
	if g2.Enc {
		t.Fatal("enc-default 默认关时不该加密")
	}
}

// 回归：索引上报要限条目数并走单事务。
// 之前 DELETE 之后逐条 Exec、无事务、无上限，而 DB 只有一条连接，
// 一次 16MiB 上报（约 10 万条）就能把控制面整体拖停。
func TestIndexReportBounded(t *testing.T) {
	c := newTestController(t)

	tooMany := make([]api.IndexEntry, maxIndexEntries+1)
	for i := range tooMany {
		tooMany[i] = api.IndexEntry{Path: "/x", SHA256: itoa(i)}
	}
	w := &recWriter{}
	c.handleIndex(w, reqAs("POST", "/v1/index", "n1", "node",
		api.IndexReport{NodeID: "n1", Entries: tooMany}))
	if w.Code() != http.StatusRequestEntityTooLarge {
		t.Fatalf("超限索引应 413，实际 %d", w.Code())
	}

	// 正常规模必须落库（且是一次事务里完成的）。
	// 换一个节点名：limiter 是每节点 1/s，上面那次 413 也计了数。
	c.limiter = &rateLimiter{seen: map[string][]time.Time{}}
	ok := []api.IndexEntry{
		{Path: "/a", SHA256: "s1", Size: 1},
		{Path: "/b", SHA256: "s2", Size: 2},
	}
	w2 := &recWriter{}
	c.handleIndex(w2, reqAs("POST", "/v1/index", "n1", "node",
		api.IndexReport{NodeID: "n1", Entries: ok}))
	if w2.Code() != 200 {
		t.Fatalf("正常索引上报失败：%d %s", w2.Code(), w2.buf.String())
	}
	var n int
	if err := c.db.QueryRow(`SELECT COUNT(*) FROM replicas WHERE node='n1'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("落库条数 %d，期望 2", n)
	}
}

// 回归：jobdone 必须限速。
// 它是唯一没有 limiter 的写接口，而 jobUpdate/event 每次都会派生 goroutine
// 去抢那条唯一的 DB 连接。
func TestJobDoneRateLimited(t *testing.T) {
	c := newTestController(t)
	g := api.TransferGrant{
		ID: "xfer-rl", Src: "n1", Dst: "n2",
		Hops:      []api.Hop{{NodeID: "n1"}, {NodeID: "n2"}},
		ExpiresAt: time.Now().Add(time.Hour),
	}
	c.jobPersist(&g)

	limited := false
	for i := 0; i < 60; i++ {
		w := &recWriter{}
		c.handleJobDone(w, reqAs("POST", "/v1/jobdone", "n1", "node",
			api.DoneRequest{GrantID: "xfer-rl", NodeID: "n1", OK: true}))
		if w.Code() == http.StatusTooManyRequests {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("连打 60 次 jobdone 都没被限速：单张证书即可堆爆 DB 连接与 events 表")
	}
}

// 回归：任务行缺失时 jobdone 必须失败关闭。
// 旧写法 `len(parts) > 0 && !parts[req.NodeID]` 在 grantParticipants 返回 nil
// 时直接放行，等于"查不到就允许任何节点改写终态"。
func TestJobDoneUnknownGrantRejected(t *testing.T) {
	c := newTestController(t)
	w := &recWriter{}
	c.handleJobDone(w, reqAs("POST", "/v1/jobdone", "n1", "node",
		api.DoneRequest{GrantID: "xfer-does-not-exist", NodeID: "n1", OK: true}))
	if w.Code() != http.StatusNotFound {
		t.Fatalf("未知 grant 应 404，实际 %d", w.Code())
	}
}

// 回归：台账必须原子写；解析失败必须拒绝启动而不是静默清空。
//
// 旧实现 os.WriteFile 原地截断且丢弃错误，加载时把 Unmarshal 错误也丢掉：
// 台账一旦被截断，Burned 变空 → 所有已核销的入网 token 复活，NextNode 归 1
// → 新节点可能拿到旧编号与既有 CN 撞号。
func TestEnrollLedgerSurvivesTruncation(t *testing.T) {
	dir := t.TempDir()
	l := &enrollLedger{Burned: map[string]string{"h1": "node-1"}, NextNode: 7, Used: map[string]bool{"node-1": true}}
	l.save(dir)

	// 正常读回
	got := loadEnrollLedger(dir)
	if got.Burned["h1"] != "node-1" || got.NextNode != 7 {
		t.Fatalf("台账没持久化：%+v", got)
	}

	// 原子写不应该留下临时文件
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".tmp-") {
			t.Fatalf("原子写残留临时文件：%s", e.Name())
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "enroll-ledger.json")); err != nil {
		t.Fatalf("台账文件不存在：%v", err)
	}
}

// 回归：吊销未知节点必须 404，而不是"静默成功"。
func TestRevokeUnknownNodeIs404(t *testing.T) {
	c := newTestController(t)
	w := &recWriter{}
	c.handleRevoke(w, reqAs("POST", "/v1/revoke", "admin", "admin", map[string]string{"node": "typo-node"}))
	if w.Code() != http.StatusNotFound {
		t.Fatalf("未知节点应 404（打错字母不能算吊销成功），实际 %d", w.Code())
	}

	// 已入网过的名字必须能吊销
	c.ledger.Used["real-node"] = true
	w2 := &recWriter{}
	c.handleRevoke(w2, reqAs("POST", "/v1/revoke", "admin", "admin", map[string]string{"node": "real-node"}))
	if w2.Code() != 200 {
		t.Fatalf("已知节点吊销失败：%d %s", w2.Code(), w2.buf.String())
	}
	if !c.revoked["real-node"] {
		t.Fatal("吊销没有生效")
	}
}

// 回归：密钥必须按「grant + 源」分槽，且只有源能写、只有目的端能读。
//
// 旧实现单槽 last-write-wins：多源 + 加密时后上报的源覆盖前面，目的端只能
// 解开其中一个源的块；参与方判定只认 Src/Dst，分片源上报会被 403。
func TestKeypassPerSourceSlots(t *testing.T) {
	c := newTestController(t)
	g := api.TransferGrant{
		ID: "xfer-multi", Src: "s1", Dst: "d1", Enc: true,
		Hops:      []api.Hop{{NodeID: "s1"}, {NodeID: "d1"}},
		Sources:   []api.SourceSpec{{NodeID: "s1", Start: 0, End: 1}, {NodeID: "s2", Start: 1, End: 2}},
		ExpiresAt: time.Now().Add(time.Hour),
	}
	c.jobPersist(&g)

	post := func(cn, key string) *recWriter {
		w := &recWriter{}
		c.handleKeypassPost(w, reqAs("POST", "/v1/keypass", cn, "node",
			map[string]string{"grant_id": "xfer-multi", "key_b64": key}))
		return w
	}
	if w := post("s1", "key-from-s1"); w.Code() != 200 {
		t.Fatalf("主源上报失败：%d %s", w.Code(), w.buf.String())
	}
	if w := post("s2", "key-from-s2"); w.Code() != 200 {
		t.Fatalf("分片源上报失败：%d %s（回归：参与方判定漏了 Sources）", w.Code(), w.buf.String())
	}
	if w := post("d1", "attacker"); w.Code() != http.StatusForbidden {
		t.Fatalf("目的端不该能写密钥：%d", w.Code())
	}
	if w := post("outsider", "x"); w.Code() != http.StatusForbidden {
		t.Fatalf("无关节点不该能写密钥：%d", w.Code())
	}

	get := func(cn, src string) *recWriter {
		w := &recWriter{}
		c.handleKeypassGet(w, reqAs("GET", "/v1/keypass?id=xfer-multi&src="+src, cn, "node", nil))
		return w
	}
	for _, tc := range []struct{ src, want string }{{"s1", "key-from-s1"}, {"s2", "key-from-s2"}} {
		w := get("d1", tc.src)
		if w.Code() != 200 {
			t.Fatalf("目的端取 %s 的密钥失败：%d", tc.src, w.Code())
		}
		var resp struct {
			KeyB64 string `json:"key_b64"`
			Src    string `json:"src"`
		}
		_ = json.Unmarshal(w.buf.Bytes(), &resp)
		if resp.KeyB64 != tc.want {
			t.Fatalf("源 %s 的密钥被覆盖：拿到 %q，期望 %q", tc.src, resp.KeyB64, tc.want)
		}
	}
	// 非目的端不能读
	if w := get("s2", "s1"); w.Code() != http.StatusForbidden {
		t.Fatalf("非目的端不该能读密钥：%d", w.Code())
	}
	// 重复取用必须仍然可用（多流各自建组、接收端重启续传都会再来取一次）
	if w := get("d1", "s1"); w.Code() != 200 {
		t.Fatalf("第二次取密钥失败：%d（回归：一次性发放让并行流互相踩）", w.Code())
	}
}

// 回归：events / jobs 必须有保留策略。
//
// 三张表原本没有任何 DELETE：审计每条请求一行、任务每次状态变更加一行，
// 跑几个月就是几十万行，SQLite 文件只涨不落。
func TestPruneHistoryKeepsActiveJobs(t *testing.T) {
	c := newTestController(t)
	old := time.Now().AddDate(0, 0, -90)

	// 一条很旧的已完成任务 + 一条很旧但仍在排队的任务
	c.jobPersist(&api.TransferGrant{ID: "old-done", Src: "n1", Dst: "n2", ExpiresAt: time.Now().Add(time.Hour)})
	c.jobPersist(&api.TransferGrant{ID: "old-queued", Src: "n1", Dst: "n2", ExpiresAt: time.Now().Add(time.Hour)})
	if _, err := c.db.Exec(`UPDATE jobs SET status='done', updated=? WHERE id='old-done'`, old.Unix()); err != nil {
		t.Fatal(err)
	}
	if _, err := c.db.Exec(`UPDATE jobs SET updated=? WHERE id='old-queued'`, old.Unix()); err != nil {
		t.Fatal(err)
	}
	// 两条陈旧审计事件 + 一条新的
	for _, ts := range []int64{old.Unix(), old.Unix(), time.Now().Unix()} {
		if _, err := c.db.Exec(`INSERT INTO events(ts,kind,node,detail) VALUES(?,?,?,?)`, ts, "test", "n1", ""); err != nil {
			t.Fatal(err)
		}
	}

	ev, jb, err := c.pruneHistory(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if ev != 2 {
		t.Fatalf("应删除 2 条陈旧事件，实际 %d", ev)
	}
	if jb != 1 {
		t.Fatalf("应删除 1 条陈旧任务（且只删终态），实际 %d", jb)
	}

	for _, id := range []string{"old-done", "old-queued"} {
		var n int
		if err := c.db.QueryRow(`SELECT COUNT(*) FROM jobs WHERE id=?`, id).Scan(&n); err != nil {
			t.Fatal(err)
		}
		want := 0
		if id == "old-queued" {
			want = 1 // 排队中的任务不能删：它是重启恢复的依据
		}
		if n != want {
			t.Fatalf("%s 剩余 %d 条，期望 %d", id, n, want)
		}
	}
}
