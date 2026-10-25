// ffctl：命令行入口。
//
//	ffctl send /data/big.iso node-3:/data/     发起按需传输
//	ffctl status                               查看全图负载与可达性
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"fileferry/internal/api"
	"fileferry/internal/ca"
	"fileferry/internal/transfer"
)

const usage = `用法：
  ffctl -cert-dir <dir> put  <本机文件> <dst-node>:<path>   ← 本机直推（等价 scp）
  ffctl -cert-dir <dir> get  <src-node>:<path> <本机路径>   ← 拉取到本机（等价 scp）
  ffctl -rate <字节/秒> -streams <n> -proto quic|tcp ...      ← 可选：限速 / 并行流数 / 强制协议
  ffctl -cert-dir <dir> send <src-node>:<path> <dst-node>:<path>
  ffctl -cert-dir <dir> status

cert-dir 是某台已入网机器的 data-dir（复用其 mTLS 证书）。
TODO(M5)：独立的管理员令牌，无需借用节点证书。`

func main() {
	certDir := ""
	controller := "https://127.0.0.1:8443"
	jsonOut := false
	noWait := false
	rateBps := int64(0) // -rate：限速（字节/秒），0 = 不限
	streams := 0        // -streams：并行流数，0 = 由 controller 决定
	advertise := ""     // -advertise：ffctl 接收端对外地址（NAT 后需显式给）
	pinHash := false    // -pin：把源节点索引里的摘要钉进授权（强校验）
	// -proto：强制数据面协议。auto（默认）= 按提示依次尝试；
	// quic / tcp 则只试一种。高丢包链路上 QUIC 会因拥塞控制把吞吐
	// 压到极低（实测 2% 丢包时 10MB 从 0.5s 变 25s），此时应显式选 tcp。
	protoSel := "auto"
	args := os.Args[1:]
	var rest []string
	for i := 0; i < len(args); i++ {
		if args[i] == "-proto" {
			if i+1 < len(args) {
				protoSel = args[i+1]
				i++
			}
			continue
		}
		if args[i] == "-pin" {
			pinHash = true
			continue
		}
		if args[i] == "-advertise" {
			if i+1 < len(args) {
				advertise = args[i+1]
				i++
			}
			continue
		}
		if args[i] == "-streams" {
			if i+1 < len(args) {
				if n, err := strconv.Atoi(args[i+1]); err == nil {
					streams = n
				}
				i++
			}
			continue
		}
		if args[i] == "-rate" {
			if i+1 < len(args) {
				if n, err := strconv.ParseInt(args[i+1], 10, 64); err == nil {
					rateBps = n
				}
				i++
			}
			continue
		}
		if args[i] == "-cert-dir" || args[i] == "-controller" {
			if i+1 < len(args) {
				if args[i] == "-cert-dir" {
					certDir = args[i+1]
				} else {
					controller = args[i+1]
				}
			}
			i++
			continue
		}
		if args[i] == "-json" {
			jsonOut = true
			continue
		}
		if args[i] == "-nowait" {
			noWait = true
			continue
		}
		rest = args[i:]
		break
	}
	if certDir == "" || len(rest) == 0 {
		// token 不需要证书即可执行
		if len(rest) == 1 && rest[0] == "token" {
			if tok, err := ca.NewEnrollToken(); err == nil {
				fmt.Println(tok)
				return
			}
			os.Exit(1)
		}
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}

	cl, err := newClient(controller, certDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "证书加载失败：", err)
		os.Exit(1)
	}

	switch rest[0] {
	case "send":
		if len(rest) != 3 {
			fmt.Fprintln(os.Stderr, usage)
			os.Exit(2)
		}
		srcNode, srcPath, ok1 := splitNodePath(rest[1])
		dstNode, dstPath, ok2 := splitNodePath(rest[2])
		if !ok1 || !ok2 {
			fmt.Fprintln(os.Stderr, "路径格式应为 node:/path")
			os.Exit(2)
		}
		grant, err := cl.Send(api.TransferRequest{Src: srcNode, SrcPath: srcPath, Dst: dstNode, DstPath: dstPath, RateLimit: rateBps})
		if err != nil {
			fmt.Fprintln(os.Stderr, "传输请求失败：", err)
			os.Exit(1)
		}
		fmt.Printf("已签发 %s：%s -> %s", grant.ID, grant.Src, grant.Dst)
		if grant.Mode == "switch" {
			fmt.Printf("（交换台 %s 对接）", grant.Hops[1].NodeID)
		} else if len(grant.Relays) > 0 {
			fmt.Printf("（经 %s 中继）", strings.Join(grant.Relays, " -> "))
		}
		if noWait {
			fmt.Println("；任务已入队（-nowait：不等待完成）")
			return
		}
		// 默认等待完成：轮询任务状态，退出码反映结果（agent/脚本友好）
		fmt.Println("；等待完成…")
		deadline := time.Now().Add(10 * time.Minute)
		// 自适应轮询：小文件应当"立刻就回"，长传输再退到 1s 一次。
		// 之前固定 2s，意味着任何一次 send 至少多等 2 秒——scp 是立即
		// 结束的，这条延迟直接决定"用起来像不像 scp"。
		interval := 100 * time.Millisecond
		for time.Now().Before(deadline) {
			time.Sleep(interval)
			if interval < time.Second {
				interval *= 2
			}
			jobs, err := cl.Jobs(grant.ID)
			if err != nil || len(jobs) == 0 {
				continue
			}
			switch jobs[0].Status {
			case "done":
				fmt.Printf("完成：%s（%s -> %s）\n", jobs[0].ID, jobs[0].Src, jobs[0].Dst)
				return
			case "failed":
				fmt.Fprintf(os.Stderr, "失败：%s（%s -> %s）\n", jobs[0].ID, jobs[0].Src, jobs[0].Dst)
				os.Exit(1)
			}
		}
		fmt.Fprintln(os.Stderr, "超时：10 分钟内未完成（可用 -nowait 改为只入队）")
		os.Exit(1)
	case "put":
		// ffctl put <本机文件> <dst-node>:<远端路径>
		// 等价于 scp local host:/path：本机直接连目标节点数据面推送，
		// 不经过 controller，也不需要文件先存在于某台节点上。
		if len(rest) != 3 {
			fmt.Fprintln(os.Stderr, "用法: ffctl put <本机文件> <dst-node>:<远端路径>")
			os.Exit(2)
		}
		localPath := rest[1]
		dstNode, dstPath, ok := splitNodePath(rest[2])
		if !ok {
			fmt.Fprintln(os.Stderr, "目标格式应为 node:/path")
			os.Exit(2)
		}
		if err := runPut(cl, certDir, localPath, dstNode, dstPath, rateBps, streams, protoSel, noWait); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	case "get":
		// 两种用法：
		//   ffctl get <src-node>:<path> <本机路径>   ← 从节点拉到本机（等价 scp）
		//   ffctl get <取件码>                        ← 兑换 share 取件码
		if len(rest) == 3 {
			srcNode, srcPath, ok := splitNodePath(rest[1])
			if !ok {
				fmt.Fprintln(os.Stderr, "源格式应为 node:/path")
				os.Exit(2)
			}
			if err := runGet(cl, certDir, srcNode, srcPath, rest[2], streams, advertise, pinHash); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			return
		}
		if len(rest) != 2 {
			fmt.Fprintln(os.Stderr, "用法: ffctl get <取件码>")
			os.Exit(2)
		}
		var g api.TransferGrant
		if err := cl.Post("/v1/get", map[string]string{"code": rest[1]}, &g); err != nil {
			fmt.Fprintln(os.Stderr, "取件失败：", err)
			os.Exit(1)
		}
		fmt.Printf("已受理：%s -> 本机 %s（%s）\n", g.Src, g.DstPath, g.ID)
	case "token":
		// 铸造一枚一次性入网令牌：打印后由管理员加入 controller
		// 配置的 enroll-tokens 并重启 controller，再交给新服务器
		tok, err := ca.NewEnrollToken()
		if err != nil {
			fmt.Fprintln(os.Stderr, "生成失败：", err)
			os.Exit(1)
		}
		fmt.Println(tok)
	case "status":
		hbs, err := cl.Status()
		if err != nil {
			fmt.Fprintln(os.Stderr, "状态查询失败：", err)
			os.Exit(1)
		}
		if jsonOut { // 机器可读输出（agent/脚本）
			json.NewEncoder(os.Stdout).Encode(hbs)
			return
		}
		for _, h := range hbs {
			edges := make([]string, 0, len(h.Edges))
			for _, e := range h.Edges {
				edges = append(edges, fmt.Sprintf("%s/%.1fms/%s", e.To, e.RTTms, e.Proto))
			}
			fmt.Printf("%-8s %-20s cpu=%3.0f%% mem=%3.0f%% 负载传输=%d 出边=[%s]\n",
				h.NodeID, h.Hostname, h.CPUPct, h.MemPct, h.ActiveXfers, strings.Join(edges, " "))
		}
	case "share":
		if len(rest) < 2 || len(rest) > 3 {
			fmt.Fprintln(os.Stderr, "用法: ffctl share <node>:<path> [ttl分钟]")
			os.Exit(2)
		}
		ttl := 10
		if len(rest) == 3 {
			if n, err := strconv.Atoi(rest[2]); err == nil {
				ttl = n
			}
		}
		node, path, ok := splitNodePath(rest[1])
		if !ok {
			fmt.Fprintln(os.Stderr, "格式 node:/path")
			os.Exit(2)
		}
		var resp map[string]any
		if err := cl.Post("/v1/share", map[string]any{"src": node, "path": path, "ttl_min": ttl}, &resp); err != nil {
			fmt.Fprintln(os.Stderr, "分享失败：", err)
			os.Exit(1)
		}
		fmt.Printf("取件码：%v（%v 分钟内有效，最多 %v 次）\n目标机执行：ff get %v\n", resp["code"], resp["expires_in_min"], resp["max_uses"], resp["code"])
	case "revoke":
		if len(rest) != 2 {
			fmt.Fprintln(os.Stderr, "用法: ffctl revoke <node-id>")
			os.Exit(2)
		}
		var ignored struct{}
		if err := cl.Post("/v1/revoke", map[string]string{"node": rest[1]}, &ignored); err != nil {
			fmt.Fprintln(os.Stderr, "吊销失败：", err)
			os.Exit(1)
		}
		fmt.Printf("已吊销 %s（即刻剔除拓扑，旧授权 30 分钟内自然过期）\n", rest[1])
	case "jobs":
		jobs, err := cl.Jobs("")
		if err != nil {
			fmt.Fprintln(os.Stderr, "任务查询失败：", err)
			os.Exit(1)
		}
		if jsonOut {
			json.NewEncoder(os.Stdout).Encode(jobs)
			return
		}
		for _, j := range jobs {
			fmt.Printf("%-10s %-8s -> %-8s %-8s %s\n", j.ID, j.Src, j.Dst, j.Status, time.Unix(j.Updated, 0).Format("15:04:05"))
		}
	default:
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
}

// loadCreds 读取 cert-dir 里的 mTLS 凭据。
// 优先使用管理员证书（admin.crt，由 controller 首次启动生成）；否则
// 退回节点证书（node 角色无法发起传输，仅用于诊断连通性）。
func loadCreds(certDir string) (tls.Certificate, *x509.CertPool, error) {
	crt, key := filepath.Join(certDir, "node.crt"), filepath.Join(certDir, "node.key")
	if _, err := os.Stat(filepath.Join(certDir, "admin.crt")); err == nil {
		crt, key = filepath.Join(certDir, "admin.crt"), filepath.Join(certDir, "admin.key")
	}
	cert, err := tls.LoadX509KeyPair(crt, key)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	rootPEM, err := os.ReadFile(filepath.Join(certDir, "ca.crt"))
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(rootPEM) {
		return tls.Certificate{}, nil, fmt.Errorf("ca.crt 解析失败")
	}
	return cert, pool, nil
}

func newClient(controller, certDir string) (*api.Client, error) {
	cert, pool, err := loadCreds(certDir)
	if err != nil {
		return nil, err
	}
	return &api.Client{
		Base: controller,
		HC: &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			RootCAs:      pool,
			MinVersion:   tls.VersionTLS13,
		}}},
	}, nil
}

// dataPlaneTLS 是**直连目标节点数据面**用的 TLS 配置：同一套凭据，
// 根证书用于校验节点证书。用它跑 manifest 签名（BuildManifest 取
// Certificates[0] 的 ed25519 私钥）。
func dataPlaneTLS(certDir string) (*tls.Config, error) {
	cert, pool, err := loadCreds(certDir)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// runPut 实现本机直推：本地算摘要 → 控制面签授权 → 直连目标节点推送。
//
// 完整性：授权里带 FileSHA256/FileSize（controller 签名钉死），接收端
// 校验 manifest 与之一致，且逐块 SHA256——与节点间传输同一套保证。
// 权限：目标节点的 allowed-dirs 白名单照常生效。
func runPut(cl *api.Client, certDir, localPath, dstNode, dstPath string, rateBps int64, streams int, protoSel string, noWait bool) error {
	fi, err := os.Stat(localPath)
	if err != nil {
		return fmt.Errorf("读本机文件失败：%w", err)
	}
	if fi.IsDir() {
		return fmt.Errorf("%s 是目录：put 只支持单个文件（目录请先打包）", localPath)
	}
	sum, err := fileSHA256(localPath)
	if err != nil {
		return fmt.Errorf("计算摘要失败：%w", err)
	}

	var grant api.TransferGrant
	if err := cl.Post("/v1/push", api.PushRequest{
		Dst:       dstNode,
		DstPath:   dstPath,
		LocalPath: filepath.Base(localPath),
		SHA256:    sum,
		Size:      fi.Size(),
		RateLimit: rateBps,
		Streams:   streams,
	}, &grant); err != nil {
		return fmt.Errorf("申请推送授权失败：%w", err)
	}
	fmt.Printf("已授权 %s：本机 -> %s:%s（%d 字节）\n", grant.ID, grant.Dst, grant.DstPath, fi.Size())

	if noWait {
		fmt.Println("（-nowait 对 put 无效：推送由本进程完成，必须等待）")
	}

	tlsConf, err := dataPlaneTLS(certDir)
	if err != nil {
		return fmt.Errorf("加载数据面凭据失败：%w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	// 直连目标节点的数据面（Hops[1] 由 controller 填好地址与 TCP 端口）。
	// Proto 不在签名内，可以自由切换：先按提示试，失败再换另一种。
	// 之前 controller 硬编码 tcp，等于直推永远用不上 QUIC。
	// 进度显示 + 停滞检测共用同一份计数。
	// 进度：被墙链路上大文件可能跑几分钟，没有进度用户无法判断是卡死
	// 还是在传（我自己实测 91 秒静默卡顿时就分不清）。
	prog := &progressState{}
	stopProgress := startProgress(os.Stderr, fi.Size(), prog)
	defer stopProgress()

	protos := pickProtos(protoSel, grant.Hops[1].Proto)
	var (
		n     int64
		lastE error
		start = time.Now()
	)
	for i, pr := range protos {
		h := grant.Hops[1]
		h.Proto = pr
		prog.reset()
		// 每种尝试用独立 ctx：看门狗取消它即切断该协议的连接；
		// 外层 ctx 仍可用于整体超时/中断。
		actx, acancel := context.WithCancel(ctx)
		doneCh := make(chan struct{})
		if fi.Size() > stallMinBytes && i+1 < len(protos) {
			go func() {
				t := time.NewTicker(500 * time.Millisecond)
				defer t.Stop()
				for {
					select {
					case <-doneCh:
						return
					case <-t.C:
					}
					sent, el := prog.snapshot()
					if shouldSwitch(el, sent, fi.Size()) {
						fmt.Fprintf(os.Stderr, "\r  %s 太慢（%.0f KB/s），切换到 %s 重试（已收部分保留）\n",
							pr, float64(sent)/el.Seconds()/1024, protos[i+1])
						acancel()
						return
					}
				}
			}()
		}
		open := cancellableOpener(actx, transfer.OpenerDirect(actx, h, tlsConf))
		n, lastE = transfer.SendFile(actx, localPath, open, tlsConf, &grant)
		close(doneCh)
		acancel()
		if lastE == nil {
			break
		}
		if ctx.Err() != nil {
			break
		}
	}
	el := time.Since(start)
	if lastE != nil {
		return fmt.Errorf("推送失败（%v 均不可用）：%w", protos, lastE)
	}
	mbps := float64(n) / (1 << 20) / el.Seconds()
	fmt.Printf("完成：%s（%d 字节，%.2fs，%.0f MB/s，SHA256 %s…）\n",
		grant.DstPath, n, el.Seconds(), mbps, sum[:12])
	return nil
}

// runGet 实现"远端 → 本机"拉取：本机起临时 TLS 数据面接收端，由源节点
// 主动连过来推送。等价 scp host:/path ./local。
//
// 与 put 的差别：这里 ffctl 是 TLS **服务器**，所以需要一张带
// ServerAuth 的短时效证书（管理员证书只有 ClientAuth）。证书由
// controller 按需签发，CN 一次性。
func runGet(cl *api.Client, certDir, srcNode, srcPath, localPath string, streams int, advertise string, pinHash bool) error {
	var ep api.PullEndpoint
	if err := cl.Post("/v1/pullcert", struct{}{}, &ep); err != nil {
		return fmt.Errorf("申请传输端点证书失败：%w", err)
	}
	pair, err := tls.X509KeyPair([]byte(ep.CertPEM), []byte(ep.KeyPEM))
	if err != nil {
		return fmt.Errorf("加载端点证书失败：%w", err)
	}

	// 校验授权签名用的公钥
	block, _ := pem.Decode([]byte(ep.SignPubPEM))
	if block == nil {
		return fmt.Errorf("controller 未提供签名公钥")
	}
	pk, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("解析签名公钥失败：%w", err)
	}
	signPub, ok := pk.(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("签名公钥不是 ed25519")
	}

	// 根证书：优先用端点证书里的 CA（controller 已签发链），否则读 cert-dir
	_, pool, err := loadCreds(certDir)
	if err != nil {
		return fmt.Errorf("加载根证书失败：%w", err)
	}

	srvTLS := &tls.Config{
		Certificates: []tls.Certificate{pair},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		// RootCAs 必须同时设置：传输层（HandleStream → recvOne）用它来
		// 校验 manifest 签名者的证书链。只设 ClientCAs 会让根池为 nil，
		// 于是回退到系统根证书，验签必然失败（实测报
		// "certificate is using a broken key size"，具有误导性）。
		RootCAs:    pool,
		MinVersion: tls.VersionTLS13,
	}
	ln, err := tls.Listen("tcp", ":0", srvTLS)
	if err != nil {
		return fmt.Errorf("监听数据面失败：%w", err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	host := advertise
	if host == "" {
		host = localIPTowards(cl.Base)
	}
	listenAddr := net.JoinHostPort(host, strconv.Itoa(port))

	var grant api.TransferGrant
	if err := cl.Post("/v1/pull", api.PullRequest{
		NodeID:     ep.NodeID,
		Src:        srcNode,
		SrcPath:    srcPath,
		DstPath:    localPath,
		ListenAddr: listenAddr,
		ListenPort: port,
		Streams:    streams,
		PinHash:    pinHash,
	}, &grant); err != nil {
		return fmt.Errorf("申请拉取授权失败：%w", err)
	}
	fmt.Printf("已授权 %s：%s:%s -> 本机 %s（经由 %s）\n", grant.ID, grant.Src, grant.SrcPath, grant.DstPath, listenAddr)

	// 接收端放行任意本地路径（这是用户自己的机器，且路径由用户给出）
	transfer.SetPathGuard(nil)
	transfer.SetInboxRoot("")

	verify := func(g *api.TransferGrant) bool {
		return g.Verify(signPub) && time.Now().Before(g.ExpiresAt)
	}
	want := grant.Streams
	if want < 1 {
		want = 1
	}
	worst := make(chan error, want+1)
	var got int

	// 源节点会为每条流各建一条连接
	done := make(chan struct{}, want+1)
	go func() {
		for i := 0; i < want+1; i++ {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				peer := ""
				if tc, ok := c.(*tls.Conn); ok {
					if err := tc.Handshake(); err != nil {
						c.Close()
						return
					}
					if len(tc.ConnectionState().PeerCertificates) > 0 {
						peer = tc.ConnectionState().PeerCertificates[0].Subject.CommonName
					}
				}
				transfer.HandleStream(c, string(ep.NodeID), verify, srvTLS, peer)
				done <- struct{}{}
			}(c)
		}
	}()

	// 等文件落地（或失败）
	deadline := time.Now().Add(30 * time.Minute)
	finished := false
	lastPoll := time.Now()
	for time.Now().Before(deadline) {
		// 轮询任务状态：源端失败（文件不存在、白名单拒绝等）时必须
		// 立刻返回，否则会一直等到 30 分钟超时（实测源文件不存在时
		// 挂满 60 秒仍无输出）。
		if time.Since(lastPoll) > 2*time.Second {
			lastPoll = time.Now()
			if jobs, err := cl.Jobs(grant.ID); err == nil && len(jobs) > 0 {
				switch jobs[0].Status {
				case "failed":
					return fmt.Errorf("拉取失败：源端报告失败（%s）", jobs[0].ID)
				case "done":
					finished = true
				}
			}
		}
		if finished {
			break
		}
		if st, err := os.Stat(grant.DstPath); err == nil && st.Size() >= 0 {
			// 只有在收到全部流或文件已完整时才认为完成：用 grant 里的大小判断
			if grant.FileSize > 0 && st.Size() == grant.FileSize {
				finished = true
				break
			}
			if grant.FileSize == 0 && st.Size() > 0 {
				finished = true
				break
			}
		}
		select {
		case <-done:
			got++
			if got >= want {
				finished = true
			}
		case <-time.After(200 * time.Millisecond):
		}
		if finished {
			break
		}
	}
	select {
	case err := <-worst:
		if err != nil {
			return err
		}
	default:
	}
	if !finished {
		return fmt.Errorf("拉取超时：%s 未在 30 分钟内就绪", grant.DstPath)
	}
	st, err := os.Stat(grant.DstPath)
	if err != nil {
		return fmt.Errorf("拉取结束但本机没有文件：%w", err)
	}
	fmt.Printf("完成：%s（%d 字节）\n", grant.DstPath, st.Size())
	return nil
}

// localIPTowards 猜测本机对 controller 可达的地址（用于告诉源节点回连）。
func localIPTowards(base string) string {
	u, err := url.Parse(base)
	if err != nil {
		return "127.0.0.1"
	}
	host := u.Hostname()
	c, err := net.Dial("udp", net.JoinHostPort(host, "9"))
	if err != nil {
		return "127.0.0.1"
	}
	defer c.Close()
	if a, ok := c.LocalAddr().(*net.UDPAddr); ok {
		return a.IP.String()
	}
	return "127.0.0.1"
}

// startProgress 启动后台渲染协程，把进度画成单行。
//
// 进度计数同时供看门狗使用（见 watchdog.go）：两者必须共用同一份
// 计数，否则判断"跑得慢"的依据和用户看到的不一致。
// 返回的函数用于停止并换行。
func startProgress(w *os.File, total int64, st *progressState) func() {
	if st != nil {
		transfer.SetProgressSink(func(n int64) { st.add(n) })
	}
	if total <= 0 {
		return func() { transfer.SetProgressSink(nil) }
	}
	isTTY := false
	if fi, err := w.Stat(); err == nil {
		isTTY = fi.Mode()&os.ModeCharDevice != 0
	}
	if !isTTY {
		// 非终端（脚本/管道）：不打印，但保留计数供看门狗使用
		return func() { transfer.SetProgressSink(nil) }
	}
	done := make(chan struct{})
	go func() {
		t := time.NewTicker(200 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
			}
			cur, el := st.snapshot()
			pct := float64(cur) / float64(total) * 100
			if pct > 100 {
				pct = 100
			}
			if cur >= total {
				// 数据已发完但事务未结束：在等接收端校验并回 ACK。
				// 明确标出来，否则"100% 却还在转"看起来像卡死——
				// 实测这里可能持续数秒（对端要落盘 + 校验全文件哈希）。
				fmt.Fprintf(w, "\r  已发完，等待对端校验确认…（%s）   ", humanBytes(total))
				continue
			}
			speed := 0.0
			if el.Seconds() > 0.2 {
				speed = float64(cur) / el.Seconds() / (1 << 20)
			}
			fmt.Fprintf(w, "\r  %5.1f%%  %s / %s  %.1f MB/s   ",
				pct, humanBytes(cur), humanBytes(total), speed)
		}
	}()
	return func() {
		close(done)
		transfer.SetProgressSink(nil)
		fmt.Fprintln(w)
	}
}

// humanBytes 人类可读的字节数（1024 进制）。
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}

// pickProtos 决定尝试顺序。auto = 提示值 → quic → tcp；
// 显式指定时只试那一种（避免在高丢包链路上一遍遍重试 QUIC）。
func pickProtos(sel, hint string) []string {
	if sel == "quic" || sel == "tcp" {
		return []string{sel}
	}
	return dedupProtos(hint, "quic", "tcp")
}

// dedupProtos 按顺序去重并丢掉空串（第一个通常是 controller 给的建议值）。
func dedupProtos(in ...string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, p := range in {
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

// fileSHA256 流式算整文件摘要（大文件不整读进内存）。
func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// splitNodePath 拆 "node-3:/data/x.iso"。
func splitNodePath(s string) (node, path string, ok bool) {
	i := strings.Index(s, ":")
	if i <= 0 || i == len(s)-1 {
		return "", "", false
	}
	return s[:i], s[i+1:], true
}
