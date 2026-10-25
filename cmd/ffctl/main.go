// ffctl：命令行入口。
//
//	ffctl send /data/big.iso node-3:/data/     发起按需传输
//	ffctl status                               查看全图负载与可达性
package main

import (
	"strconv"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"fileferry/internal/api"
	"fileferry/internal/ca"
)

const usage = `用法：
  ffctl -cert-dir <dir> send <src-node>:<path> <dst-node>:<path>
  ffctl -cert-dir <dir> status

cert-dir 是某台已入网机器的 data-dir（复用其 mTLS 证书）。
TODO(M5)：独立的管理员令牌，无需借用节点证书。`

func main() {
	certDir := ""
	controller := "https://127.0.0.1:8443"
	jsonOut := false
	noWait := false
	args := os.Args[1:]
	var rest []string
	for i := 0; i < len(args); i++ {
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
		grant, err := cl.Send(api.TransferRequest{Src: srcNode, SrcPath: srcPath, Dst: dstNode, DstPath: dstPath})
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
		for time.Now().Before(deadline) {
			time.Sleep(2 * time.Second)
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
	case "get":
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

func newClient(controller, certDir string) (*api.Client, error) {
	// 优先使用管理员证书（admin.crt，由 controller 首次启动生成）；
	// 否则退回节点证书（node 角色无法发起传输，仅用于诊断连通性）。
	crt, key := filepath.Join(certDir, "node.crt"), filepath.Join(certDir, "node.key")
	if _, err := os.Stat(filepath.Join(certDir, "admin.crt")); err == nil {
		crt, key = filepath.Join(certDir, "admin.crt"), filepath.Join(certDir, "admin.key")
	}
	cert, err := tls.LoadX509KeyPair(crt, key)
	if err != nil {
		return nil, err
	}
	rootPEM, err := os.ReadFile(filepath.Join(certDir, "ca.crt"))
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(rootPEM) {
		return nil, fmt.Errorf("ca.crt 解析失败")
	}
	return &api.Client{
		Base: controller,
		HC: &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			RootCAs:      pool,
			MinVersion:   tls.VersionTLS13,
		}}},
	}, nil
}

// splitNodePath 拆 "node-3:/data/x.iso"。
func splitNodePath(s string) (node, path string, ok bool) {
	i := strings.Index(s, ":")
	if i <= 0 || i == len(s)-1 {
		return "", "", false
	}
	return s[:i], s[i+1:], true
}
