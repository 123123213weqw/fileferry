// ffctl：命令行入口。
//
//	ffctl send /data/big.iso node-3:/data/     发起按需传输
//	ffctl status                               查看全图负载与可达性
package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"fileferry/internal/api"
)

const usage = `用法：
  ffctl -cert-dir <dir> send <src-node>:<path> <dst-node>:<path>
  ffctl -cert-dir <dir> status

cert-dir 是某台已入网机器的 data-dir（复用其 mTLS 证书）。
TODO(M5)：独立的管理员令牌，无需借用节点证书。`

func main() {
	certDir := ""
	controller := "https://127.0.0.1:8443"
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
		rest = args[i:]
		break
	}
	if certDir == "" || len(rest) == 0 {
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
		if len(grant.Relays) > 0 {
			fmt.Printf("（经 %s 中继）", strings.Join(grant.Relays, " -> "))
		}
		fmt.Println("；任务已入队，源节点下次心跳（≤5s）后开始执行")
		// TODO(M2)：等待传输完成与状态查询
	case "status":
		hbs, err := cl.Status()
		if err != nil {
			fmt.Fprintln(os.Stderr, "状态查询失败：", err)
			os.Exit(1)
		}
		for _, h := range hbs {
			edges := make([]string, 0, len(h.Edges))
			for _, e := range h.Edges {
				edges = append(edges, fmt.Sprintf("%s/%.1fms/%s", e.To, e.RTTms, e.Proto))
			}
			fmt.Printf("%-8s %-20s cpu=%3.0f%% mem=%3.0f%% 负载传输=%d 出边=[%s]\n",
				h.NodeID, h.Hostname, h.CPUPct, h.MemPct, h.ActiveXfers, strings.Join(edges, " "))
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
