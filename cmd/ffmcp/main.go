// ffmcp：把 fileferry 封装为 MCP（Model Context Protocol）服务器。
// stdio 传输（JSON-RPC 2.0，行分隔 JSON），供 ZCode / Claude Desktop
// 等 MCP 客户端把"跨机传文件/看舰队拓扑"当原生工具调用。
//
// 配置（环境变量）：
//
//	FF_CERT_DIR    管理员证书目录（admin.crt/admin.key/ca.crt）
//	FF_CONTROLLER  controller 地址（默认 https://127.0.0.1:8443）
//
// 客户端接入示例（ZCode / Claude Desktop 的 mcpServers 配置）：
//
//	{"fileferry": {"command": "/path/to/ffmcp",
//	               "env": {"FF_CERT_DIR": "/home/me/ff-admin",
//	                       "FF_CONTROLLER": "https://1.2.3.4:9443"}}}
//
// 工具：ff_send / ff_status / ff_jobs / ff_token
package main

import (
	"bufio"
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

const protocolVersion = "2024-11-05"

// —— JSON-RPC / MCP 报文 ——

type rpcReq struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcErr struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcResp struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *rpcErr         `json:"error,omitempty"`
}

type toolDef struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

type callResult struct {
	Content []map[string]string `json:"content"`
	IsError bool                `json:"isError,omitempty"`
}

var client *api.Client

func main() {
	certDir := os.Getenv("FF_CERT_DIR")
	controller := os.Getenv("FF_CONTROLLER")
	if controller == "" {
		controller = "https://127.0.0.1:8443"
	}
	var err error
	client, err = newClient(controller, certDir)
	if err != nil {
		// MCP 服务器不能往 stdout 打日志（那是协议通道），错误留给 RPC
		fmt.Fprintf(os.Stderr, "ffmcp 初始化失败：%v\n", err)
		os.Exit(1)
	}

	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var req rpcReq
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			write(out, rpcResp{JSONRPC: "2.0", ID: json.RawMessage("null"), Error: &rpcErr{Code: -32700, Message: "parse error"}})
			continue
		}
		if req.ID == nil { // 通知（如 notifications/initialized）：不回
			continue
		}
		resp := dispatch(req)
		resp.JSONRPC = "2.0"
		resp.ID = req.ID
		write(out, resp)
	}
}

func write(out *bufio.Writer, r rpcResp) {
	b, _ := json.Marshal(r)
	out.Write(append(b, '\n'))
	out.Flush()
}

func dispatch(req rpcReq) rpcResp {
	switch req.Method {
	case "initialize":
		return ok(map[string]any{
			"protocolVersion": protocolVersion,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "fileferry", "version": "1.0"},
		})
	case "tools/list":
		return ok(map[string]any{"tools": tools()})
	case "tools/call":
		return handleCall(req.Params)
	default:
		return rpcResp{Error: &rpcErr{Code: -32601, Message: "method not found: " + req.Method}}
	}
}

func ok(v any) rpcResp {
	b, _ := json.Marshal(v)
	return rpcResp{Result: b}
}

func text(s string) callResult {
	return callResult{Content: []map[string]string{{"type": "text", "text": s}}}
}

func textErr(s string) callResult {
	return callResult{Content: []map[string]string{{"type": "text", "text": s}}, IsError: true}
}

func tools() []toolDef {
	str := func(items ...string) map[string]any { // {"type":"string",...枚举/描述}
		m := map[string]any{"type": "string"}
		if len(items) == 1 {
			m["description"] = items[0]
		}
		return m
	}
	_ = str
	return []toolDef{
		{
			Name: "ff_send",
			Description: "跨服务器按需传输文件（自动选路：直连/中继/交换台）。默认阻塞到完成。" +
				"路径格式 <节点名>:/绝对路径。节点名是部署时固定的稳定名字（agent.yaml 的 node-name），" +
				"重装/重启不变，可安全写进脚本；不确定时先用 ff_status 查（返回 node_id/hostname/addr，" +
				"可按 hostname 或 IP 反查 node_id）。目标写目录（以 / 结尾）会自动补源文件名。",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"src":    map[string]any{"type": "string", "description": "源 node:/绝对路径"},
					"dst":    map[string]any{"type": "string", "description": "目的 node:/绝对路径（目录需在目标机白名单内）"},
					"nowait": map[string]any{"type": "boolean", "description": "true=只入队立即返回（默认等待完成）"},
				},
				"required": []string{"src", "dst"},
			},
		},
		{
			Name: "ff_status",
			Description: "查看舰队：在线节点（node_id 即传输用的节点名）、主机名、CPU/内存、" +
				"探测边（延迟/协议）。传输前用它把主机名或 IP 映射到 node_id。",
			InputSchema: map[string]any{"type": "object", "properties": map[string]any{}},
		},
		{
			Name:        "ff_jobs",
			Description: "查询近期传输任务与状态（done/failed/queued）。",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"id": map[string]any{"type": "string", "description": "可选，精确查某任务"},
				},
			},
		},
		{
			Name:        "ff_token",
			Description: "铸造一次性入网令牌（ff_enroll_…）。需管理员把它加入 controller 配置后，新服务器才能入网。",
			InputSchema: map[string]any{"type": "object", "properties": map[string]any{}},
		},
	}
}

func handleCall(params json.RawMessage) rpcResp {
	var p struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments,omitempty"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return rpcResp{Error: &rpcErr{Code: -32602, Message: "bad params"}}
	}
	var res callResult
	switch p.Name {
	case "ff_status":
		res = toolStatus()
	case "ff_send":
		res = toolSend(p.Arguments)
	case "ff_jobs":
		res = toolJobs(p.Arguments)
	case "ff_token":
		res = toolToken()
	default:
		return rpcResp{Error: &rpcErr{Code: -32602, Message: "unknown tool: " + p.Name}}
	}
	b, _ := json.Marshal(res)
	return rpcResp{Result: b}
}

func toolStatus() callResult {
	hbs, err := client.Status()
	if err != nil {
		return textErr("状态查询失败：" + err.Error())
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "在线节点 %d：\n", len(hbs))
	for _, h := range hbs {
		edges := make([]string, 0, len(h.Edges))
		for _, e := range h.Edges {
			edges = append(edges, fmt.Sprintf("%s(%.0fms,%s)", e.To, e.RTTms, e.Proto))
		}
		fmt.Fprintf(&sb, "- %s %s cpu=%.0f%% mem=%.0f%% 出边:[%s]\n",
			h.NodeID, h.Hostname, h.CPUPct, h.MemPct, strings.Join(edges, " "))
	}
	return text(sb.String())
}

func toolSend(args json.RawMessage) callResult {
	var a struct {
		Src    string `json:"src"`
		Dst    string `json:"dst"`
		NoWait bool   `json:"nowait"`
	}
	if err := json.Unmarshal(args, &a); err != nil || a.Src == "" || a.Dst == "" {
		return textErr("参数需要 src/dst（node:/绝对路径）")
	}
	srcNode, srcPath, ok := splitNodePath(a.Src)
	dstNode, dstPath, ok2 := splitNodePath(a.Dst)
	if !ok || !ok2 {
		return textErr("路径格式应为 node:/abs/path")
	}
	grant, err := client.Send(api.TransferRequest{Src: srcNode, SrcPath: srcPath, Dst: dstNode, DstPath: dstPath})
	if err != nil {
		return textErr("签发失败：" + err.Error())
	}
	via := "直连"
	if grant.Mode == "switch" {
		via = "交换台 " + grant.Hops[1].NodeID + " 对接"
	} else if len(grant.Relays) > 0 {
		via = "经 " + strings.Join(grant.Relays, "->") + " 中继"
	}
	if a.NoWait {
		return text(fmt.Sprintf("已入队 %s（%s -> %s，%s）；源节点 ≤5s 内开始", grant.ID, grant.Src, grant.Dst, via))
	}
	deadline := time.Now().Add(10 * time.Minute)
	for time.Now().Before(deadline) {
		time.Sleep(2 * time.Second)
		jobs, err := client.Jobs(grant.ID)
		if err != nil || len(jobs) == 0 {
			continue
		}
		switch jobs[0].Status {
		case "done":
			return text(fmt.Sprintf("传输完成：%s（%s -> %s，%s）", grant.ID, grant.Src, grant.Dst, via))
		case "failed":
			return textErr(fmt.Sprintf("传输失败：%s（%s -> %s）", grant.ID, grant.Src, grant.Dst))
		}
	}
	return textErr("等待超时（10 分钟）：" + grant.ID)
}

func toolJobs(args json.RawMessage) callResult {
	var a struct {
		ID string `json:"id"`
	}
	json.Unmarshal(args, &a)
	jobs, err := client.Jobs(a.ID)
	if err != nil {
		return textErr("查询失败：" + err.Error())
	}
	if len(jobs) == 0 {
		return text("无匹配任务")
	}
	var sb strings.Builder
	for _, j := range jobs {
		fmt.Fprintf(&sb, "%s %s->%s %s %s\n", j.ID, j.Src, j.Dst, j.Status, time.Unix(j.Updated, 0).Format("01-02 15:04"))
	}
	return text(sb.String())
}

func toolToken() callResult {
	tok, err := ca.NewEnrollToken()
	if err != nil {
		return textErr("生成失败：" + err.Error())
	}
	return text(tok + "\n（加入 controller 配置 enroll-tokens 并重启后生效）")
}

func splitNodePath(s string) (node, path string, ok bool) {
	i := strings.Index(s, ":")
	if i <= 0 || i == len(s)-1 {
		return "", "", false
	}
	return s[:i], s[i+1:], true
}

func newClient(controller, certDir string) (*api.Client, error) {
	if certDir == "" {
		return nil, fmt.Errorf("FF_CERT_DIR 未设置（管理员证书目录）")
	}
	crt, key := filepath.Join(certDir, "admin.crt"), filepath.Join(certDir, "admin.key")
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
		HC: &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			RootCAs:      pool,
			MinVersion:   tls.VersionTLS13,
		}}},
	}, nil
}
