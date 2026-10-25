# fileferry

面向复杂网络的小型按需文件传输系统：十多台服务器，内网↔内网、
内网↔外网，自动跳板路由 + 负载感知调度，全程无两两共享密钥。

> **English** — fileferry is a lightweight, self-hosted, on-demand
> file transfer system for small fleets of servers in complex networks
> (intranet↔intranet, intranet↔internet). Nodes auto-discover each
> other, probe reachability, and transfers are routed over a
> load-aware directed graph with automatic multi-hop relaying —
> no pairwise shared keys, no external services. Single static Go
> binary per node (~8MB), mTLS with a built-in CA, admin-only
> transfer authorization, QUIC with TCP fallback, parallel
> multi-stream transfers, chunked SHA-256 verification and atomic
> writes. Similar in spirit to Syncthing (mesh) or croc (relay),
> but on-demand, permissioned, and load-routed.
>
> **Keywords**: file transfer · file distribution · p2p · peer-to-peer ·
> mesh network · relay · mTLS · QUIC · self-hosted · zero trust ·
> Go · golang

## 架构

- **ff-controller**（1 台，双网卡机器）：内嵌 CA（ed25519 根证书）、
  一次性 enrollment、心跳汇聚、拓扑选链（Dijkstra）、传输授权签发、
  SQLite 任务记录。
- **ff-agent**（每台服务器）：一次性 token 入网换证书（mTLS，24h
  自动续期）、5s 心跳上报负载与可达性、QUIC 数据面监听与传输执行。
- **ffctl**（任意已入网机器）：`send` / `status`。

信任模型：根私钥只在 controller；agent 之间无任何共享密钥；每次
传输由 controller 签发短时效 grant（ed25519），节点本地验签。**角色
权限**：证书分 admin / node 两级——admin（操作者，controller 首次
启动生成 `admin.crt/admin.key`，请拷走保管）才能发起传输与查看
状态；node 只能心跳与执行任务；接收端只接受 controller 签名且发给
自己的 grant，落盘路径由此决定，陌生节点无法投递文件。

路由模型：可达性是**有向图**——每跳只需起点主动连得到终点；
边权 = rtt × (1 + 中继负载/100)，负载超 80% 的节点不做中继；
直连可达时永远直连，不可达时自动串联中继（跳板）；中继节点会
验证"自己确实在这条 controller 签名的路径上"才转发，防止被
滥用为开放代理；传输中断换链续传（M2.5）。

数据面：QUIC（UDP，多路复用、弱网友好），探测发现 UDP 被禁的
链路自动回退 TCP+TLS（约定端口 = 数据面端口 + 1），同一套流协议。
4 MiB 分块，逐块 SHA-256 校验，接收端临时文件 + 原子改名，完成
哨兵 + ACK 握手后才断开连接。

## 目录

```
cmd/controller   控制面
cmd/agent        节点 agent
cmd/ffctl        命令行
internal/ca      内嵌 CA 与 mTLS
internal/api     REST 协议类型与客户端
internal/topology 有向可达图 + 负载加权选链
internal/transfer QUIC 分块传输 / 断点续传 / 中继
```

## 当作 MCP 服务器用（AI agent 原生工具）

`ffmcp` 把传输能力封装为 MCP（Model Context Protocol）工具，ZCode /
Claude Desktop 等 MCP 客户端可直接调用：

```json
{"mcpServers": {"fileferry": {
  "command": "/path/to/ffmcp",
  "env": {"FF_CERT_DIR": "/home/me/ff-admin",
          "FF_CONTROLLER": "https://1.2.3.4:9443"}}}}
```

工具：`ff_send`（阻塞到完成）、`ff_status`（舰队拓扑）、
`ff_jobs`（任务查询）、`ff_token`（铸入网令牌）。

## 部署一台新服务器（三步）

```bash
# 1. 铸造一次性入网令牌（管理员机器）
ff token
# → ff_enroll_xxxx……
# 把它加入 hub 上 ffctl/ctl.yaml 的 enroll-tokens 列表并重启 controller

# 2. 一键部署（在持有最新构建的机器上，ssh 别名直达目标机）
scripts/deploy-agent.sh myserver "ff_enroll_xxxx……"
#   自动：复制二进制 → 写配置（含 allowed-dirs 白名单）→
#   systemd 守护（无 sudo 则 nohup）→ 打印验证命令

# 3. 验证
ff status          # 新节点应在 10 秒内出现并开始探测建边
```

手工部署等价步骤（不想用脚本时）：
1. `scp bin/ff-agent myserver:~/ff/`
2. 目标机写 `~/ff/agent.yaml`：

```yaml
controller: https://<controller地址>:9443
enroll-token: ff_enroll_一次性令牌
data-port: 7800            # 数据面 UDP 端口（TCP 回退默认用 7801）
# tcp-port: 443            # 被墙网络只放行 443 时：把 TCP 数据面固定到 443
data-dir: /home/me/ff
node-name: ff-node-a       # 稳定节点名（缺省用主机名），重装后身份不变
allowed-dirs:              # 落盘白名单：源/目的路径都必须在列表内
  - /home/me/ff
advertise: 1.2.3.4:7800    # 仅公网机/与 controller 同机时需要
```

3. 启动并守护：`nohup ~/ff/ff-agent -config ~/ff/agent.yaml &`，
   或 `sudo systemctl enable --now ff-agent`（单元模板见 systemd/）。

网络要求：出站可达 controller:9443（TCP）；想接收直连/被打洞则放行
入站 7800/udp + 7801/tcp——都不满足时自动走交换台模式，仅出站也能收文件。

## 快速开始（开发机自测）

```bash
make build            # 产出 bin/ff-controller bin/ff-agent bin/ffctl
# 起 controller（会生成一次性 token，改 configs/*.yaml 后直接跑）
./bin/ff-controller -config configs/controller.example.yaml
# 另一个终端起两个 agent（用各自 token / data-dir）
./bin/ff-agent -config /tmp/agent1.yaml
./bin/ff-agent -config /tmp/agent2.yaml
# 发文件
./bin/ffctl -cert-dir /tmp/ff1 -controller https://127.0.0.1:8443 \
    send node-1:/tmp/big.iso node-2:/tmp/
```

## 里程碑

- [x] M0 骨架：仓库 / 构建 / 单测 / 冒烟管道
- [x] M7 交换台模式（DERP 式反向中继）：无常规路径时，两端各自
      **出站**拨向一台选举产生的交换台节点（负载最低、双方可达），
      交换台按 grant 行别配对两条现成连接后双向管道——NAT 不构成
      障碍。真实环境验证：V100 ↔ node5 跨两个校园 NAT 传输 50MB，
      sha256 一致，52s 完成
- [x] M1 信任与观测：✅ CA/enrollment/心跳 ✅ status 展示
      ✅ 探测回填可达边 ✅ 证书自动续期（/v1/renew + 自我重启）
      ✅ SQLite 审计与任务持久化（重启恢复队列）✅ API 限速
      ✅ 落盘路径白名单 ✅ /proc 指标采集（CPU/内存/磁盘，Linux）
- [x] M2 直连传输：✅ grant 签发与两端验签 ✅ 分块传输
      + 逐块校验 + 原子落盘 ✅ 完成回报 ⬜ 限速 ⬜ 断点续传接线
- [ ] M3 复杂网络（核心已落地）：✅ TCP 回退（探测 QUIC 失败自动
      降级，端口约定 +1） ✅ 中继链数据面（grant 逐跳路径 + 验签 +
      双向管道 + 防开放代理） ⬜ 断链换路续传
- [x] M6 NAT 打洞（机制完成，成败取决于对端 NAT 类型）：
      ✅ controller UDP 回声口（验证书链+签名+防重放）✅ 公网映射账本
      ✅ 双端同时发牌（心跳信道携带）✅ 共享 socket（嗅探外壳+Transport，
      监听/拨号/WHOAMI 同源）✅ 对发开洞 + 前缀探测自动建边
      真实环境验证：跨两个校园 NAT 的对等打洞被对称型 NAT 拒绝
      （双方同时行动、地址正确、失败被正确识别并回落中继）
- [x] M4 每任务限速 / 精准负载：✅ /proc 指标采集（CPU/内存/磁盘已进心跳，边权与中继排除
真正生效）⬜ 边权调优 ⬜ 每任务限速 ⬜ 磁盘水位参与调度
- [x] M11 临时取件码：ff share / ff get（含加密路径，端到端实测通过）
- [ ] M5 收尾：✅ systemd 沙箱单元（systemd/）✅ 安全自检脚本
      （scripts/security-check.sh）✅ make audit（govulncheck）
      ⬜ ffctl 管理令牌 ⬜ 部署打包 ⬜ UDP 缓冲调优（sysctl net.core.rmem_max=7500000）
- [x] 安全加固（自渗透驱动）：✅ token 核销持久化 ✅ 管理员证书 10 年
      ✅ 认证清单 manifest（源端签名 文件哈希+大小，唯一块计数判定
      完成 + 全文件验哈希——防重放、防恶意中继篡改内容）
      ✅ 回声口限速 ✅ 密钥离机 + 备份

## 和 scp / rsync 的对应关系

| 想做的事 | scp | fileferry |
|---|---|---|
| 本机 → 远端 | `scp f host:/p` | `ffctl put f node-b:/p` |
| 远端 → 远端 | `scp a:/f b:/p`（走本机中转） | `ffctl send a:/f b:/p`（节点直连/中继，不经本机） |
| 限速 | `-l`（Kbit/s） | `-rate <字节/秒>`（整任务共享配额） |
| 断点续传 | 无 | 自动（进度位图 + `.ffpart`） |
| 免 ssh | 需要 sshd | 不需要，自建 mTLS 数据面 |
| 被墙/只放 443 | 取决于 sshd 端口 | `tcp-port: 443` 即可 |

**实测（本机 loopback，1 个 agent，每轮清空目标，逐次校验 SHA256）**：

| 文件 | fileferry `put` | rsync daemon | 说明 |
|---|---|---|---|
| 1 MB | 0.016 s | 0.007 s | rsync 略快（无 TLS 握手） |
| 10 MB | 0.037 s | 0.025 s | rsync 略快 |
| 100 MB | 0.212 s | 0.220 s | 持平 |

loopback 没有网络 RTT，fileferry 的 mTLS 握手与 controller 往返成了固定开销，
所以小文件不占优。它换来的是：不需要 sshd、能穿透只放 443 的网络、断点续传、
多流并行（高 RTT 链路上差距会拉大）。

### 断点续传的实测证据

```
# 20MB @ 限速 2MB/s，4 秒时 kill -9 接收端
中断时进度: 4/5 块已收（临时文件 16777216 字节）
# 重启接收端后重发
完成：（4194304 字节，2.01s，2 MB/s）   ← 只补了缺失的 1 块
SHA256 一致
```

## 网络受限 / 被墙时怎么用

数据面有两条腿：**QUIC(UDP)** 与 **TCP**。探测时会同时试两条，谁通用谁，
所以只要 TCP 能出去就能传。但国内网络里 UDP 常被干扰、非标准端口常被封，
这时按下面两条改：

```yaml
# agent.yaml
data-port: 7800     # UDP 仍绑着，不通就自动跳过
tcp-port: 443       # TCP 数据面固定到 443（默认是 data-port+1）
```

- `tcp-port` 由**每个节点自己上报**，通过心跳同步给全网（`PeerInfo.TCPPort`
  / `Hop.TCPPort`），所以各节点端口可以不同，也可以相同。
- 端口不写死：`ffctl status` 能看到每台节点的 `tcp_port`。
- 实测（同机 loopback，UDP 被指向死端口、只剩 TCP）：

| 文件 | 耗时 | 吞吐 |
|---|---|---|
| 100 KB | 0.12 s | — |
| 4 MB | 0.12 s | 34 MB/s |
| 200 MB | 0.31 s | 647 MB/s |

三条命令就能验证：

```bash
ffctl status                      # 看边是不是 tcp、各节点 tcp_port
ffctl send a:/tmp/big b:/tmp/     # 传
ffctl jobs                        # 查状态
```

### 不会被 fail2ban / 防火墙当成扫描

早期版本有两处会导致**整个 IP 被封（连带 SSH 一起断）**：

1. 打洞时对同一主机的 13 个连续端口发包（实测 8 秒 13 个端口）——这就是
   水平端口扫描的特征。现在已知对端公网映射时**只打 1 个端口**，只有地址
   是猜测时才退化为 3 个候选。
2. 探测无退避：对端宕机时每 30 秒无差别重试所有 peer，且每次都记日志。
   现在失败后指数退避（30s → 1m → 2m → 4m → 5m 封顶），日志只在状态
   变化时打一行。

回归测试里对这两点有断言（`TestRegressSendOpenersExact`、
`TestRegressProbeBackoff`）。

## 路径与身份约定

- **目标写成目录**：`node-2:/data/` 或已存在的目录，接收端自动补源文件名；
  显式写文件名则原样使用。
- **落盘白名单** `allowed-dirs`：按路径分量比较并解析符号链接，`/data`
  不会放行 `/data-evil`；`inbox:` 取件标记只允许单层文件名，拒绝 `..`。
- **节点身份**：`node-name` 首次入网占用后固定，重装/重启/换机都不漂移，
  可以当常量写进脚本和 prompt。字符集基本不限——实测 `数据库-主`、
  `web.prod-01` 都能直接用（X.509 CN 能原样保存 UTF-8）。唯一禁止的是
  `:` `/` 和控制字符：`:` 会与 `node:/path` 语法冲突（`a:b:/x` 会被
  静默解析成 node=`a`），所以显式配置非法名字时 agent **启动即失败**，
  不会静默改名。名字大小写不敏感去重（`Node-1` 与 `node-1` 视为同名）。
  未配置时回退主机名；重名或非法才退回自增 `node-N`。

  类比 ssh：`node-name` 相当于 `~/.ssh/config` 里的 `Host db1`，
  而 `ff_status` 里的 `hostname`/`addr` 相当于 `HostName 10.0.0.5`。
  scp/rsync 也从不问对端「你叫什么」——名字是操作者给的稳定别名，
  fileferry 现在同理。
- **撤销**：`ffctl revoke` 后名单随心跳下发，数据面立即拒收/拒发该节点，
  不只是控制面拦截。

## 协议

[GPL-3.0](LICENSE) · Copyright (C) 2026 fileferry 贡献者

