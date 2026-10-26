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

## 给 AI agent 用：token 成本与往返次数

先说结论：**MCP schema 不是主要成本，往返次数才是。**

实测（4 个工具，中文描述）：

| 项 | token | 什么时候付 |
|---|---|---|
| tools/list schema | **297** | 每次对话一次 |
| `ff_status` 输出 | ~35 | 每次调用 |
| `ffctl put` 输出 | ~48 | 每次调用 |
| `ffctl -json put` 输出 | ~45（纯 JSON，好解析） | 每次调用 |

一次工具调用的**结果**很便宜；但每多一轮往返，整段对话都要重新输入一遍。
所以优化的目标是**别让 agent 多绕一圈**：

### 1. 直接写主机名或 IP，不用先查名字

```bash
ffctl put ./x.bin 10.0.0.5:/data/x.bin     # IP
ffctl put ./x.bin web-01:/data/x.bin       # 主机名
ffctl put ./x.bin beta:/data/x.bin         # node_id（旧写法，仍然可用）
```

服务端按 `node_id → 主机名 → IP` 顺序解析（只考虑在线节点）。

### 2. 报错自带可选项，改一个参数就能重试

```
dst "nosuch" 不存在；在线节点：alpha, beta（也可用主机名或 IP）
dst "web-01" 有多个匹配，请指定其中之一：alpha, beta
no path alpha -> beta（alpha 出边: ; beta 出边: gamma）
```

对比一下「node not found」——agent 只能再调一次 status 才知道有哪些节点。

> 歧义时不猜。同一台机器跑多个 agent 时（主机名/IP 相同）会要求显式指定，
> 因为传错文件比报错更难排查。

### 3. 机器可读输出

```bash
ffctl -json put ./x.bin beta:/data/x.bin
{"bytes":1048624,"dst":"/data/x.bin","mbps":68.4,"ok":true,"secs":0.015,"sha256":"2666…"}
```

单行、短键、无中文句子——不用正则解析，也省 token。

### 4. schema 本身也压过一轮

旧版 4 个工具 ≈ 420 token，现在 ≈ 297（-29%）。删掉的是"重装/重启不变"
这类安抚性说明——那属于文档，不该出现在每次对话都要读的接口描述里。

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
# tcp-advertise-port: 443  # 自己监听 tcp-port，但对外公布这个端口（端口转发/代理后）
# bind-addr: 10.0.0.5      # 多网卡主机只绑某个内网口（默认所有接口）
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
- [x] M4 精准负载 / 限速：✅ /proc 指标采集 ✅ 每任务限速 ✅ 磁盘水位参与调度
（LoadPct 取 CPU/内存/磁盘三维最高值，余量 <2GiB 开始告警，超过 80% 不作中继）
✅ 边权调优（实测吞吐经 EMA 平滑后真正参与选链，不再只看 rtt）
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
| 远端 → 本机 | `scp host:/p ./local` | `ffctl get node-b:/p ./local` |
| 远端 → 远端 | `scp a:/f b:/p`（走本机中转） | `ffctl send a:/f b:/p`（节点直连/中继，不经本机） |
| 限速 | `-l`（Kbit/s） | `-rate <字节/秒>`（整任务共享配额） |
| 断点续传 | 无 | 自动（进度位图 + `.ffpart`） |
| 内容校验 | 无（只有传输校验和） | 逐块 SHA256 + 全文件摘要（由发送方签名） |
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

### 真实 RTT 下的实测（不是 loopback）

loopback 没有传播时延，测不出长肥管道上的问题。用双向延迟代理注入 RTT 后
（`put` 100MB，每轮清空目标、逐次校验 SHA256）：

| RTT | 流数=1 | 流数=2 | 流数=4 | 流数=8 |
|---|---|---|---|---|
| 40 ms | 1.15 s（87 MB/s） | 1.01 s（99 MB/s） | 1.04 s | 1.04 s |
| 无延迟 | 0.21 s（476 MB/s） | — | — | — |

结论要直说：**40ms RTT 下单流就已经跑到 87MB/s，多流只提升约 14%**
（QUIC 的流控窗口足够大，所以"多流叠配额"的收益不大）。它的价值更多
体现在高丢包/限速/单流被中间设备干扰的场景，而不是干净链路的带宽。

> 说明：同一 RTT 下 **rsync 的对照数没能拿到**。我写的 TCP 延迟代理会让
> rsync 的分块协议卡死（120s 超时），这是代理缺陷而非 rsync 的问题，
> 所以不引用该数据。可比的只有 loopback 那组（见上）。

### 丢包环境下的实测：**数据不可信，我没有可靠结论**

之前这里贴过一张「丢包 → QUIC 吞吐塌陷 60~150 倍」的表。**那张表作废**，
原因有两层，都是测量方法的问题：

1. **TCP 那一列从来不可能成立**：代理在应用层删字节。对 UDP 是真实丢包，
   对 TCP 直接破坏可靠性契约——删掉的字节补不回来，接收端只看到截断流。
   把 fileferry 自己的 TCP 路径接上去，1MB 跑了 **91.23s** 才失败，正好等于
   发送端 90s 写超时。这是"被截断憋死"，不是"丢包下跑得慢"。
2. **UDP 那一列同样不可信**：当前代理在 30% 丢包设定下，200 个突发 UDP 包
   只实收 **1 个**；而对 paced 流量又表现正常。结果是把吞吐夹在 ~3MB/s 且
   **与设定丢包率完全无关**——实测 0%/2%/5%/10%/15% 五档都是 5.2s（3.07MB/s）。
   那是代理上限，不是 QUIC 的行为。排除代理后（连接窗口 16MB @ RTT 40ms
   → 理论上限 400MB/s）可确认瓶颈不在 fileferry。

结论：**「QUIC 在丢包下塌陷」在方向上与 Cubic 的基于丢包拥塞控制一致，
但我没有可信的实测倍数，也没有任何 TCP 的对照数据。

要拿可信数据需要能丢 **IP 包**的环境（root + pfctl / dummynet，或远端机器
用 `tc netem`）。本机做不到，我不再拿本地代理的丢包结论说话。

作为参考，**只有延迟的测量是可信的**（延迟线经 echo 验证：设 20ms 单向，
实测 45ms 往返）：

| RTT | 100MB 单流 |
|---|---|
| 无延迟 | 0.21s（476 MB/s） |
| 40 ms | 1.15s（87 MB/s） |

### 慢链路上 `ffctl` 会做什么（以及做不到什么）

**会做的**：

- 进度实时显示（按 64KB 写入粒度计数，不满块跳变）
- 发完后明确显示「等待对端校验确认…（已等 12s，链路可能较慢）」——
  这段时间可能很长（见下），不标出来和卡死无法区分
- 连接完全不通时，6 秒后自动换协议重试（断点续传接上）

**做不到的（实测确认，别指望更多）**：

QUIC 流控窗口是 16MB，发送端 `Write` 只要数据进了 quic-go 缓冲就返回，
**不反映链路速度**：

- 文件 ≤ 16MB：瞬间塞满窗口、进度直冲 100%，之后全是等 ACK。
  此时检测不到"活着但慢"。实测 16MB 经 300KB/s 链路跑了 **53.9s**，
  自动切换**没有触发**（这是设计限制，不是 bug）。
- 文件 > 16MB：窗口填满后 `Write` 开始阻塞，进度才跟随链路，低速率可检出。

所以自动换协议主要防「假活」（连接建立但推不动），不是万能慢速检测。
已知链路差时请直接 `-proto tcp`。

### 慢链路收尾（P0，已修）

接收端为了写 `HAVE` 行设了 5 秒写超时，**之后没有清掉**。该超时作用于
连接上所有后续写，包括末尾的 `ACK`——于是任何耗时超过 5 秒的传输都会在
收尾时 `i/o timeout`，对端看到 EOF，**文件其实已完整落盘却报失败**并重试
3 次（实测 5MB@1MB/s：185 秒后失败）。

loopback 上一切都 <5 秒，所以这个 bug 长期不可见；一旦上真机、跨地域或
限速，必然命中。现在 HAVE 之后立即清零，ACK 前单独给 30 秒。
回归测试用真实 TCP + 手工"慢对端"（HAVE 后停 6 秒再发数据），
两处修复任一缺失都会失败。

### put / get 的实现要点

- `put`：本机作 TLS 客户端直连目标节点，授权里 `Src` = 调用者管理员 CN。
- `get`：本机作 TLS **服务器**，由源节点回连推数据。管理员证书只带
  `ClientAuth`，无法充当服务端，所以 controller 按需签发一张
  **一次性、短时效、带 ServerAuth** 的传输端点证书（CN 带随机后缀）。
- 两条方向都不经过 controller 传数据，也都受目标节点的 `allowed-dirs`
  白名单约束。
- `get` 默认**不**用节点索引里的摘要钉死内容（`-pin` 可强制）。原因：
  索引是定期上报的，文件在两次上报之间被改动，钉死会让合法传输被拒
  ——实测踩到过一次（agent 启动时索引了同名旧文件）。
- 源端失败（文件不存在、白名单拒绝）时 ffctl 会在约 2 秒内返回，
  不会干等到超时（靠轮询 `/v1/jobs`）。

实测（本机 loopback，一个 agent）：

```
get 8MB          0.67s   ✅ SHA256 一致
get 到目录       自动补源文件名 ✅
get 源不存在     2.03s 内失败（不是等 30 分钟）
get 白名单外     2.03s 内失败
```

### 传输中能看到进度（之前没有）

大文件在被墙链路上可能跑几分钟，之前 `ffctl put` 全程静默——用户无法
区分"在慢慢传"和"已经卡死"。我自己实测时就遇到过 91 秒静默卡顿、只能
靠猜。现在（stderr 是终端时）：

```
  42.3%  8.5 MB / 20.0 MB  5.0 MB/s
  已发完，等待对端校验确认…（20.0 MB）
```

第二行是有意加的：数据发完后对端还要落盘、算全文件哈希再回 ACK，这段
可能持续数秒。不标出来的话"100% 却还要等"看起来像卡死。

另外 `ffctl` 默认不再打印内部 `[tl]` 时序日志（scp 也不会这么吵），
排查时设 `FF_DEBUG=1` 打开。

### 增量传输：rsync 风格滚动校验

源文件更新后同步到**同一个目标路径**时走增量。实现参考 rsync 的
`checksum.c`/`match.c`：接收端把已有文件的**分块弱校验（可滚动）+ 强校验**
发过去，发送端用一个滑动窗口在新文件上逐字节推进，命中即产出一条
「从你本地旧文件拷贝 X 到 Y」的指令，未命中的部分作为字面量传输。

弱校验与 rsync 一致：`a=Σx_i`、`b=Σ(n-i)·x_i`，滑动时
`a'=a-x_out+x_in`、`b'=b-n·x_out+a'`（均 mod 2^16），强校验用 SHA-256 截断。
被复用区域一次跳过整块，所以**未改动的部分不产生逐字节开销**。

实测（100MB，块大小自适应 16KB，双向计数，两台都经同一计数代理）：

| 场景 | rsync 上行 | fileferry 上行 | 含协商的总过网 |
|---|---|---|---|
| 首次全量 | 105.5 MB | 105.0 MB | 105.5 / 105.1 MB |
| 末尾追加 1MB | 1.51 MB | **1.07 MB** | 1.57 / **1.18 MB** |
| **原地改 4KB** | 470 KB | **34 KB** | 535 / **146 KB** |
| 中间插入 1 字节 | 499 KB | **461 KB** | 564 / 572 KB |
| 全新内容 | 105.4 MB | 105.0 MB | — |

全部哈希一致。**四个增量场景里两个明显更快、一个基本持平。**

#### 已知的边界（不粉饰）

1. **每个 4MB 分块两端各有最多一个块大小（16KB）无法匹配**：分块是独立的
   编码单元，错位时块内首尾的残段凑不出完整的校验块。rsync 的流没有这种
   边界，所以它只浪费一次。这解释了为什么「插入 1 字节」我们是 461KB 而不是
   几 KB。彻底解决要把滚动扫描改成跨分块连续（然后按边界切分指令），
   是下一步。
2. **签名协商量随文件增大**：块数上限 8192，100MB ≈ 77KB 签名。只由**第一条
   流**携带、其余流用共享缓存，否则 4 条流各发一遍就是 410KB（实测过，
   那样总过网会反超 rsync）。
3. **加密传输（share/get）禁用分段帧**：分段帧里的字面量是明文，照发会绕过
   端到端加密。加密路径仍可用整块复用（引用帧），只是没有细粒度增量。
4. 弱校验会碰撞，所以必须用强校验确认；命中后仍以分块 SHA-256 兜底。

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

