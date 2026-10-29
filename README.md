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
哨兵 + ACK 握手后才断开连接。**目录递归**：`ffctl send -r` 整树
复制，相对路径参与清单签名（防篡改落盘位置），权限位与修改时间
保留（对齐 `scp -p` / `rsync -a` 基本语义）；每文件独立清单 +
HKDF 派生文件密钥（加密时），QUIC 连接池化省逐文件握手。
**限速**：`ffctl send -limit <MB/s>` 整条传输令牌桶配额（多流共享）。
落盘完整性：逐块 + 全文件 SHA-256、原子改名；`sync-write: true`
（agent 配置）可加开 fsync 获得掉电级持久性（默认关，对齐 rsync/cp
的语义，小文件吞吐高一个量级）。

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
data-port: 7800            # 数据面 UDP 端口（TCP 回退自动用 7801）
data-dir: /home/me/ff
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
# 整个目录递归（保留权限/修改时间），整条传输限速 20MB/s
./bin/ffctl -cert-dir /tmp/ff1 -controller https://127.0.0.1:8443 \
    send -r -limit 20 node-1:/tmp/dataset node-2:/data/
# 增量同步：目的端已有近似文件时只传差异（rsync 式 delta）
./bin/ffctl -cert-dir /tmp/ff1 -controller https://127.0.0.1:8443 \
    send -delta node-1:/tmp/app-v2.tar node-2:/data/app.tar
```

## 里程碑

- [x] M0 骨架：仓库 / 构建 / 单测 / 冒烟管道
- [x] M7 交换台模式（DERP 式反向中继）：无常规路径时，两端各自
      **出站**拨向一台选举产生的交换台节点（负载最低、双方可达），
      交换台按 grant 行别配对两条现成连接后双向管道——NAT 不构成
      障碍。真实环境验证：V100 ↔ node5 跨两个校园 NAT 传输 50MB，
      sha256 一致，52s 完成
- [ ] M1 信任与观测（大部分完成）：✅ CA/enrollment/心跳 ✅ status 展示
      ✅ 探测回填可达边 ✅ 证书自动续期（/v1/renew + 自我重启）
      ✅ SQLite 审计与任务持久化（重启恢复队列）✅ API 限速
      ✅ 落盘路径白名单 ⬜ /proc 指标采集
- [x] M2 直连传输（基础可用）：✅ grant 签发与两端验签 ✅ 分块传输
      + 逐块校验 + 原子落盘 ✅ 完成回报 ✅ 限速（-limit，令牌桶多流共享）
      ✅ 断点续传接线（autoRetry + HAVE 位图）
- [x] M2.7 目录递归：send -r 整树复制，相对路径入清单签名，权限/
      mtime 保留，QUIC 连接池化，加密模式每文件派生密钥（防跨文件
      nonce 重用），交换台模式 FFEND 哨兵收尾
- [x] M2.8 增量同步（rsync 式 delta transfer）：`ffctl send -delta`
      对目的端已有近似文件只传差异——接收端把已有文件逐块 (adler32
      滚动和, SHA-256 强和) 清单经 BASE 行回给发送端，发送端滚动窗口
      任意偏移匹配，只发字面量/COPY 指令；重建结果仍过整文件 SHA-256
      （delta 不引入新信任假设：基准损坏自动退化为全量自愈）。5MB
      文件实测仅传 ~1.1MB 字面量；加密模式配方序号作 nonce 计数器
- [ ] M3 复杂网络（核心已落地）：✅ TCP 回退（探测 QUIC 失败自动
      降级，端口约定 +1） ✅ 中继链数据面（grant 逐跳路径 + 验签 +
      双向管道 + 防开放代理） ⬜ 断链换路续传
- [x] M6 NAT 打洞（机制完成，成败取决于对端 NAT 类型）：
      ✅ controller UDP 回声口（验证书链+签名+防重放）✅ 公网映射账本
      ✅ 双端同时发牌（心跳信道携带）✅ 共享 socket（嗅探外壳+Transport，
      监听/拨号/WHOAMI 同源）✅ 对发开洞 + 前缀探测自动建边
      真实环境验证：跨两个校园 NAT 的对等打洞被对称型 NAT 拒绝
      （双方同时行动、地址正确、失败被正确识别并回落中继）
- [ ] M4 精准负载：✅ 每任务限速（-limit MB/s） ⬜ 边权调优 ⬜ 磁盘水位参与调度
- [ ] M5 收尾：✅ systemd 沙箱单元（systemd/）✅ 安全自检脚本
      （scripts/security-check.sh）✅ make audit（govulncheck）
      ⬜ ffctl 管理令牌 ⬜ 部署打包 ⬜ UDP 缓冲调优（sysctl net.core.rmem_max=7500000）
- [x] 稳定性打磨（本轮）：✅ agent 启动竞态修复（whoamiLoop 在数据面
      socket 就绪前启动 → nil panic 崩进程；改为就绪后启动 + 判空兜底）
      ✅ enroll 指数退避重试（controller 未起不再 crash-loop）
      ✅ 空文件死锁修复（0 块文件哨兵即完成，旧版单文件路径同样受累）
      ✅ 接收端并发 map 崩溃修复（saveProgress 无锁迭代 got 表，
      多流并行收块时 runtime fatal 进程死亡——压测 1GB 实锤）
      ✅ 心跳周期默认 1s→500ms + ffctl 完成轮询 150ms（grant 投递与
      完成感知延迟持续压缩）
- [x] 批量文件单流打包：目录模式同一流上依次发多文件段（各段独立
      清单/ACK），FFEND 哨兵收尾——每文件 4 RTT → 2 RTT；TCP 回退
      与交换台模式免逐文件 TLS 握手/配对，WAN 小文件吞吐提升一倍
- [x] 对标基准（scripts/bench-local.sh，macOS 回环；scp 走用户态
      sshd 对照通道）：256MB 单文件 ff 1.2s / scp 0.4s / cp 0.1s；
      400MB 目录 ff 0.9s / scp 0.6s / rsync 1.7s（ff 胜 rsync）；
      500×16KB ff 0.8s / scp 0.2s（差距=协调层固定延迟 ~0.5s，
      真实舰队场景无此对照意义——scp/rsync 需两两配钥，ff 不需要）
- [x] 强化压测（scripts/stress-local.sh，镜像真实压测三阶段 + 中断
      续传）：5×100MB 并发 5/5（聚合 55MB/s）、1GB 102MB/s、
      20×5MB 风暴 20/20、kill -9 源 agent 后 autoRetry+HAVE 位图
      1 轮内续传恢复且哈希一致；race 全绿
      （注：真实舰队压测 scripts/stress-test.sh 因 222.186.10.53 /
      v100_222 不可达未能复跑，环境恢复后可直接执行）
- [x] 安全加固（自渗透驱动）：✅ token 核销持久化 ✅ 管理员证书 10 年
      ✅ 认证清单 manifest（源端签名 文件哈希+大小，唯一块计数判定
      完成 + 全文件验哈希——防重放、防恶意中继篡改内容）
      ✅ 回声口限速 ✅ 密钥离机 + 备份

## 协议

[GPL-3.0](LICENSE) · Copyright (C) 2026 fileferry 贡献者

