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
- [ ] M1 信任与观测（进行中）：✅ CA/enrollment/心跳 ✅ status 展示
      ✅ 探测回填可达边 ⬜ /proc 指标采集 ⬜ 证书自动续期 ⬜ SQLite 持久化
- [ ] M2 直连传输（基础可用）：✅ grant 签发与两端验签 ✅ 分块传输
      + 逐块校验 + 原子落盘 ✅ 完成回报 ⬜ 限速 ⬜ 断点续传接线
- [ ] M3 复杂网络（核心已落地）：✅ TCP 回退（探测 QUIC 失败自动
      降级，端口约定 +1） ✅ 中继链数据面（grant 逐跳路径 + 验签 +
      双向管道 + 防开放代理） ⬜ 断链换路续传
- [ ] M4 精准负载：⬜ 边权调优 ⬜ 每任务限速 ⬜ 磁盘水位参与调度
- [ ] M5 收尾：⬜ ffctl 管理令牌 ⬜ systemd 单元 ⬜ 部署打包
      ⬜ UDP 缓冲调优（sysctl net.core.rmem_max=7500000）

## 协议

[GPL-3.0](LICENSE) · Copyright (C) 2026 fileferry 贡献者

