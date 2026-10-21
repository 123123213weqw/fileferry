# fileferry

面向复杂网络的小型按需文件传输系统：十多台服务器，内网↔内网、
内网↔外网，自动跳板路由 + 负载感知调度，全程无两两共享密钥。

## 架构

- **ff-controller**（1 台，双网卡机器）：内嵌 CA（ed25519 根证书）、
  一次性 enrollment、心跳汇聚、拓扑选链（Dijkstra）、传输授权签发、
  SQLite 任务记录。
- **ff-agent**（每台服务器）：一次性 token 入网换证书（mTLS，24h
  自动续期）、5s 心跳上报负载与可达性、QUIC 数据面监听与传输执行。
- **ffctl**（任意已入网机器）：`send` / `status`。

信任模型：根私钥只在 controller；agent 之间无任何共享密钥；每次
传输由 controller 签发短时效 grant（ed25519），节点本地验签。

路由模型：可达性是**有向图**——每跳只需起点主动连得到终点；
边权 = rtt × (1 + 中继负载/100)，负载超 80% 的节点不做中继；
不可达时自动选出中继链（自动跳板）；传输中断换链续传，不重传。

数据面：QUIC（UDP，多路复用、弱网友好），探测到 UDP 被禁时逐
链路回退 TCP+TLS（M3）。4 MiB 分块，逐块 SHA-256 校验，断点
续传清单 `.ffpart`。

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

- [ ] M1 信任与观测：CA/enrollment/心跳落地，/proc 指标采集，
      status 展示，证书自动续期，SQLite 任务表
- [ ] M2 直连传输：grant 通知与验签、限速、原子落盘、断点续传
- [ ] M3 复杂网络：探测循环、TCP 回退、中继链数据面、换链续传
- [ ] M4 精准负载：边权调优、每任务限速、磁盘水位参与调度
- [ ] M5 收尾：ffctl 管理令牌、systemd 单元、部署打包

## 协议

[GPL-3.0](LICENSE) · Copyright (C) 2026 fileferry 贡献者

