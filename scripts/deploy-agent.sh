#!/usr/bin/env bash
# 一键把 ff-agent 部署到一台新服务器并接入舰队。
#
# 用法：deploy-agent.sh <ssh别名> <enroll-token> [data-dir]
#   ssh别名     ~/.ssh/config 里能直达的目标机（含用户/密钥）
#   enroll-token 一 ffctl token 铸造、已加入 controller 配置的令牌
#   data-dir    可选，默认 ~/ff
#
# 前置：本机 ./bin/ff-agent 是最新构建；目标机能出站访问 controller。
# 行为：复制二进制 → 生成配置（含 allowed-dirs）→ 有 sudo 装 systemd
# 服务，否则 nohup 拉起 → 打印验证命令。
set -euo pipefail

HOST="${1:?用法: deploy-agent.sh <ssh别名> <enroll-token> [data-dir]}"
TOKEN="${2:?缺少 enroll-token（先跑 ffctl token 并加入 controller 配置）}"
DATADIR="${3:-\$HOME/ff}"
CONTROLLER="${FF_CONTROLLER:-https://222.186.10.53:9443}"

echo "==> 传输二进制到 $HOST"
# 先停旧进程（二进制正被运行时无法覆盖）
ssh "$HOST" "pgrep -x ff-agent >/dev/null && (systemctl is-active --quiet ff-agent 2>/dev/null && sudo -n systemctl stop ff-agent || pkill -x ff-agent) || true"
ssh "$HOST" "mkdir -p ~/ff"
scp -q bin/ff-agent "$HOST":~/ff/ff-agent

echo "==> 写入配置"
ssh "$HOST" "cat > ~/ff/agent.yaml <<EOF
controller: $CONTROLLER
enroll-token: $TOKEN
data-port: 7800
data-dir: $DATADIR
allowed-dirs:
  - $DATADIR
EOF
chmod +x ~/ff/ff-agent"

echo "==> 启动（优先 systemd 守护，无 sudo 则 nohup）"
if ssh "$HOST" "sudo -n true 2>/dev/null"; then
  ssh "$HOST" "sudo -n tee /etc/systemd/system/ff-agent.service >/dev/null <<EOF
[Unit]
Description=fileferry agent
After=network-online.target

[Service]
User=\$USER
ExecStart=\$HOME/ff/ff-agent -config \$HOME/ff/agent.yaml
Restart=always
RestartSec=3
NoNewPrivileges=true
ProtectSystem=full
PrivateTmp=true
ReadWritePaths=$DATADIR

[Install]
WantedBy=multi-user.target
EOF
sudo -n systemctl daemon-reload
sudo -n systemctl enable --now ff-agent"
  echo "==> systemd 服务 ff-agent 已启用"
else
  ssh "$HOST" "nohup ~/ff/ff-agent -config ~/ff/agent.yaml > ~/ff/agent.log 2>&1 &
sleep 2; pgrep -x ff-agent >/dev/null && echo 'nohup 已拉起（注意：机器重启后需手动拉起）'"
fi

echo ""
echo "完成。验证：ssh $HOST tail ~/ff/agent.log   # 应出现 \"agent node-N 就绪\""
echo "      全图：ff status（管理员机器）"
