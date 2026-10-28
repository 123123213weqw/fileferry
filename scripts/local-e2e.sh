#!/usr/bin/env bash
# 本地回环 e2e：controller + 2 agent + 传输冒烟。
# 用法：scripts/local-e2e.sh [保持运行秒数]  （默认跑完冒烟即退出）
set -euo pipefail
cd "$(dirname "$0")/.."

ROOT=$(mktemp -d /tmp/fileferry-e2e.XXXXXX)
BIN=$PWD/bin
PORT_BASE=${PORT_BASE:-18400}

mkdir -p $ROOT/cfg $ROOT/node1/ff $ROOT/node2/ff $ROOT/scratch
cat > $ROOT/cfg/controller.yaml <<EOF
listen: 127.0.0.1:$PORT_BASE
data-dir: $ROOT/ctl
enroll-tokens:
  - ff_enroll_tok1
  - ff_enroll_tok2
EOF
cat > $ROOT/cfg/agent1.yaml <<EOF
controller: https://127.0.0.1:$PORT_BASE
enroll-token: ff_enroll_tok1
data-port: $((PORT_BASE+10))
data-dir: $ROOT/node1/ff
allowed-dirs:
  - $ROOT/node1
advertise: 127.0.0.1:$((PORT_BASE+10))
EOF
cat > $ROOT/cfg/agent2.yaml <<EOF
controller: https://127.0.0.1:$PORT_BASE
enroll-token: ff_enroll_tok2
data-port: $((PORT_BASE+20))
data-dir: $ROOT/node2/ff
allowed-dirs:
  - $ROOT/node2
advertise: 127.0.0.1:$((PORT_BASE+20))
EOF

cleanup() {
  [ -n "${CTL_PID:-}" ] && kill $CTL_PID 2>/dev/null || true
  [ -n "${A1_PID:-}" ] && kill $A1_PID 2>/dev/null || true
  [ -n "${A2_PID:-}" ] && kill $A2_PID 2>/dev/null || true
  wait 2>/dev/null || true
}
trap cleanup EXIT

$BIN/ff-controller -config $ROOT/cfg/controller.yaml >$ROOT/ctl.log 2>&1 &
CTL_PID=$!
$BIN/ff-agent -config $ROOT/cfg/agent1.yaml >$ROOT/a1.log 2>&1 &
A1_PID=$!
$BIN/ff-agent -config $ROOT/cfg/agent2.yaml >$ROOT/a2.log 2>&1 &
A2_PID=$!

# 等 node-1/node-2 入网（status 仅 admin 可查：用 controller 生成的管理员证书）
mkdir -p $ROOT/admin
for i in $(seq 1 30); do
  if [ -f $ROOT/ctl/admin.crt ] && [ -f $ROOT/ctl/ca/ca.crt ]; then break; fi
  sleep 1
done
cp $ROOT/ctl/admin.crt $ROOT/ctl/admin.key $ROOT/admin/ 2>/dev/null
cp $ROOT/ctl/ca/ca.crt $ROOT/admin/ca.crt 2>/dev/null
ok=""
for i in $(seq 1 30); do
  if $BIN/ffctl -cert-dir $ROOT/admin -controller https://127.0.0.1:$PORT_BASE status 2>/dev/null | grep -q node-2; then ok=1; break; fi
  sleep 1
done
[ -n "$ok" ] || { echo "节点未入网"; tail -5 $ROOT/*.log; exit 1; }
echo "两节点已入网（$ROOT）"

# controller 按**到达顺序**分配 node-N（与 token 无关）：从各 agent
# 证书 CN 读出实际 ID，避免"send node-1 打到另一台"的顺序竞态
ID1=$(openssl x509 -in $ROOT/node1/ff/node.crt -noout -subject | sed -n 's/.*CN *= *\(node-[0-9]*\).*/\1/p')
ID2=$(openssl x509 -in $ROOT/node2/ff/node.crt -noout -subject | sed -n 's/.*CN *= *\(node-[0-9]*\).*/\1/p')
[ -n "$ID1" ] && [ -n "$ID2" ] && [ "$ID1" != "$ID2" ] || { echo "无法确定节点 ID（$ID1 / $ID2）"; exit 1; }
echo "节点映射：node1目录=$ID1 node2目录=$ID2"

FFCTL() { $BIN/ffctl -cert-dir $ROOT/admin -controller https://127.0.0.1:$PORT_BASE "$@"; }

# 等待探测建边（可达性是有向图：必须等到源 node-1 对 node-2 的出边）
edge=""
for i in $(seq 1 45); do
  OUT=$($BIN/ffctl -cert-dir $ROOT/admin -controller https://127.0.0.1:$PORT_BASE status 2>/dev/null || true)
  echo "$OUT" | grep -q "$ID1 .*出边=\[$ID2" && { edge=1; break; }
  sleep 2
done
[ -n "$edge" ] && echo "探测边已建立" || echo "警告：45s 内未见探测边（继续尝试 send）"

# 冒烟：16MB 文件 node-1 -> node-2（边传播存在秒级窗口，422 则退避重试）
dd if=/dev/urandom of=$ROOT/node1/payload.bin bs=1m count=16 2>/dev/null
send_ok=""
for i in $(seq 1 12); do
  if FFCTL send $ID1:$ROOT/node1/payload.bin $ID2:$ROOT/node2/recv.bin; then send_ok=1; break; fi
  sleep 5
done
[ -n "$send_ok" ] || { echo "send 持续失败"; tail -20 $ROOT/*.log; exit 1; }
S1=$(shasum -a 256 $ROOT/node1/payload.bin | cut -d' ' -f1)
S2=$(shasum -a 256 $ROOT/node2/recv.bin | cut -d' ' -f1)
[ "$S1" = "$S2" ] && echo "冒烟 OK" || { echo "哈希不一致"; exit 1; }

# 目录递归冒烟：嵌套子目录 + 不同权限/mtime，逐文件哈希与属性校验
mkdir -p $ROOT/node1/tree/sub/deep
echo "top content" > $ROOT/node1/tree/top.txt
dd if=/dev/urandom of=$ROOT/node1/tree/mid.bin bs=1m count=3 2>/dev/null
dd if=/dev/urandom of=$ROOT/node1/tree/sub/deep/nest.bin bs=64k count=5 2>/dev/null
chmod 600 $ROOT/node1/tree/mid.bin
touch -t 202601010304 $ROOT/node1/tree/top.txt
FFCTL send -r $ID1:$ROOT/node1/tree $ID2:$ROOT/node2/tree-copy
DIR_OK=1
for f in top.txt mid.bin sub/deep/nest.bin; do
  S1=$(shasum -a 256 $ROOT/node1/tree/$f | cut -d' ' -f1)
  S2=$(shasum -a 256 $ROOT/node2/tree-copy/$f 2>/dev/null | cut -d' ' -f1)
  [ "$S1" = "$S2" ] || { echo "目录冒烟哈希不一致：$f"; DIR_OK=0; }
done
[ "$DIR_OK" = 1 ] && {
  P1=$(stat -f "%Lp" $ROOT/node1/tree/mid.bin); P2=$(stat -f "%Lp" $ROOT/node2/tree-copy/mid.bin)
  M1=$(stat -f "%Sm" -t "%Y%m%d%H%M" $ROOT/node1/tree/top.txt); M2=$(stat -f "%Sm" -t "%Y%m%d%H%M" $ROOT/node2/tree-copy/top.txt)
  [ "$P1" = "$P2" ] && echo "权限保留 OK（$P2）" || echo "权限不一致：$P1 vs $P2"
  [ "$M1" = "$M2" ] && echo "mtime 保留 OK（$M2）" || echo "mtime 不一致：$M1 vs $M2"
  echo "目录递归冒烟 OK"
}

# 若指定了保持时长，则继续运行环境供手动实验
if [ "${1:-0}" -gt 0 ]; then echo "保持 ${1}s…"; sleep "$1"; fi
