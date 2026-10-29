#!/usr/bin/env bash
# 本地三阶段强化压测（镜像 scripts/stress-test.sh 的阶段设计，
# 供真实舰队不可达时在本机验证稳定性；另加阶段4：中断续传）。
#   阶段1：5 并发 × 100MB   阶段2：1GB 大文件
#   阶段3：20 × 5MB 小文件风暴   阶段4：传输中杀掉源 agent → autoRetry 续传
# 用法：scripts/stress-local.sh
set -euo pipefail
cd "$(dirname "$0")/.."
BIN=$PWD/bin
ROOT=$(mktemp -d /tmp/fileferry-stress.XXXXXX)
PORT_BASE=${PORT_BASE:-18900}
AGENT_BIN=${AGENT_BIN:-$BIN/ff-agent}   # 阶段4 可换 -race 构建做泄漏观察

mkdir -p $ROOT/cfg $ROOT/n1/ff $ROOT/n2/ff $ROOT/admin $ROOT/n1/share
cat > $ROOT/cfg/controller.yaml <<EOF
listen: 127.0.0.1:$PORT_BASE
data-dir: $ROOT/ctl
enroll-tokens: [ff_enroll_t1, ff_enroll_t2]
EOF
cat > $ROOT/cfg/a1.yaml <<EOF
controller: https://127.0.0.1:$PORT_BASE
enroll-token: ff_enroll_t1
data-port: $((PORT_BASE+10))
data-dir: $ROOT/n1/ff
allowed-dirs: [$ROOT/n1, $ROOT/n2]
advertise: 127.0.0.1:$((PORT_BASE+10))
EOF
cat > $ROOT/cfg/a2.yaml <<EOF
controller: https://127.0.0.1:$PORT_BASE
enroll-token: ff_enroll_t2
data-port: $((PORT_BASE+20))
data-dir: $ROOT/n2/ff
allowed-dirs: [$ROOT/n1, $ROOT/n2]
advertise: 127.0.0.1:$((PORT_BASE+20))
EOF
cleanup() {
  kill ${CTL_PID:-0} ${A1_PID:-0} ${A2_PID:-0} 2>/dev/null || true
  wait 2>/dev/null || true
}
trap cleanup EXIT
$BIN/ff-controller -config $ROOT/cfg/controller.yaml >$ROOT/ctl.log 2>&1 & CTL_PID=$!
$AGENT_BIN -config $ROOT/cfg/a1.yaml >$ROOT/a1.log 2>&1 & A1_PID=$!
$AGENT_BIN -config $ROOT/cfg/a2.yaml >$ROOT/a2.log 2>&1 & A2_PID=$!
sleep 2
cp $ROOT/ctl/admin.crt $ROOT/ctl/admin.key $ROOT/admin/
cp $ROOT/ctl/ca/ca.crt $ROOT/admin/ca.crt
FFCTL() { $BIN/ffctl -cert-dir $ROOT/admin -controller https://127.0.0.1:$PORT_BASE "$@"; }

ID1=$(openssl x509 -in $ROOT/n1/ff/node.crt -noout -subject | sed -n 's/.*CN *= *\(node-[0-9]*\).*/\1/p')
ID2=$(openssl x509 -in $ROOT/n2/ff/node.crt -noout -subject | sed -n 's/.*CN *= *\(node-[0-9]*\).*/\1/p')
[ -n "$ID1" ] && [ -n "$ID2" ] || { echo "节点 ID 解析失败"; exit 1; }

# 等边 + 探测期间同步准备数据集（urandom 慢，后台并行）
dd if=/dev/urandom of=$ROOT/n1/share/rep100.bin bs=1M count=100 2>/dev/null &
DD1=$!
for i in $(seq 1 45); do
  FFCTL status 2>/dev/null | grep -q "$ID1 .*出边=\[$ID2" && break; sleep 2
done
wait $DD1
for i in $(seq 1 20); do dd if=/dev/urandom of=$ROOT/n1/share/s-$i.bin bs=1M count=5 2>/dev/null; done
T0=$(date +%s)

echo "=== 阶段1：5 并发 × 100MB ==="
SEND_PIDS=""
for i in 1 2 3 4 5; do
  FFCTL -nowait send $ID1:$ROOT/n1/share/rep100.bin $ID2:$ROOT/n2/ff/recv/p1-$i.bin > $ROOT/send1-$i.log 2>&1 &
  SEND_PIDS="$SEND_PIDS $!"
done
P1_OK=0
for t in $(seq 1 120); do
  N=$(( ls $ROOT/n2/ff/recv/p1-*.bin 2>/dev/null || true ) | wc -l | tr -d ' ')
  [ "$N" = "5" ] && break
  sleep 2
done
sleep 3 # 落盘收尾
for i in 1 2 3 4 5; do
  S1=$(shasum -a 256 $ROOT/n1/share/rep100.bin | cut -d' ' -f1)
  S2=$(shasum -a 256 $ROOT/n2/ff/recv/p1-$i.bin 2>/dev/null | cut -d' ' -f1)
  [ "$S1" = "$S2" ] && P1_OK=$((P1_OK+1)) || echo "  p1-$i 哈希不一致"
done
T1=$(date +%s)
echo "阶段1: ${P1_OK}/5 成功, 耗时 $((T1-T0))s, 聚合 $(python3 -c "print(round(500/max(1,$T1-$T0),1))")MB/s"

echo "=== 阶段2：1GB 大文件 ==="
T2=$(date +%s)
dd if=/dev/urandom of=$ROOT/n1/share/big1g.bin bs=1M count=1024 2>/dev/null
FFCTL send $ID1:$ROOT/n1/share/big1g.bin $ID2:$ROOT/n2/ff/recv/big1g.bin > /dev/null
S1=$(shasum -a 256 $ROOT/n1/share/big1g.bin | cut -d' ' -f1)
S2=$(shasum -a 256 $ROOT/n2/ff/recv/big1g.bin | cut -d' ' -f1)
T3=$(date +%s)
[ "$S1" = "$S2" ] && R2="OK($((T3-T2))s, $(python3 -c "print(round(1024/max(1,$T3-$T2),1))")MB/s)" || R2="BAD"
echo "阶段2: $R2"

echo "=== 阶段3：20 × 5MB 风暴 ==="
T4=$(date +%s)
SEND_PIDS=""
for i in $(seq 1 20); do
  FFCTL -nowait send $ID1:$ROOT/n1/share/s-$i.bin $ID2:$ROOT/n2/ff/recv/s-$i.bin > $ROOT/send3-$i.log 2>&1 &
  SEND_PIDS="$SEND_PIDS $!"
  [ $((i % 5)) = 0 ] && { wait $SEND_PIDS; SEND_PIDS=""; } # 限 5 并发：只等 send（守护进程不能 wait，否则死等）
done
[ -n "$SEND_PIDS" ] && wait $SEND_PIDS
P3_OK=0
for t in $(seq 1 90); do
  N=$(( ls $ROOT/n2/ff/recv/s-*.bin 2>/dev/null || true ) | wc -l | tr -d ' ')
  [ "$N" = "20" ] && break
  sleep 2
done
sleep 3
for i in $(seq 1 20); do
  S1=$(shasum -a 256 $ROOT/n1/share/s-$i.bin | cut -d' ' -f1)
  S2=$(shasum -a 256 $ROOT/n2/ff/recv/s-$i.bin 2>/dev/null | cut -d' ' -f1)
  [ "$S1" = "$S2" ] && P3_OK=$((P3_OK+1)) || echo "  s-$i 哈希不一致"
done
T5=$(date +%s)
echo "阶段3: ${P3_OK}/20 成功, 耗时 $((T5-T4))s"

echo "=== 阶段4：中断续传（传输中杀源 agent）==="
dd if=/dev/urandom of=$ROOT/n1/share/kill200.bin bs=1M count=200 2>/dev/null
FFCTL -nowait send $ID1:$ROOT/n1/share/kill200.bin $ID2:$ROOT/n2/ff/recv/kill200.bin > /dev/null
sleep 1.2 # 让传输启动
kill -9 $A1_PID; A1_PID=""
sleep 4   # autoRetry 生效窗口
$AGENT_BIN -config $ROOT/cfg/a1.yaml >>$ROOT/a1.log 2>&1 & A1_PID=$!
K_OK=BAD
for t in $(seq 1 90); do
  if [ -f $ROOT/n2/ff/recv/kill200.bin ]; then
    S1=$(shasum -a 256 $ROOT/n1/share/kill200.bin | cut -d' ' -f1)
    S2=$(shasum -a 256 $ROOT/n2/ff/recv/kill200.bin | cut -d' ' -f1)
    [ "$S1" = "$S2" ] && { K_OK="OK($t 轮内恢复)"; break; }
  fi
  sleep 2
done
echo "阶段4: $K_OK"

echo "=== 资源抽样（无泄漏粗查）==="
ps -o pid,rss,command -p $CTL_PID $A1_PID $A2_PID 2>/dev/null | awk 'NR==1 || /ff-/ {print $1, $2/1024 "MB", $3}'
echo "=== 汇总：数据 $((500+1024+100+200))MB + 20×5MB, 总耗时 $(($(date +%s)-T0))s ==="
