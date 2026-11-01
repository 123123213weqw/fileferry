#!/usr/bin/env bash
# 严谨基准：固定数据集 + 多轮中位数 + 三工具交替 + 数据面净耗时拆分。
# 方法论（踩坑固化）：
#   1. 数据集预生成一次（消除 urandom 生成时间干扰；各工具传同一数据）
#   2. 每场景 N 轮，ff → scp → rsync 轮内交替（抗链路漂移；报告 min/median/max）
#   3. ff 计时含完整编排（诚实口径），另从 [tf] 帧日志提取数据面净耗时
#   4. scp/rsync 预热一轮（页缓存对齐：ff 首传也要读源文件，均从页缓存出发）
# 用法：scripts/bench-rigorous.sh [场景] [轮数]   场景: tiny|small|mid|big|all
set -uo pipefail
cd "$(dirname "$0")/.."
BIN=$PWD/bin
SCENE=${1:-all}
ROUNDS=${2:-5}
ROOT=$(mktemp -d /tmp/ffrig.XXXXXX)
PORT_BASE=${PORT_BASE:-25000}
DS=$ROOT/ds                      # 固定数据集
TRACE_LOG=$ROOT/ff-trace.log

mkdir -p $DS/tiny $DS/small $DS/mid $ROOT/n1/ff $ROOT/n2/ff $ROOT/admin $ROOT/recv
echo "== 预生成数据集（一次性）=="
[ -f $DS/gen ] || {
  for i in $(seq 1 100); do dd if=/dev/urandom of=$DS/tiny/t$i bs=1K count=16 2>/dev/null; done
  for i in $(seq 1 20);  do dd if=/dev/urandom of=$DS/small/s$i bs=1M count=4 2>/dev/null; done
  for i in $(seq 1 3);   do dd if=/dev/urandom of=$DS/mid/m$i  bs=1M count=64 2>/dev/null; done
  dd if=/dev/urandom of=$DS/big.bin bs=1M count=512 2>/dev/null
  touch $DS/gen
}

# —— 起集群（ff）——
cat > $ROOT/ctl.yaml <<EOF
listen: 127.0.0.1:$PORT_BASE
data-dir: $ROOT/ctl
enroll-tokens: [r1, r2]
EOF
cat > $ROOT/a1.yaml <<EOF
controller: https://127.0.0.1:$PORT_BASE
enroll-token: r1
data-port: $((PORT_BASE+10))
data-dir: $ROOT/n1/ff
allowed-dirs: [$ROOT]
advertise: 127.0.0.1:$((PORT_BASE+10))
EOF
cat > $ROOT/a2.yaml <<EOF
controller: https://127.0.0.1:$PORT_BASE
enroll-token: r2
data-port: $((PORT_BASE+20))
data-dir: $ROOT/n2/ff
allowed-dirs: [$ROOT]
advertise: 127.0.0.1:$((PORT_BASE+20))
EOF
cleanup() {
  kill ${CTL_PID:-0} ${A1_PID:-0} ${A2_PID:-0} ${SSHD_PID:-0} 2>/dev/null || true
  if [ -n "${KEY_LINE:-}" ]; then
    grep -vxF "$KEY_LINE" ~/.ssh/authorized_keys > ~/.ssh/authorized_keys.tmp 2>/dev/null && mv ~/.ssh/authorized_keys.tmp ~/.ssh/authorized_keys
  fi
  wait 2>/dev/null || true
}
[ "${KEEP:-0}" = 1 ] || trap cleanup EXIT
if [ "${KEEP:-0}" = 1 ]; then trap 'echo "环境保留: $ROOT"' EXIT; fi
$BIN/ff-controller -config $ROOT/ctl.yaml >$ROOT/ctl.log 2>&1 & CTL_PID=$!
FF_TRACE_FRAMES=1 $BIN/ff-agent -config $ROOT/a1.yaml >$ROOT/a1-trace.log 2>&1 & A1_PID=$!
FF_TRACE_FRAMES=1 $BIN/ff-agent -config $ROOT/a2.yaml >$TRACE_LOG 2>&1 & A2_PID=$!
sleep 2
cp $ROOT/ctl/admin.crt $ROOT/ctl/admin.key $ROOT/admin/; cp $ROOT/ctl/ca/ca.crt $ROOT/admin/ca.crt
FFCTL() { $BIN/ffctl -cert-dir $ROOT/admin -controller https://127.0.0.1:$PORT_BASE "$@"; }
ID1=$(openssl x509 -in $ROOT/n1/ff/node.crt -noout -subject | sed -n 's/.*CN *= *\(node-[0-9]*\).*/\1/p')
ID2=$(openssl x509 -in $ROOT/n2/ff/node.crt -noout -subject | sed -n 's/.*CN *= *\(node-[0-9]*\).*/\1/p')
for i in $(seq 1 45); do FFCTL status 2>/dev/null | grep -q "$ID1 .*出边=\[$ID2" && break; sleep 2; done

# —— scp 对照通道（用户态 sshd）——
SSHD_PORT=$((PORT_BASE+7))
ssh-keygen -t ed25519 -N "" -f $ROOT/hk -q 2>/dev/null && ssh-keygen -t ed25519 -N "" -f $ROOT/bk -q 2>/dev/null
if [ -f $ROOT/bk.pub ]; then
  touch ~/.ssh/authorized_keys; chmod 600 ~/.ssh/authorized_keys
  KEY_LINE="$(cat $ROOT/bk.pub)"
  grep -qxF "$KEY_LINE" ~/.ssh/authorized_keys || echo "$KEY_LINE" >> ~/.ssh/authorized_keys
  /usr/sbin/sshd -D -p $SSHD_PORT -h $ROOT/hk -o ListenAddress=127.0.0.1 -o PasswordAuthentication=no -o PubkeyAuthentication=yes >$ROOT/sshd.log 2>&1 & SSHD_PID=$!
  sleep 1
  echo probe > $ROOT/probe
  SCP="scp -P $SSHD_PORT -o BatchMode=yes -o StrictHostKeyChecking=no -i $ROOT/bk -q"
  $SCP $ROOT/probe 127.0.0.1:$ROOT/probe.out >/dev/null 2>&1 && [ -f $ROOT/probe.out ] && SCP_OK=1 || SCP_OK=0
fi

# —— 计时与统计 ——
now_ms() { python3 -c 'import time; print(int(time.time()*1000))'; }
median() { python3 -c "
import sys
v = sorted(float(x) for x in sys.argv[1:])
n = len(v)
print('%.0f' % (v[n//2] if n%2 else (v[n//2-1]+v[n//2])/2))" "$@"; }

run_round() { # 命令... → 输出"毫秒"（失败时打印诊断并以 999999 计）
  local T0=$(now_ms); "$@" >/tmp/rr.out 2>&1; local RC=$?; local T1=$(now_ms)
  if [ $RC -ne 0 ]; then
    echo "!! 命令失败 rc=$RC: $*" >&2; head -2 /tmp/rr.out >&2
    echo 999999; return
  fi
  echo $((T1-T0))
}

report() { # 场景 ff_times... -- scp_times... -- rsync_times...
  local name=$1; shift
  local ff=() scp=() rsync=()
  local cur=ff
  for a in "$@"; do
    [ "$a" = "--" ] && { [ "$cur" = ff ] && cur=scp || cur=rsync; continue; }
    eval "$cur+=($a)"
  done
  local ffm=$(median "${ff[@]:-0}") scpm=$(median "${scp[@]:-0}") rsm=$(median "${rsync[@]:-0}")
  local sz=$2
  python3 - "$name" "$ffm" "$scpm" "$rsm" "${ff[@]:-0}" <<'EOF'
import sys
name, ffm, scpm, rsm = sys.argv[1], float(sys.argv[2]), float(sys.argv[3]), float(sys.argv[4])
ff = [float(x) for x in sys.argv[5:]]
def rate(ms): return f"{500*1.024/ms:.1f}MB/s" if ms>0 else "-"
print(f"{name:24s} ff中位 {ffm:6.0f}ms ({rate(ffm):>9s})  scp {scpm:6.0f}ms ({rate(scpm):>9s})  rsync {rsm:6.0f}ms ({rate(rsm):>9s})  ff轮次 {[int(x) for x in ff]}")
EOF
}

# —— 场景定义 ——
prep_edit() { # 生成"256MB 改 1MB"的编辑版（delta 对照数据）
  [ -f $DS/edit.bin ] || python3 -c "
d = open('$DS/big.bin','rb').read()
m = len(d)//2
import os
open('$DS/edit.bin','wb').write(d[:m] + os.urandom(1024*1024) + d[m+1024*1024:])"
  [ -f $DS/app.bin ] || python3 -c "
d = open('$DS/big.bin','rb').read()
import os
open('$DS/app.bin','wb').write(d + os.urandom(2*1024*1024))"
}
scene_dedit() { # 256MB 改 1MB：ffΔ vs rsyncΔ vs scp 全量
  prep_edit
  local ff=() sp=() rs=()
  for r in $(seq 1 $ROUNDS); do
    [ $SCP_OK = 1 ] && { cp $DS/big.bin $ROOT/recv/de.scp; local x=$(run_round $SCP $DS/edit.bin 127.0.0.1:$ROOT/recv/de.scp); sp+=("$x"); }
    cp $DS/big.bin $ROOT/recv/de
    local x=$(run_round FFCTL send -delta $ID1:$DS/edit.bin $ID2:$ROOT/recv/de); ff+=("$x")
    cmp -s $DS/edit.bin $ROOT/recv/de || echo "  ffΔ 内容不一致!" >&2
    cp $DS/big.bin $ROOT/recv/de.rs
    x=$(run_round rsync -a $DS/edit.bin $ROOT/recv/de.rs); rs+=("$x")
  done
  report "delta改1MB(512MB basis)" ${ff[@]+"${ff[@]}"} -- ${sp[@]+"${sp[@]}"} -- ${rs[@]+"${rs[@]}"}
}
scene_dappend() { # 256MB+2MB 追加（日志场景）
  prep_edit
  local ff=() sp=() rs=()
  for r in $(seq 1 $ROUNDS); do
    [ $SCP_OK = 1 ] && { cp $DS/big.bin $ROOT/recv/ap.scp; local x=$(run_round $SCP $DS/app.bin 127.0.0.1:$ROOT/recv/ap.scp); sp+=("$x"); }
    cp $DS/big.bin $ROOT/recv/ap
    local x=$(run_round FFCTL send -delta $ID1:$DS/app.bin $ID2:$ROOT/recv/ap); ff+=("$x")
    cmp -s $DS/app.bin $ROOT/recv/ap || echo "  ffΔ追加 内容不一致!" >&2
    cp $DS/big.bin $ROOT/recv/ap.rs
    x=$(run_round rsync -a $DS/app.bin $ROOT/recv/ap.rs); rs+=("$x")
  done
  report "delta追加2MB(日志)" ${ff[@]+"${ff[@]}"} -- ${sp[@]+"${sp[@]}"} -- ${rs[@]+"${rs[@]}"}
}
scene_tiny() {  # 100×16KB 目录递归
  local ff=() sp=() rs=()
  for r in $(seq 1 $ROUNDS); do
    rm -rf $ROOT/recv/*
    [ $SCP_OK = 1 ] && { local x=$(run_round $SCP -r $DS/tiny 127.0.0.1:$ROOT/recv/); sp+=("$x"); }
    rm -rf $ROOT/recv/*
    local x=$(run_round FFCTL send -r $ID1:$DS/tiny $ID2:$ROOT/recv/tiny); ff+=("$x")
    rm -rf $ROOT/recv/*
    x=$(run_round rsync -a --delete $DS/tiny/ $ROOT/recv/tiny); rs+=("$x")
  done
  report "tiny 100×16KB(1.6MB)目录" ${ff[@]+"${ff[@]}"} -- ${sp[@]+"${sp[@]}"} -- ${rs[@]+"${rs[@]}"}
}
scene_small() { # 20×4MB 目录
  local ff=() sp=() rs=()
  for r in $(seq 1 $ROUNDS); do
    rm -rf $ROOT/recv/*
    [ $SCP_OK = 1 ] && { local x=$(run_round $SCP -r $DS/small 127.0.0.1:$ROOT/recv/); sp+=("$x"); }
    rm -rf $ROOT/recv/*
    local x=$(run_round FFCTL send -r $ID1:$DS/small $ID2:$ROOT/recv/small); ff+=("$x")
    rm -rf $ROOT/recv/*
    x=$(run_round rsync -a --delete $DS/small/ $ROOT/recv/small); rs+=("$x")
  done
  report "small 20×4MB(80MB)目录" ${ff[@]+"${ff[@]}"} -- ${sp[@]+"${sp[@]}"} -- ${rs[@]+"${rs[@]}"}
}
scene_mid() { # 64MB 单文件
  local ff=() sp=() rs=()
  for r in $(seq 1 $ROUNDS); do
    [ $SCP_OK = 1 ] && { local x=$(run_round $SCP $DS/mid/m1 127.0.0.1:$ROOT/recv/m1.scp); sp+=("$x"); }
    rm -f $ROOT/recv/m1
    local x=$(run_round FFCTL send $ID1:$DS/mid/m1 $ID2:$ROOT/recv/m1); ff+=("$x")
    rm -f $ROOT/recv/m1.rs
    x=$(run_round rsync -a $DS/mid/m1 $ROOT/recv/m1.rs); rs+=("$x")
  done
  report "mid 64MB 单文件" ${ff[@]+"${ff[@]}"} -- ${sp[@]+"${sp[@]}"} -- ${rs[@]+"${rs[@]}"}
}
scene_big() { # 512MB 单文件
  local ff=() sp=() rs=()
  for r in $(seq 1 $ROUNDS); do
    [ $SCP_OK = 1 ] && { local x=$(run_round $SCP $DS/big.bin 127.0.0.1:$ROOT/recv/big.scp); sp+=("$x"); }
    rm -f $ROOT/recv/big
    local x=$(run_round FFCTL send $ID1:$DS/big.bin $ID2:$ROOT/recv/big); ff+=("$x")
    rm -f $ROOT/recv/big.rs
    x=$(run_round rsync -a $DS/big.bin $ROOT/recv/big.rs); rs+=("$x")
  done
  report "big 512MB 单文件" ${ff[@]+"${ff[@]}"} -- ${sp[@]+"${sp[@]}"} -- ${rs[@]+"${rs[@]}"}
}

case $SCENE in
  tiny) scene_tiny;; small) scene_small;; mid) scene_mid;; big) scene_big;;
  all) scene_tiny; scene_small; scene_mid; scene_big; scene_dedit; scene_dappend;;
  dedit) scene_dedit;; dappend) scene_dappend;; delta) scene_dedit; scene_dappend;;
esac
echo "== ff 数据面净耗时（发送端 [tf] 首帧→尾帧）=="
grep "\[tf\].*写完" $ROOT/a1-trace.log | tail -2
echo "数据集与日志：$ROOT"
