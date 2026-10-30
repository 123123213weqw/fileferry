#!/usr/bin/env bash
# 本地基准：fileferry vs rsync vs cp（回环，2 agent 同机不同端口）。
# macOS 无 sshd 权限时 scp 跳过；rsync 用 daemon 模式（无 ssh 加密，
# 是 rsync 的最快形态）。文件均为随机内容（无压缩收益，公平）。
set -euo pipefail
cd "$(dirname "$0")/.."
BIN=$PWD/bin
SCALE=${SIZE_SCALE:-1} # 数据集缩放：共享/波动机器上可调小求速（如 0.25）
ROOT=$(mktemp -d /tmp/fileferry-bench.XXXXXX)
PORT_BASE=${PORT_BASE:-18800}

mkdir -p $ROOT/cfg $ROOT/n1/ff $ROOT/n2/ff $ROOT/admin $ROOT/n1/src $ROOT/n2/dst $ROOT/rsync-tmp
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
RS_DST=$ROOT/n2/dst/  # openrsync 的 daemon 模式不可用：直接本地→本地
cleanup() {
  kill ${CTL_PID:-0} ${A1_PID:-0} ${A2_PID:-0} 2>/dev/null || true
  [ -n "${SSHD_PID:-}" ] && kill $SSHD_PID 2>/dev/null || true
  if [ -n "${BENCH_KEY_LINE:-}" ]; then
    grep -vxF "$BENCH_KEY_LINE" ~/.ssh/authorized_keys > ~/.ssh/authorized_keys.tmp 2>/dev/null && \
      mv ~/.ssh/authorized_keys.tmp ~/.ssh/authorized_keys
    chmod 600 ~/.ssh/authorized_keys
  fi
  wait 2>/dev/null || true
}
trap cleanup EXIT
$BIN/ff-controller -config $ROOT/cfg/controller.yaml >$ROOT/ctl.log 2>&1 & CTL_PID=$!
$BIN/ff-agent -config $ROOT/cfg/a1.yaml >$ROOT/a1.log 2>&1 & A1_PID=$!
$BIN/ff-agent -config $ROOT/cfg/a2.yaml >$ROOT/a2.log 2>&1 & A2_PID=$!
sleep 2
cp $ROOT/ctl/admin.crt $ROOT/ctl/admin.key $ROOT/admin/
cp $ROOT/ctl/ca/ca.crt $ROOT/admin/ca.crt

# scp 对照：macOS 无 root 起不了系统 sshd，用**用户态 sshd**（高位端口，
# 仅回环）。密钥完全自包含：临时 hostkey + 临时客户端密钥 +
# AuthorizedKeysFile 指向本目录（不动用户的 authorized_keys）。
SSHD_PORT=$((PORT_BASE+7))
if ssh-keygen -t ed25519 -N "" -f $ROOT/hostkey -q 2>/dev/null && \
   ssh-keygen -t ed25519 -N "" -f $ROOT/benchkey -q 2>/dev/null; then
  # 临时公钥挂进用户 authorized_keys（macOS sshd 对绝对路径
  # AuthorizedKeysFile 不生效），cleanup 精确移除
  touch ~/.ssh/authorized_keys; chmod 600 ~/.ssh/authorized_keys
  BENCH_KEY_LINE="$(cat $ROOT/benchkey.pub)"
  grep -qxF "$BENCH_KEY_LINE" ~/.ssh/authorized_keys || echo "$BENCH_KEY_LINE" >> ~/.ssh/authorized_keys
  /usr/sbin/sshd -D -p $SSHD_PORT -h $ROOT/hostkey \
    -o ListenAddress=127.0.0.1 -o PasswordAuthentication=no \
    -o PubkeyAuthentication=yes >$ROOT/sshd.log 2>&1 &
  SSHD_PID=$!
  SCP="TIMEOUT 30 scp -P $SSHD_PORT -o BatchMode=yes -o StrictHostKeyChecking=no -i $ROOT/benchkey"
  # 通道探活：小文件实测（部分环境用户态 sshd 会挂起，探测失败即跳过 scp 行）
  echo probe > $ROOT/probe.txt
  if $SCP $ROOT/probe.txt 127.0.0.1:$ROOT/probe.out >/dev/null 2>&1 && [ -f $ROOT/probe.out ]; then
    echo "scp 对照通道：用户态 sshd 127.0.0.1:$SSHD_PORT（探活通过）"
  else
    SCP=""
    echo "（scp 通道探活失败，跳过 scp 对照）"
    kill $SSHD_PID 2>/dev/null || true
  fi
else
  SCP=""
  echo "（ssh-keygen 不可用，跳过 scp 对照）"
fi

FFCTL() { $BIN/ffctl -cert-dir $ROOT/admin -controller https://127.0.0.1:$PORT_BASE "$@"; }
for i in $(seq 1 45); do
  FFCTL status 2>/dev/null | grep -q "node-1 .*出边=\[node-2" && break; sleep 2
done

# 测试数据：256MB 大文件 + 100×4MB 中文件 + 500×16KB 小文件（随机内容）
BIG_N=$(python3 -c "print(max(1,int(256*$SCALE)))")
dd if=/dev/urandom of=$ROOT/n1/src/big.bin bs=1M count=$BIG_N 2>/dev/null
mkdir -p $ROOT/n1/src/mset
M_N=$(python3 -c "print(max(1,int(100*$SCALE)))")
for i in $(seq 1 $M_N); do dd if=/dev/urandom of=$ROOT/n1/src/mset/m-$i.bin bs=1K count=4096 2>/dev/null; done
mkdir -p $ROOT/n1/src/smalls
S_N=$(python3 -c "print(max(1,int(500*$SCALE)))")
for i in $(seq 1 $S_N); do dd if=/dev/urandom of=$ROOT/n1/src/smalls/s-$i.bin bs=1K count=16 2>/dev/null; done

# TIMEOUT <秒> <命令...>：可移植超时（macOS 无 GNU timeout）
TIMEOUT() {
  local secs=$1; shift
  if command -v timeout >/dev/null 2>&1; then
    timeout "$secs" "$@"
  else
    "$@" & local p=$!
    ( sleep "$secs"; kill -9 $p 2>/dev/null ) & local k=$!
    wait $p; local rc=$?
    kill $k 2>/dev/null
    return $rc
  fi
}

bench() { # 名称 命令...
  local name=$1; shift
  local t0=$(python3 -c 'import time;print(time.time())')
  "$@" > /dev/null 2>&1
  local rc=$?
  local t1=$(python3 -c 'import time;print(time.time())')
  BENCH_NAME="$name" BENCH_T0="$t0" BENCH_T1="$t1" BENCH_RC=$rc python3 <<'EOF'
import os
n = os.environ["BENCH_NAME"]
d = float(os.environ["BENCH_T1"]) - float(os.environ["BENCH_T0"])
print("%s: %.1fs rc=%s" % (n, d, os.environ["BENCH_RC"]))
EOF
}

echo "=== 大文件 256MB ==="
rm -f $ROOT/n2/dst/big.bin
bench "ff    " FFCTL send node-1:$ROOT/n1/src/big.bin node-2:$ROOT/n2/dst/big.bin
rm -f $ROOT/n2/dst/big.cp
bench "cp    " cp $ROOT/n1/src/big.bin $ROOT/n2/dst/big.cp
rm -f $ROOT/n2/dst/big.rsync
bench "rsync " rsync -a $ROOT/n1/src/big.bin $RS_DST
if [ -n "$SCP" ]; then
  rm -f $ROOT/n2/dst/big.scp
  bench "scp   " $SCP $ROOT/n1/src/big.bin 127.0.0.1:$ROOT/n2/dst/big.scp
fi

echo "=== 100×4MB = 400MB，目录递归 ==="
rm -rf ${RS_DST}mff
bench "rsync " rsync -a $ROOT/n1/src/mset ${RS_DST}mff
rm -rf $ROOT/n2/dst/mcp && mkdir -p $ROOT/n2/dst/mcp
bench "cp    " cp $ROOT/n1/src/mset/m-*.bin $ROOT/n2/dst/mcp/
rm -rf $ROOT/n2/dst/mffdir
bench "ff    " FFCTL send -r node-1:$ROOT/n1/src/mset node-2:$ROOT/n2/dst/mffdir
if [ -n "$SCP" ]; then
  rm -rf $ROOT/n2/dst/mset.scp
  bench "scp   " $SCP -r $ROOT/n1/src/mset 127.0.0.1:$ROOT/n2/dst/mset.scp
fi

echo "=== 增量同步 256MB 改 1MB（delta transfer 对照） ==="
# 目的端已有 big.bin（旧版），源端 big2.bin = big.bin 改中间 1MB：
# rsync 天然走增量；ff 需 -delta 显式开启；scp 永远全量
dd if=/dev/urandom of=$ROOT/n1/src/big-edit.bin bs=1M count=1 2>/dev/null
python3 - "$ROOT/n1/src/big.bin" "$ROOT/n1/src/big2.bin" "$ROOT/n1/src/big-edit.bin" <<'EOF'
import sys
old, new, editp = sys.argv[1], sys.argv[2], sys.argv[3]
with open(old, 'rb') as f:
    data = f.read()
mid = len(data) // 2
with open(editp, 'rb') as f:
    e = f.read()
with open(new, 'wb') as f:
    f.write(data[:mid] + e + data[mid + len(e):])
EOF
rm -f $ROOT/n2/dst/big2.bin && cp $ROOT/n1/src/big.bin $ROOT/n2/dst/big2.bin # 目的端旧版
bench "ffΔ   " FFCTL send -delta node-1:$ROOT/n1/src/big2.bin node-2:$ROOT/n2/dst/big2.bin
cmp -s $ROOT/n1/src/big2.bin $ROOT/n2/dst/big2.bin && echo "  ffΔ 内容一致" || echo "  ffΔ 内容不一致!!"
cp $ROOT/n1/src/big.bin $ROOT/n2/dst/big2.rsync
bench "rsyncΔ" rsync -a $ROOT/n1/src/big2.bin $RS_DST.big2.rsync
if [ -n "$SCP" ]; then
  cp $ROOT/n1/src/big.bin $ROOT/n2/dst/big2.scp
  bench "scp   " $SCP $ROOT/n1/src/big2.bin 127.0.0.1:$ROOT/n2/dst/big2.scp
fi

echo "=== 日志追加 ${BIG_N}MB+1MB（tail 场景：前缀不变仅尾部追加） ==="
python3 - "$ROOT/n1/src/big.bin" "$ROOT/n1/src/appended.bin" <<'EOF'
import sys, os
old, new = sys.argv[1], sys.argv[2]
with open(old, 'rb') as f:
    data = f.read()
with open(new, 'wb') as f:
    f.write(data)
    f.write(os.urandom(1024 * 1024))
EOF
cp $ROOT/n1/src/big.bin $ROOT/n2/dst/appended.bin
bench "ffΔ+  " FFCTL send -delta node-1:$ROOT/n1/src/appended.bin node-2:$ROOT/n2/dst/appended.bin
cmp -s $ROOT/n1/src/appended.bin $ROOT/n2/dst/appended.bin && echo "  内容一致" || echo "  内容不一致!!"
# 二次追加（basis 校验和缓存命中 + 快速路径：日常日志同步的真实形态）
python3 -c "
d = open('$ROOT/n1/src/appended.bin','rb').read()
open('$ROOT/n1/src/appended2.bin','wb').write(d + __import__('os').urandom(1024*1024))"
bench "ffΔ+2 " FFCTL send -delta node-1:$ROOT/n1/src/appended2.bin node-2:$ROOT/n2/dst/appended.bin
cmp -s $ROOT/n1/src/appended2.bin $ROOT/n2/dst/appended.bin && echo "  内容一致" || echo "  内容不一致!!"
cp $ROOT/n1/src/big.bin $ROOT/n2/dst/appended.rsync
bench "rsyncΔ" rsync -a $ROOT/n1/src/appended.bin $RS_DST.appended.rsync

echo "=== 500×16KB ≈ 8MB，目录递归（小文件风暴） ==="
rm -rf ${RS_DST}smalls
bench "rsync " rsync -a $ROOT/n1/src/smalls $RS_DST
mkdir -p $ROOT/n2/dst/scp-check && rm -rf $ROOT/n2/dst/scp-check && bench "cp    " cp -R $ROOT/n1/src/smalls $ROOT/n2/dst/scp-check/
rm -rf $ROOT/n2/dst/smalls-ff
bench "ff    " FFCTL send -r node-1:$ROOT/n1/src/smalls node-2:$ROOT/n2/dst/smalls-ff
if [ -n "$SCP" ]; then
  rm -rf $ROOT/n2/dst/smalls.scp
  bench "scp   " $SCP -r $ROOT/n1/src/smalls 127.0.0.1:$ROOT/n2/dst/smalls.scp
fi
echo "=== 目录：$ROOT ==="
