#!/usr/bin/env bash
# fileferry 压力测试
# 用法：FF_CONTROLLER=https://ctl:9443 FF_SRC=node-2 FF_DST=node-4 \
#       FF_SRC_DIR=/srv/share FF_DST_DIR=/srv/recv ./stress-test.sh
# 所有节点名与目录都从环境变量取，脚本内不再写死任何真实主机/路径。
CTL="${FF_CONTROLLER:?用法: FF_CONTROLLER=https://<controller>:9443 stress-test.sh}"
SRC="${FF_SRC:?缺 FF_SRC（源节点名）}"
DST="${FF_DST:?缺 FF_DST（目的节点名）}"
SRC_DIR="${FF_SRC_DIR:-/srv/share}"
DST_DIR="${FF_DST_DIR:-/srv/recv}"
FF() { ~/fileferry/bin/ffctl -nowait -cert-dir ~/ff-admin-hub -controller $CTL "$@"; }
chk() { # 本地文件 远端路径 对端ssh别名 -> 校验并输出
  S1=$(sha256sum "$1" | cut -d" " -f1)
  S2=$(ssh -o BatchMode=yes "$3" "sha256sum $2 2>/dev/null" | cut -d" " -f1)
  [ "$S1" = "$S2" ] && echo OK || echo BAD
}
H="${FF_DST_SSH:?缺 FF_DST_SSH（目的机 ssh 别名，用于校验）}"; RD="$DST_DIR"
T0=$(date +%s)
echo "=== 阶段1：5 并发 × 100MB 多源 ==="
for i in 1 2 3 4 5; do FF send ${SRC}:${SRC_DIR}/replica100.bin ${DST}:$RD/p1-$i.bin >/dev/null & done
# 轮询全部到达（最多 10 分钟）
for t in $(seq 1 120); do
  N=$(ssh -o BatchMode=yes $H "ls $RD/p1-*.bin 2>/dev/null | wc -l")
  [ "$N" = "5" ] && break; sleep 5
done
T1=$(date +%s); P1=$((T1-T0))
R1=0; for i in 1 2 3 4 5; do [ "$(chk ~/ff-share/replica100.bin $RD/p1-$i.bin $H)" = OK ] && R1=$((R1+1)); done
echo "阶段1: ${R1}/5 成功, 总耗时 ${P1}s, 聚合吞吐 $(echo "scale=1; 500/$P1" | bc)MB/s"
echo "=== 阶段2：1GB 大文件 ==="
T2=$(date +%s)
FF send ${SRC}:${SRC_DIR}/big1g.bin ${DST}:$RD/big1g.bin >/dev/null
for t in $(seq 1 180); do
  ssh -o BatchMode=yes $H "test -f $RD/big1g.bin" 2>/dev/null && break; sleep 5
done
T3=$(date +%s); P2=$((T3-T2))
R2=$(chk ~/ff-share/big1g.bin $RD/big1g.bin $H)
echo "阶段2: $R2, 耗时 ${P2}s, 吞吐 $(echo "scale=1; 1024/$P2" | bc)MB/s"
echo "=== 阶段3：20 × 5MB 小文件风暴 ==="
T4=$(date +%s)
for i in $(seq 1 20); do FF send ${SRC}:${SRC_DIR}/small-$i.bin ${DST}:$RD/s-$i.bin >/dev/null; done
for t in $(seq 1 120); do
  N=$(ssh -o BatchMode=yes $H "ls $RD/s-*.bin 2>/dev/null | wc -l")
  [ "$N" = "20" ] && break; sleep 3
done
T5=$(date +%s); P3=$((T5-T4))
R3=0; for i in $(seq 1 20); do [ "$(chk ~/ff-share/small-$i.bin $RD/s-$i.bin $H)" = OK ] && R3=$((R3+1)); done
echo "阶段3: ${R3}/20 成功, 总耗时 ${P3}s"
echo "=== 汇总 ==="
echo "总数据量 $((500+1024+100))MB, 总耗时 $((T5-T0))s"
