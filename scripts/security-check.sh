#!/usr/bin/env bash
# fileferry 安全自检：对运行中的 controller 跑渗透用例回归。
# 用法: security-check.sh <controller-url> [节点证书目录] [已知已用token]
set -u
CTL="${1:?用法: security-check.sh <controller-url> [节点证书目录] [已用token]}"
CERTDIR="${2:-}"
BURNED="${3:-}"
pass=0; fail=0
check() { # 名称 期望 实际
  if [ "$2" = "$3" ]; then echo "PASS: $1"; pass=$((pass+1)); else echo "FAIL: $1 (期望 $2 得到 $3)"; fail=$((fail+1)); fi
}
# 1. 匿名访问被拒
code=$(curl -sk -m 5 "$CTL/v1/status" -o /dev/null -w '%{http_code}')
check "匿名 status 403" 403 "$code"
code=$(curl -sk -m 5 -X POST "$CTL/v1/transfer" -d '{}' -o /dev/null -w '%{http_code}')
check "匿名 transfer 403" 403 "$code"
# 2. 错误 token 被拒
code=$(curl -sk -m 5 -X POST "$CTL/v1/enroll" -d '{"token":"x"}' -o /dev/null -w '%{http_code}')
check "伪造 token 401" 401 "$code"
# 3. 已用 token 重放被拒（持久台账）
if [ -n "$BURNED" ]; then
  code=$(curl -sk -m 5 -X POST "$CTL/v1/enroll" -d "{\"token\":\"$BURNED\"}" -o /dev/null -w '%{http_code}')
  check "token 重放 401" 401 "$code"
fi
# 4. 节点证书无管理员权限
if [ -n "$CERTDIR" ] && [ -f "$CERTDIR/node.crt" ]; then
  code=$(curl -sk -m 5 --cert "$CERTDIR/node.crt" --key "$CERTDIR/node.key" -X POST "$CTL/v1/transfer" -d '{}' -o /dev/null -w '%{http_code}')
  check "节点证书 transfer 403" 403 "$code"
  code=$(curl -sk -m 5 --cert "$CERTDIR/node.crt" --key "$CERTDIR/node.key" "$CTL/v1/status" -o /dev/null -w '%{http_code}')
  check "节点证书 status 403" 403 "$code"
fi
echo "---- $pass 通过 / $fail 失败 ----"
[ "$fail" = 0 ]
