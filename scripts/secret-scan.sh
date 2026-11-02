#!/usr/bin/env bash
# secret-scan.sh — ZCode Hub 泄密守卫
# 用法:
#   secret-scan.sh --staged    # pre-commit: 扫描暂存区
#   secret-scan.sh --history   # pre-push / CI: 扫描全部历史
#   secret-scan.sh --selftest  # 自检: 构造已知泄漏验证扫描器确实能抓到
# 退出码: 0=干净, 1=发现泄漏或扫描器故障
#
# 实现注意: 扫描函数只输出命中文本、不在函数内改状态 ——
# 管道会把这些函数丢进子 shell，在里面设 FAIL 标志会静默丢失（实际踩过）。
set -u
SELF="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
cd "$(git rev-parse --show-toplevel 2>/dev/null)" || { echo "not a git repo"; exit 1; }
MODE="${1:---staged}"

# 泄漏值特征（写法刻意与源码常量区分：源码只有 "enc:v1:" 七个字符，不会命中 40+ 的密文模式）
VALUE_PATTERNS=(
  'enc:v1:[A-Za-z0-9+/=_-]{40,}'
  'eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}'
  'AQAAANCMnd8[A-Za-z0-9+/=]{20,}'
  'ZHB1:[A-Za-z0-9+/=]{40,}'
  '[u]ntrusted comment: minisign'  # 字符类防自匹配
  '-----BEGIN [A-Z ]*PRIVATE KEY-----'
  # 文档/注释里的明文密码：密码/password/secret 后跟冒号或等号 + 引号/反引号包住的 8+ 位字面量。
  # 只匹配“标记 + 分隔符 + 引号值”的形态，正文里的“密码至少 6 位”之类不会命中。
  '(^|[^A-Za-z0-9_])(密码|口令|[Pp]assword|[Pp]asswd|[Ss]ecret)[[:space:]]*[:：=]?[[:space:]]*[`"][A-Za-z0-9!@#$%^&*_+=.,-]{8,}[`"]'
)
# 禁止入库的文件路径（本地数据 / 密钥 / 打包产物）
PATH_PATTERNS=(
  '(^|/)(credentials\.snap|snapkey|hub-config\.json|benefits\.json|credentials\.json\.hub-backup)$'
  '\.zhb$'
  '(^|/)(profiles|dist|backups)/'
)

# 值特征扫描：stdin=待扫文本，stdout=命中行（无命中则空）
scan_content() {
  local p hits data
  data=$(cat)  # stdin 只能读一次：每条规则的 grep 会消费完管道
  for p in "${VALUE_PATTERNS[@]}"; do
    hits=$(printf '%s\n' "$data" | grep -nE "$p" 2>/dev/null | head -3 | cut -c1-140)
    [ -n "$hits" ] && printf '%s\n' "$hits"
  done
  return 0
}

# 路径扫描：stdin=文件名列表，stdout=被禁文件（无则空）
scan_files() {
  local f p
  while IFS= read -r f; do
    [ -z "$f" ] && continue
    for p in "${PATH_PATTERNS[@]}"; do
      echo "$f" | grep -qE "$p" && { echo "$f"; break; }
    done
  done
  return 0
}

# 汇总判定：stdin=命中集合；有命中打印详情并以非零退出
verdict() {
  local h
  if IFS= read -r h; then
    echo "  ✗ $h"
    while IFS= read -r h; do echo "  ✗ $h"; done
    echo "[secret-scan] 发现疑似泄漏 —— 提交被阻止。"
    echo "  凭据泄漏处置: 在 ZCode 客户端退出登录并重登（令牌失效）→ 删除对应存档 → 重扫通过后再提交。"
    echo "  确认为误报? 在 scripts/secret-scan.sh 的特征清单里说明并加白（慎用）。"
    return 1
  fi
  return 0
}

case "$MODE" in
  --staged)
    echo "[secret-scan] 扫描暂存区…"
    { git diff --cached --name-only | scan_files; git diff --cached -U0 | scan_content; } | verdict
    exit $?
    ;;
  --history)
    echo "[secret-scan] 扫描全部历史…"
    ALL_PAT=$(printf '%s|' "${VALUE_PATTERNS[@]}")
    ALL_PAT=${ALL_PAT%|}
    { git log --all --name-only --pretty=format: | sort -u | scan_files; } | verdict
    r1=$?
    M=$(git grep -hE "$ALL_PAT" $(git rev-list --all) 2>/dev/null | head -3 | cut -c1-140)
    r2=0
    if [ -n "$M" ]; then
      echo "$M" | verdict
      r2=$?
    fi
    [ $r1 -ne 0 ] && exit 1
    [ $r2 -ne 0 ] && exit 1
    echo "[secret-scan] 通过 ✓"
    exit 0
    ;;
  --selftest)
    echo "[secret-scan] 自检…"
    TMP=$(mktemp -d)
    git init -q "$TMP" 2>/dev/null
    cd "$TMP" || exit 1   # 必须真正驻留临时仓库，否则扫描器扫的是外层仓库的暂存区
    FIXTURE="enc:v1:AbCd""EfGhIjKlMnOpQrStUvWxYz0123456789abcdefABCDEF+"  # 运行时拼接，源码不构成完整特征
    echo "token := "$FIXTURE"" > leak.txt
    git add leak.txt
    if bash "$SELF" --staged >/dev/null 2>&1; then
      echo "  ✗ 扫描器漏报（未拦截明显泄漏）"; cd /; rm -rf "$TMP"; exit 1
    else
      echo "  ✓ 泄漏文件被正确拦截"
    fi
    echo 'clean = 1' > ok.txt
    git rm --cached leak.txt -q && git add ok.txt
    if bash "$SELF" --staged >/dev/null 2>&1; then
      echo "  ✓ 干净文件正确放行"
    else
      echo "  ✗ 扫描器误报"; cd /; rm -rf "$TMP"; exit 1
    fi
    # 明文密码（文档形态）必须拦截
    PWFIX="Demo-""Pass-""987654321"   # 运行时拼接，源码不构成完整特征
    printf 'login: demo
密码 `%s`
' "$PWFIX" > pw.txt
    git add pw.txt
    if bash "$SELF" --staged >/dev/null 2>&1; then
      echo "  ✗ 扫描器漏报（未拦截文档中的明文密码）"; cd /; rm -rf "$TMP"; exit 1
    else
      echo "  ✓ 文档明文密码被正确拦截"
    fi
    # 说明性文字不得误报
    git rm --cached pw.txt -q
    echo '口令至少 6 位，且密码与令牌不会出现在这里' > pwok.txt
    git add pwok.txt
    if bash "$SELF" --staged >/dev/null 2>&1; then
      echo "  ✓ 说明性文字正确放行"
    else
      echo "  ✗ 扫描器误报（说明性文字被拦截）"; cd /; rm -rf "$TMP"; exit 1
    fi
    cd /
    rm -rf "$TMP"
    echo "[secret-scan] 自检通过 ✓"
    exit 0
    ;;
  *)
    echo "用法: secret-scan.sh --staged|--history|--selftest"; exit 1 ;;
esac
