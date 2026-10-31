#!/usr/bin/env bash
# repo-check.sh — 公开仓库一致性门禁
# 用法: scripts/repo-check.sh   （本地或 CI 均可，退出码 0=通过）
# 检查: 版本号两处同步、CHANGELOG 收录、必备文件齐全、docs 链接有效
set -u
cd "$(git rev-parse --show-toplevel 2>/dev/null)" || { echo "not a git repo"; exit 1; }
FAIL=0
ok()  { echo "  ✓ $1"; }
bad() { echo "  ✗ $1"; FAIL=1; }

CONF_VER=$(python -c "import json;print(json.load(open('src-tauri/tauri.conf.json',encoding='utf-8'))['version'])" 2>/dev/null)
CARGO_VER=$(grep -m1 '^version' src-tauri/Cargo.toml | sed 's/version *= *\"\(.*\)\"/\1/')

echo "[repo-check] 版本同步"
if [ "$CONF_VER" = "$CARGO_VER" ]; then ok "tauri.conf=$CONF_VER == Cargo.toml=$CARGO_VER";
else bad "版本漂移: tauri.conf=$CONF_VER vs Cargo.toml=$CARGO_VER（v1.3.0 实际踩过：二进制自报旧版本、更新器 semver 失灵）"; fi

echo "[repo-check] CHANGELOG"
if grep -q "\[$CONF_VER\]" CHANGELOG.md 2>/dev/null; then ok "CHANGELOG 含 [$CONF_VER]";
else bad "CHANGELOG 缺少 [$CONF_VER] 条目"; fi

echo "[repo-check] 必备文件"
for f in README.md README.en.md LICENSE CHANGELOG.md SECURITY.md CONTRIBUTING.md NOTICE.md CODE_OF_CONDUCT.md \
         .github/workflows/ci.yml .github/workflows/release.yml .github/dependabot.yml \
         .github/ISSUE_TEMPLATE/bug_report.yml .github/PULL_REQUEST_TEMPLATE.md docs/DESIGN.md; do
  [ -f "$f" ] && ok "$f" || bad "缺少 $f"
done

echo "[repo-check] README 语言互链"
grep -q "README.en.md" README.md && ok "zh→en 链接" || bad "README.md 缺 README.en.md 链接"
grep -q "README.md" README.en.md && ok "en→zh 链接" || bad "README.en.md 缺 README.md 链接"

echo "[repo-check] Issue 模板中的旧版本引用"
BADVER=$(grep -rl "placeholder.*[0-9]\+\.[0-9]\+" .github/ISSUE_TEMPLATE 2>/dev/null | wc -l)
[ "$BADVER" -eq 0 ] && ok "模板无硬编码版本" || ok "模板含版本样例（允许）"

if [ "$FAIL" -eq 0 ]; then echo "[repo-check] 通过 ✓"; exit 0;
else echo "[repo-check] 未通过 —— 公开前必须修复"; exit 1; fi
