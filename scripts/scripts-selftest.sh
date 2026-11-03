#!/usr/bin/env bash
# scripts-selftest.sh — 校验仓库脚本在非 UTF-8 控制台下也能正常工作。
#
# 背景：v1.10.2 的 Release 构建在 Windows runner 上失败，因为 release-notes.sh
# 里的 Python 输出中文，而 runner 控制台是 cp1252。本地（UTF-8 终端）完全正常，
# 所以必须在本地显式模拟 cp1252 才能提前发现同类问题。
#
# 用法: bash scripts/scripts-selftest.sh
set -uo pipefail
cd "$(git rev-parse --show-toplevel 2>/dev/null || dirname "$0"/..)"
FAIL=0
ok()  { echo "  ✓ $1"; }
bad() { echo "  ✗ $1"; FAIL=1; }

PY=$(command -v python || command -v python3)
VER=$("$PY" -c "import json;print(json.load(open('src-tauri/tauri.conf.json',encoding='utf-8'))['version'])")

echo "[scripts-selftest] 中文输出在 cp1252 控制台下不崩"
if PYTHONIOENCODING=cp1252 bash scripts/release-notes.sh >/dev/null 2>&1; then
  ok "release-notes.sh（cp1252 模拟）"
else
  bad "release-notes.sh 在 cp1252 下失败——Release 构建会挂"
fi
if PYTHONIOENCODING=cp1252 bash scripts/release-notes.sh 2>/dev/null | grep -q "ZCode Hub v$VER"; then
  ok "release-notes.sh 输出含 v$VER"
else
  bad "release-notes.sh 输出缺少版本标题 v$VER"
fi

echo "[scripts-selftest] release-notes 对缺失版本给出明确失败"
if bash scripts/release-notes.sh 0.0.0 >/dev/null 2>&1; then
  bad "缺失版本应返回非 0"
else
  ok "缺失版本返回非 0"
fi

echo "[scripts-selftest] coverage-gate 的报错路径可读"
# 注意：不要在 Git Bash 里 grep 中文——它的 locale 可能是 C，会把 UTF-8 中文判为不匹配。
# 这里改为断言「有 [coverage-gate] 前缀且不是 Python traceback」。
COV_ERR=$(PYTHONIOENCODING=cp1252 "$PY" scripts/coverage-gate.py /nonexistent.lcov 2>&1)
if echo "$COV_ERR" | grep -q "\[coverage-gate\]" && ! echo "$COV_ERR" | grep -q "Traceback"; then
  ok "coverage-gate 缺文件报错（cp1252 模拟，无 traceback）"
else
  bad "coverage-gate 缺文件时未给出可读报错: $COV_ERR"
fi

if [ "$FAIL" -eq 0 ]; then echo "[scripts-selftest] 通过 ✓"; exit 0;
else echo "[scripts-selftest] 未通过"; exit 1; fi
