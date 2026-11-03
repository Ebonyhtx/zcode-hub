#!/usr/bin/env bash
# release-notes.sh — 从 CHANGELOG.md 提取某个版本的段落，作为 Release 说明。
# 用法: scripts/release-notes.sh 1.10.1 > notes.md
#       省略版本参数时读取 src-tauri/tauri.conf.json 的版本号。
# 文案来源是仓库内可审阅的 CHANGELOG，而不是从 commit 标题现凑。
set -euo pipefail
cd "$(git rev-parse --show-toplevel 2>/dev/null || dirname "$0"/..)"

PY=$(command -v python || command -v python3)
VER="${1:-}"
if [ -z "$VER" ]; then
  VER=$("$PY" -c "import json;print(json.load(open('src-tauri/tauri.conf.json',encoding='utf-8'))['version'])")
fi

"$PY" - "$VER" <<'PY'
import re
import sys

# CHANGELOG 是中文：Windows 控制台默认 cp1252/GBK，直接 print 会在 CI 上崩。
# 显式把 stdout 重配为 UTF-8，保证任何平台输出一致。
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

version = sys.argv[1]
heading = re.compile(r"^##\s+\[(?P<ver>[^\]]+)\]")
with open("CHANGELOG.md", encoding="utf-8") as f:
    lines = f.read().splitlines()

start = None
for i, line in enumerate(lines):
    m = heading.match(line)
    if m and m.group("ver") == version:
        start = i
        break
if start is None:
    sys.stderr.write("[release-notes] CHANGELOG.md 里没有 [%s] 段落\n" % version)
    sys.exit(1)

end = len(lines)
for j in range(start + 1, len(lines)):
    if heading.match(lines[j]):
        end = j
        break

body = "\n".join(lines[start + 1:end]).strip()
if not body:
    sys.stderr.write("[release-notes] [%s] 段落为空\n" % version)
    sys.exit(1)

# 去掉正文里对「本节内容针对哪个版本」已冗余的引导行，保留分节与小标题
print("## ZCode Hub v%s\n" % version)
print(body)
PY
