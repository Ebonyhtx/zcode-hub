#!/usr/bin/env python
# coverage-gate.py — 从 LCOV 报告计算行覆盖率并做门槛校验。
# 用法: python scripts/coverage-gate.py lcov.info [--min 40]
# 退出码 0 = 达标；1 = 低于门槛（附差值）。
#
# 门槛是「防退化」而不是目标值：当前基线见 docs/PERFORMANCE.md。
# 大量代码依赖 Tauri 运行时 / Windows API，单测覆盖不到，所以门槛留出余量；
# 提升基线后应同步上调，避免覆盖率悄悄下滑。
import re
import sys

DEFAULT_MIN = 45.0  # 基线 46.7%（2026-11-03），留出余量防抖动


def parse_lcov(path):
    """返回 (命中行数, 总行数)。LCOV 的 DA:<line>,<count> 才是行覆盖数据。"""
    hit = total = 0
    try:
        f = open(path, encoding="utf-8")
    except OSError as e:
        sys.stderr.write("[coverage-gate] 无法读取 LCOV 报告 %s: %s\n" % (path, e))
        raise SystemExit(1)
    with f:
        for line in f:
            if not line.startswith("DA:"):
                continue
            body = line[3:].strip()
            parts = body.split(",")
            if len(parts) < 2:
                continue
            try:
                count = int(parts[1])
            except ValueError:
                continue
            total += 1
            if count > 0:
                hit += 1
    return hit, total


def main(argv):
    # 输出含中文：Windows 控制台默认 cp1252/GBK 会 UnicodeEncodeError，
    # 那会把真正的报错盖掉。显式固定为 UTF-8。
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    if len(argv) < 2:
        sys.stderr.write("usage: coverage-gate.py <lcov.info> [--min N]\n")
        return 2
    path = argv[1]
    minimum = DEFAULT_MIN
    if "--min" in argv:
        idx = argv.index("--min")
        if idx + 1 < len(argv):
            minimum = float(argv[idx + 1])
    hit, total = parse_lcov(path)
    if total == 0:
        sys.stderr.write("[coverage-gate] LCOV 里没有行数据: %s\n" % path)
        return 1
    pct = hit * 100.0 / total
    status = "OK" if pct >= minimum else "FAIL"
    print(
        "[coverage-gate] %s: %.2f%% line coverage (%d/%d lines), floor %.2f%%"
        % (status, pct, hit, total, minimum)
    )
    if pct < minimum:
        sys.stderr.write(
            "[coverage-gate] 低于门槛 %.2f 个百分点：新增代码请补测试，"
            "如果是有意下调，请在同一 PR 里说明并更新 docs/PERFORMANCE.md 的基线\n"
            % (minimum - pct)
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
