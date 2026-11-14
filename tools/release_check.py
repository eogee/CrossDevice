#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""发布前校验脚本（B24 发布流程配套，仅标准库，可入库复跑）。

用法：
    py tools/release_check.py --tag v0.4.0

校验项：
    ① 打包清单 8 个文件在仓库中存在（见 docs/发布流程.md 打包清单）；
    ② node/node.py 的 NODE_VERSION 与 --tag 一致（tag 去 v 前缀比较）；
    ③ LICENSE / SECURITY.md / README.md 存在；
    ④ 打包清单不含 data/devices.json 与 .trae/（含敏感令牌/IDE 配置，不入包）；
    ⑤ tools/gen_cert.ps1 存在（xd cert init 的生成工具链）。

全部通过 → 打印汇总并以退出码 0 结束；任一失败 → 列出全部问题并以退出码 1 结束。
"""

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# 打包清单（docs/发布流程.md）：8 个文件
PACKAGE_MANIFEST = [
    "xd.py",
    "discover.py",
    "node/node.py",
    "watchdog.py",
    "tools/gen_cert.ps1",
    "README.md",
    "LICENSE",
    "SECURITY.md",
]

# 禁止入包的敏感文件/目录（含真实令牌与 IDE 配置）
FORBIDDEN_IN_MANIFEST = ("data/devices.json", ".trae/")


def main():
    ap = argparse.ArgumentParser(description="CrossDevice 发布前校验")
    ap.add_argument("--tag", required=True, help="发布 tag，如 v0.4.0（与 NODE_VERSION 对齐）")
    opts = ap.parse_args()

    problems = []
    checks = []

    def check(name, ok, note):
        checks.append((name, bool(ok), note))

    # ① 打包清单 8 文件存在
    missing = [p for p in PACKAGE_MANIFEST if not (ROOT / p).is_file()]
    check("打包清单 8 文件齐全", not missing,
          "缺：" + "、".join(missing) if missing
          else "xd.py / discover.py / node/node.py / watchdog.py / tools/gen_cert.ps1 / README.md / LICENSE / SECURITY.md 全部在库")
    for p in missing:
        problems.append("打包清单缺文件：%s" % p)

    # ② NODE_VERSION 与 tag 一致（去 v 前缀比较）
    tag = opts.tag.strip()
    tag_ver = tag[1:] if tag.lower().startswith("v") else tag
    node_py = ROOT / "node" / "node.py"
    node_version = None
    if not node_py.is_file():
        problems.append("node/node.py 不存在，无法核对 NODE_VERSION")
        note = "node/node.py 缺失"
    else:
        m = re.search(r'^NODE_VERSION\s*=\s*"([^"]+)"',
                      node_py.read_text(encoding="utf-8"), re.M)
        node_version = m.group(1) if m else None
        if node_version is None:
            problems.append("node/node.py 中未找到 NODE_VERSION 定义")
            note = "未找到 NODE_VERSION 定义"
        elif node_version != tag_ver:
            problems.append("NODE_VERSION（%s）与 tag（%s）不一致：tag 应为 v%s，或先升 NODE_VERSION 再发布"
                            % (node_version, tag, node_version))
            note = "NODE_VERSION=%s，tag=%s（去前缀 %s）→ 不一致" % (node_version, tag, tag_ver)
        else:
            note = "NODE_VERSION=%s，tag=%s（去前缀 %s）→ 一致" % (node_version, tag, tag_ver)
    check("NODE_VERSION == tag（去 v 前缀）", node_version == tag_ver, note)

    # ③ LICENSE / SECURITY.md / README.md 存在（与 ① 有重叠，单列以保证清单调整后仍有此门槛）
    docs_missing = [p for p in ("README.md", "LICENSE", "SECURITY.md")
                    if not (ROOT / p).is_file()]
    check("README / LICENSE / SECURITY 就绪", not docs_missing,
          "缺：" + "、".join(docs_missing) if docs_missing else "三件开源文档齐备")
    for p in docs_missing:
        problems.append("开源文档缺：%s" % p)

    # ④ 打包清单不含敏感文件
    leaked = [p for p in PACKAGE_MANIFEST
              if p == FORBIDDEN_IN_MANIFEST[0] or p.startswith(FORBIDDEN_IN_MANIFEST[1])]
    check("清单不含 data/devices.json 与 .trae/", not leaked,
          "泄漏项：" + "、".join(leaked) if leaked
          else "敏感文件未入清单（含令牌的注册表与 IDE 配置不入包）")
    for p in leaked:
        problems.append("打包清单含敏感文件：%s" % p)

    # ⑤ gen_cert.ps1 存在
    cert_ok = (ROOT / "tools" / "gen_cert.ps1").is_file()
    check("tools/gen_cert.ps1 存在", cert_ok,
          "缺失（xd cert init 的生成工具链不在库）" if not cert_ok else "证书生成工具链在库")
    if not cert_ok:
        problems.append("tools/gen_cert.ps1 不存在")

    # ---- 汇总输出 ----
    print("=" * 72)
    print("release_check（tag=%s）" % tag)
    print("-" * 72)
    for name, ok, note in checks:
        print("%s %s（%s）" % ("PASS" if ok else "FAIL", name, note))
    print("-" * 72)
    if problems:
        print("共 %d 个问题：" % len(problems))
        for p in problems:
            print("  - %s" % p)
        print("校验未通过，禁止发布。")
        return 1
    print("全部通过：清单 %d 项齐备、版本一致、敏感文件未入包。"
          "可按 docs/发布流程.md 继续（tag → 打包）。" % len(PACKAGE_MANIFEST))
    return 0


if __name__ == "__main__":
    sys.exit(main())
