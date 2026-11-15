#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""smoke_s6 —— M6 批次自测（B17 宏录制与回放，纯控制端 CLI，协议零变更）。

覆盖（契约 §11 V1.7 兼容清单行 / README"宏（macro rec/run）"节）：
  M1  宏格式严格校验（白盒 xd.validate_macro / xd.load_macro）：合法宏通过并
      规范化（button 默认补齐、未知键剥离）；未知动作类型/缺必填字段/类型不对/
      数值越界/坏 version/顶层非对象/actions 非数组/未知字段/布尔冒充整数逐项
      整体拒绝且报错明确；文件缺失/坏 JSON 亦明确报错
  M2  回放顺序与 delay 节奏（真实临时 node，TLS+令牌）：只含 move 的小宏经
      `xd macro run` 分段发送，node 审计 jsonl 里 /v1/input 条目的 actions
      序列与 ts 间隔做证据（段间 ≥0.4s）；控制端墙钟 ≥ sum(delay)/speed；
      正常结束自动 release（结束后 tester 身份可 acquire 成功）
  M3  租约全程持有与中断释放：回放期间以第二身份 acquire → 409
      INPUT_LEASE_TAKEN（注入式 sleeper 在段间探测，确定性）；白盒对
      xd.macro_run_segments 注入 KeyboardInterrupt / RuntimeError 桩，
      用记录型 sender 断言随后发出了 release 请求（X-Input-Lease: release +
      空 actions），且原异常类型如实抛出
  M4  录制白盒：合成事件流喂 xd.macro_events_to_actions，断言移动去抖（位移/
      时间双阈值）、双击聚合、打字聚合、按键与滚轮映射、间隔→delay_ms；
      产物经 validate_macro 同一套校验通过；macro_plan 分段与 --speed 缩放
  M5  非法宏整体拒绝（CLI 层）：macro run 非法宏 → 非零退出、明确报错，
      白盒断言未发出任何 /v1/input 请求（审计条目数不变）；--speed 越界、
      坏 JSON 同样本地拒绝

测试安全红线：自动用例的真实注入只允许 move（坐标 1..4 的极小位移，C6 同款
安全口径）；禁止真实 click/type/key 落到活桌面；不触碰真实
%LOCALAPPDATA%\\CrossDevice 与仓库 data/（node 全部临时 config 目录 +
LOCALAPPDATA 覆盖，xd 注册表打补丁到临时目录）。

【真钩子路径的人工核对说明（不在自动断言内）】
低级钩子的真实采集无法无人值守自动化验证（会捕获真实键鼠）。人工核对步骤：
  1) 空闲桌面运行 py xd.py macro rec manual.json --seconds 8，期间缓慢移动
     鼠标、单击与双击、滚动滚轮、输入几个字符并按一次 ctrl+s；
  2) 打开 manual.json 核对：move 已按位移 ≥8px 或 ≥300ms 采样去抖；双击合并
     为 doubleclick；连续字符合并为 type；ctrl+s 为 key 动作；相邻动作带
     delay_ms；录制期间每 2 秒打印事件计数提示；
  3) 用 py xd.py macro run <测试设备> manual.json 回放，核对动作顺序与节奏
     一致；录制忽略注入事件，回放不会被自录进去。
注意：录制会捕获本机所有键鼠输入（含终端窗口的键盘输入）；F 功能键、输入法
组字键等被控端按键白名单不含的按键会被跳过并在结束时如实提示。

复用 smoke_s1/smoke_s2 脚手架（NODE_PY / S2Node / raw2 / 证书 / 令牌 /
gen_cert / free_port / write_json / run_xd / dev_dict）。
仅标准库。运行：py tests/smoke_s6.py [--keep]
"""

import argparse
import json
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path

sys.dont_write_bytecode = True      # 不在仓库中生成 __pycache__

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import smoke_s1                     # noqa: E402  复用 S1 脚手架（run_xd/gen_cert/...）
import smoke_s2                     # noqa: E402  复用 S2 脚手架（S2Node/raw2/node_tokens）
import xd                           # noqa: E402  白盒（validate_macro/plan/segments/...）

HOST = smoke_s1.HOST
TOKEN_DEFAULT = smoke_s1.TOKEN_DEFAULT
TOKEN_TESTER = smoke_s1.TOKEN_TESTER
NODE_PY = smoke_s1.NODE_PY

gen_cert = smoke_s1.gen_cert
write_json = smoke_s1.write_json
free_port = smoke_s1.free_port
run_xd = smoke_s1.run_xd
err_code = smoke_s1.err_code
S2Node = smoke_s2.S2Node
raw2 = smoke_s2.raw2
jdata = smoke_s2.jdata
dev_dict = smoke_s2.dev_dict
node_tokens = smoke_s2.node_tokens

RESULTS = []


def record(code, title, ok, evidence):
    RESULTS.append((code, title, bool(ok)))
    evidence = " ".join(str(evidence).split())
    print("%s %s %s（%s）" % (code, title, "PASS" if ok else "FAIL", evidence))


def make_node(tag, cert, key, extra_cfg=None):
    """起一个测试 node：config 目录 <tmp>/<tag>/，返回 (S2Node, cfg_dir, 端口)。"""
    cfg_dir = CTX.tmp / tag
    cfg_dir.mkdir(parents=True, exist_ok=True)
    cfg_file = cfg_dir / "node.json"
    cfg = {
        "version": 1,
        "tokens": node_tokens(),
        "tls": {"cert": str(cert), "key": str(key)},
        "audit": {"retention_days": 180},
    }
    if extra_cfg:
        cfg.update(extra_cfg)
    write_json(cfg_file, cfg)
    port = free_port()
    node = S2Node(tag, CTX.tmp, ["--config", str(cfg_file), "--port", str(port)])
    node.ready(TOKEN_DEFAULT, port)
    return node, cfg_dir, port


def audit_inputs(cfg_dir, since):
    """读取 node 审计 jsonl，返回 since 之后的 POST /v1/input 条目（ts 升序）。"""
    entries = []
    for path in sorted((cfg_dir / "audit").glob("audit-*.jsonl")):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            if str(entry.get("action", "")) == "POST /v1/input" \
                    and isinstance(entry.get("ts"), (int, float)) \
                    and entry["ts"] >= since:
                entries.append(entry)
    entries.sort(key=lambda e: e["ts"])
    return entries


def seed_device(name, port, fingerprint):
    """往临时注册表登记设备条目（指纹预填，避免 TOFU 写盘路径干扰断言）。"""
    entry = {"name": name, "ip": HOST, "port": port, "token": TOKEN_DEFAULT,
             "identity": "default", "cert_fingerprint": fingerprint,
             "mac": "", "ips": [], "hmac_key": "",
             "added_at": time.time(), "last_seen": None, "info": {}}
    xd.registry_update(lambda reg: reg["devices"].__setitem__(name, entry))


def tester_acquire(port, mode="acquire"):
    """以第二身份（tester）对 /v1/input 发空动作请求，返回 (状态码, 错误码)。"""
    st, _, body = raw2(HOST, port, "POST", "/v1/input", token=TOKEN_TESTER,
                       payload={"actions": []},
                       headers={"X-Input-Lease": mode}, timeout=10)
    return st, err_code(body)


# ---- 用例 ------------------------------------------------------------------

def m1_validate(ctx, opts):
    """M1 宏格式严格校验（白盒）：合法通过并规范化；非法逐项整体拒绝。"""
    notes = []
    legal = {"version": 1, "name": "demo", "actions": [
        {"type": "click", "x": 10, "y": 20},
        {"type": "doubleclick", "x": 1, "y": 2, "button": "right"},
        {"type": "move", "x": 0, "y": 0, "delay_ms": 100},
        {"type": "wheel", "delta": -360},
        {"type": "type", "text": "hello 你好"},
        {"type": "key", "key": "ctrl+shift+esc"},
        {"delay_ms": 500},
    ]}
    norm = xd.validate_macro(legal)
    ok_pass = (norm["version"] == 1 and norm["name"] == "demo"
               and norm["actions"][0]["button"] == "left"
               and "delay_ms" not in norm["actions"][0]
               and norm["actions"][5]["key"] == "ctrl+shift+esc"
               and norm["actions"][6] == {"delay_ms": 500}
               and set(norm["actions"][1]) == {"type", "x", "y", "button"})
    notes.append("合法宏通过=%s（button 默认=%s，未知键已剥离=%s）"
                 % (ok_pass, norm["actions"][0].get("button"),
                    set(norm["actions"][1]) == {"type", "x", "y", "button"}))
    ok_empty = isinstance(xd.validate_macro({"version": 1, "actions": []}), dict)
    notes.append("空 actions 合法=%s" % ok_empty)

    bad_cases = [
        ("未知动作类型", {"version": 1, "actions": [{"type": "format", "x": 1}]},
         "未知动作类型"),
        ("缺必填字段", {"version": 1, "actions": [{"type": "click", "x": 1}]},
         "缺少必填字段"),
        ("x 类型不对", {"version": 1, "actions": [{"type": "move", "x": "1", "y": 1}]},
         "必须是整数"),
        ("x 越界", {"version": 1, "actions": [{"type": "move", "x": 100001, "y": 1}]},
         "超出允许范围"),
        ("x 负数", {"version": 1, "actions": [{"type": "move", "x": -1, "y": 0}]},
         "超出允许范围"),
        ("布尔冒充整数", {"version": 1, "actions": [{"type": "move", "x": True, "y": 1}]},
         "必须是整数"),
        ("delay 越界", {"version": 1, "actions": [{"delay_ms": 600001}]},
         "超出允许范围"),
        ("delta 越界", {"version": 1, "actions": [{"type": "wheel", "delta": 100001}]},
         "超出允许范围"),
        ("text 过长", {"version": 1, "actions": [{"type": "type", "text": "x" * 10001}]},
         "text"),
        ("key 为空", {"version": 1, "actions": [{"type": "key", "key": ""}]}, "key"),
        ("坏 version", {"version": 2, "actions": []}, "version"),
        ("缺 version", {"actions": []}, "version"),
        ("version 字符串", {"version": "1", "actions": []}, "version"),
        ("顶层非对象", [1, 2], "顶层"),
        ("actions 非数组", {"version": 1, "actions": {"a": 1}}, "actions"),
        ("动作非对象", {"version": 1, "actions": ["move"]}, "必须是对象"),
        ("独立延迟步夹带字段", {"version": 1, "actions": [{"delay_ms": 1, "x": 2}]},
         "未知字段"),
        ("未知字段", {"version": 1,
                      "actions": [{"type": "move", "x": 1, "y": 1, "loop": 3}]},
         "未知字段"),
        ("button 非法", {"version": 1,
                         "actions": [{"type": "click", "x": 1, "y": 1,
                                      "button": "back"}]}, "button"),
        ("动作缺 type", {"version": 1, "actions": [{"x": 1}]}, "缺少 type"),
    ]
    rejected = []
    for label, data, expect_sub in bad_cases:
        try:
            xd.validate_macro(data)
            rejected.append("%s(未拒绝)" % label)
        except ValueError as exc:
            if expect_sub not in str(exc):
                rejected.append("%s(报错不含 %r：%r)" % (label, expect_sub,
                                                        str(exc)[:60]))
    ok_reject = not rejected
    notes.append("非法用例 %d/%d 整体拒绝且报错明确%s"
                 % (len(bad_cases) - len(rejected), len(bad_cases),
                    ("；问题项：" + "、".join(rejected)) if rejected else ""))

    ok_file = ok_json = False
    try:
        xd.load_macro(ctx.tmp / "no_such_macro_s6.json")
    except ValueError as exc:
        ok_file = "不存在" in str(exc)
    bad_json = ctx.tmp / "m1_bad.json"
    bad_json.write_text("{oops", encoding="utf-8")
    try:
        xd.load_macro(bad_json)
    except ValueError as exc:
        ok_json = "JSON" in str(exc)
    notes.append("文件缺失/坏 JSON 明确报错=%s/%s" % (ok_file, ok_json))
    return ok_pass and ok_empty and ok_reject and ok_file and ok_json, "；".join(notes)


def m2_replay_order(ctx, opts):
    """M2 回放顺序与 delay 节奏：真实 node + CLI 回放，审计 jsonl 为证据。"""
    notes = []
    node, cfg_dir, port = make_node("m2", ctx.cert1, ctx.key1)
    ctx.nodes.append(node)
    seed_device("m2dev", port, ctx.fp1)
    macro = {"version": 1, "name": "s6order", "actions": [
        {"type": "move", "x": 1, "y": 1},
        {"delay_ms": 400},
        {"type": "move", "x": 2, "y": 2},
        {"type": "move", "x": 3, "y": 3},
        {"delay_ms": 400},
        {"type": "move", "x": 4, "y": 4},
    ]}
    path = ctx.tmp / "m2_order.json"
    write_json(path, macro)
    started = time.time()
    out, _, error = run_xd(["macro", "run", "m2dev", str(path), "--speed", "1"],
                           xd.load_registry())
    wall = time.time() - started
    ok_cli = error is None and "回放完成" in out and "已释放输入租约" in out \
        and "3 段" in out
    notes.append("CLI 回放 ok=%s wall=%.2fs（%r）"
                 % (ok_cli, wall, (out or "").strip().splitlines()[-1][:60] if out else "-"))

    entries = audit_inputs(cfg_dir, started - 1)
    targets = [str(e.get("target")) for e in entries]
    expect = ["actions=move", "actions=move,move", "actions=move", "actions="]
    ok_seq = len(entries) >= 4 and targets[:4] == expect
    notes.append("审计 /v1/input targets=%s（期望 %s）" % (targets[:5], expect))

    gaps = [entries[i + 1]["ts"] - entries[i]["ts"] for i in range(2)] \
        if len(entries) >= 3 else []
    ok_gaps = len(gaps) == 2 and all(g >= 0.35 for g in gaps)
    notes.append("段间 ts 间隔=%s（期望 ≥0.4s，容差 0.05s）"
                 % ["%.2fs" % g for g in gaps])
    ok_wall = wall >= 0.75
    notes.append("墙钟 %.2fs ≥ sum(delay)/speed=0.8s-%s" % (wall, "抖动余量"))

    # 正常结束自动 release：若未释放，default 仍持租约（lease 60s）→ tester 会 409
    st, code = tester_acquire(port)
    ok_release = st == 200
    notes.append("回放结束后 tester acquire → %s/%s（证明已 release）" % (st, code))
    if st == 200:
        tester_acquire(port, "release")   # 清场（tester 释放自身租约）
    return ok_cli and ok_seq and ok_gaps and ok_wall and ok_release, "；".join(notes)


def m3_lease_interrupt(ctx, opts):
    """M3 租约全程持有与中断释放：段间第二身份 409 + 中断注入后 release。"""
    notes = []
    node, _, port = make_node("m3", ctx.cert1, ctx.key1)
    ctx.nodes.append(node)
    dev = dev_dict(port, ctx.fp1)
    macro = {"version": 1, "name": "s6lease", "actions": [
        {"type": "move", "x": 1, "y": 1}, {"delay_ms": 200},
        {"type": "move", "x": 2, "y": 2}, {"delay_ms": 200},
        {"type": "move", "x": 3, "y": 3},
    ]}
    plan = xd.macro_plan(xd.validate_macro(macro)["actions"], 1.0)

    seen = []

    def sleeper(_seconds):
        time.sleep(0.05)                # 实际节奏不重要，探测要快
        st, code = tester_acquire(port)
        seen.append((st, code))

    xd.macro_run_segments(dev, plan, sleeper=sleeper)
    ok_hold = bool(seen) and all(st == 409 and code == "INPUT_LEASE_TAKEN"
                                 for st, code in seen)
    notes.append("回放期间 tester acquire ×%d → %s（租约被宏回放全程持有）"
                 % (len(seen), seen[0] if seen else "-"))
    st_after, _ = tester_acquire(port)
    ok_after = st_after == 200          # 回放结束已 release，tester 可获得
    if st_after == 200:
        tester_acquire(port, "release")
    notes.append("回放结束后 tester acquire → %s（正常结束已 release）" % st_after)

    # —— 中断释放白盒：记录型 sender + KeyboardInterrupt / RuntimeError 桩 ——
    def make_sender(fail_at, exc):
        calls = []

        def sender(_device, method, path, payload=None, timeout=30, raw=False,
                   trust=False, extra_headers=None):
            calls.append((method, path, dict(extra_headers or {}), payload))
            if len(calls) == fail_at:
                raise exc
            return {"sent": [], "interactive": True, "locked": False}
        return calls, sender

    stub_dev = {"name": "", "ip": HOST, "port": 0, "token": "x",
                "identity": "default", "cert_fingerprint": ""}
    ok_interrupt = True
    for label, fail_at, exc, expect_exc in [
        ("KeyboardInterrupt", 3, KeyboardInterrupt(), KeyboardInterrupt),
        ("RuntimeError(中途409语义)", 2, RuntimeError("INPUT_LEASE_TAKEN: 已被抢占"),
         RuntimeError),
    ]:
        calls, sender = make_sender(fail_at, exc)
        raised = None
        try:
            xd.macro_run_segments(stub_dev, plan, sender=sender)
        except BaseException as caught:      # 故意宽捕获：验证原样抛出
            raised = caught
        last = calls[-1] if calls else None
        ok_release_call = bool(last) and last[0] == "POST" \
            and last[1] == "/v1/input" \
            and last[2].get("X-Input-Lease") == "release" \
            and last[3] == {"actions": []}
        ok_type = isinstance(raised, expect_exc)
        ok_calls = len(calls) == fail_at + 1
        ok_interrupt = ok_interrupt and ok_release_call and ok_type and ok_calls
        notes.append("%s 桩：中断于第 %d 次发送 → 随后发出 release=%s"
                     "（%s，共 %d 次调用）"
                     % (label, fail_at, ok_release_call,
                        type(raised).__name__ if raised else "未抛出", len(calls)))
    return ok_hold and ok_after and ok_interrupt, "；".join(notes)


def m4_record_mapping(ctx, opts):
    """M4 录制白盒：合成事件流 → 动作序列（去抖/聚合/间隔→delay_ms）。"""
    notes = []
    t0 = 100.0
    events = [
        {"kind": "move", "x": 500, "y": 500, "t": t0},
        {"kind": "move", "x": 503, "y": 501, "t": t0 + 0.010},   # 位移 3px < 8 → 丢弃
        {"kind": "move", "x": 540, "y": 500, "t": t0 + 0.050},   # 位移 40px ≥ 8 → 保留
        {"kind": "click", "x": 540, "y": 500, "button": "left", "t": t0 + 0.300},
        {"kind": "click", "x": 541, "y": 500, "button": "left",
         "t": t0 + 0.450},                                        # 双击聚合
        {"kind": "move", "x": 560, "y": 500, "t": t0 + 0.600},   # 位移 20px → 保留
        {"kind": "text", "text": "h", "t": t0 + 1.000},
        {"kind": "text", "text": "i", "t": t0 + 1.050},           # 聚合 type "hi"
        {"kind": "key", "key": "ctrl+s", "t": t0 + 1.600},        # 拆分 type，键动作
        {"kind": "wheel", "delta": -120, "t": t0 + 2.000},
    ]
    actions = xd.macro_events_to_actions(events)
    expect = [
        {"type": "move", "x": 500, "y": 500},
        {"type": "move", "x": 540, "y": 500, "delay_ms": 50},
        {"type": "doubleclick", "x": 540, "y": 500, "button": "left", "delay_ms": 250},
        {"type": "move", "x": 560, "y": 500, "delay_ms": 150},
        {"type": "type", "text": "hi", "delay_ms": 400},
        {"type": "key", "key": "ctrl+s", "delay_ms": 550},
        {"type": "wheel", "delta": -120, "delay_ms": 400},
    ]
    ok_map = actions == expect
    notes.append("事件映射=%s（得到 %s 个动作：%s）"
                 % (ok_map, len(actions),
                    "/".join(a["type"] for a in actions)))

    slow = [
        {"kind": "move", "x": 0, "y": 0, "t": 200.0},
        {"kind": "move", "x": 3, "y": 0, "t": 200.050},   # 位移 <8、间隔 <300 → 丢弃
        {"kind": "move", "x": 5, "y": 0, "t": 200.400},   # 间隔 ≥300 → 时间阈值采样
        {"kind": "move", "x": 6, "y": 0, "t": 200.410},   # 又不满足 → 丢弃
    ]
    slow_actions = xd.macro_events_to_actions(slow)
    ok_slow = (len(slow_actions) == 2 and slow_actions[1].get("x") == 5
               and slow_actions[1].get("delay_ms") == 400)
    notes.append("时间阈值采样（慢速微移仍保留）=%s（%s）"
                 % (ok_slow, [(a.get("x"), a.get("delay_ms")) for a in slow_actions]))

    ok_validate = bool(xd.validate_macro({"version": 1, "actions": actions}))
    plan = xd.macro_plan(actions, 2.0)
    waits = [round(step["wait"], 4) for step in plan]
    ok_plan = (len(plan) == 7 and waits == [0.0, 0.025, 0.125, 0.075, 0.2, 0.275, 0.2])
    notes.append("产物过同一套校验=%s；分段 ×speed=2 → %d 段 waits=%s（=%s）"
                 % (ok_validate, len(plan), waits, ok_plan))

    plan_full = xd.macro_plan(actions, 1.0)
    notes.append("speed=1 waits=%s（delay 原值）"
                 % [round(step["wait"], 4) for step in plan_full])
    ok_plan_full = [round(s["wait"], 4) for s in plan_full] \
        == [0.0, 0.05, 0.25, 0.15, 0.4, 0.55, 0.4]
    return ok_map and ok_slow and ok_validate and ok_plan and ok_plan_full, "；".join(notes)


def m5_invalid_macro_rejected(ctx, opts):
    """M5 非法宏整体拒绝（CLI 层）：非零退出 + 明确报错 + 未发任何 /v1/input。"""
    notes = []
    node, cfg_dir, port = make_node("m5", ctx.cert1, ctx.key1)
    ctx.nodes.append(node)
    seed_device("m5dev", port, ctx.fp1)

    bad = {"version": 1, "name": "bad", "actions": [{"type": "format", "x": 1}]}
    bad_path = ctx.tmp / "m5_bad_macro.json"
    write_json(bad_path, bad)
    since = time.time() - 1
    out, _, error = run_xd(["macro", "run", "m5dev", str(bad_path)],
                           xd.load_registry())
    ok_reject = (error is not None and "宏校验失败" in str(error)
                 and "未知动作类型" in str(error))
    notes.append("CLI 非法宏 → 非零退出=%s 明确报错=%r"
                 % (ok_reject, str(error)[:70] if error else "-"))

    ok_no_req = not audit_inputs(cfg_dir, since)
    notes.append("审计 /v1/input 条目数=%d（期望 0，未发出任何请求）"
                 % len(audit_inputs(cfg_dir, since)))

    good = {"version": 1, "actions": [{"type": "move", "x": 1, "y": 1}]}
    good_path = ctx.tmp / "m5_good_macro.json"
    write_json(good_path, good)
    _, _, speed_err = run_xd(["macro", "run", "m5dev", str(good_path), "--speed", "0"],
                             xd.load_registry())
    ok_speed = speed_err is not None and "speed" in str(speed_err)
    notes.append("--speed 0 → 本地拒绝=%s（%r）"
                 % (ok_speed, str(speed_err)[:50] if speed_err else "-"))

    broken = ctx.tmp / "m5_broken.json"
    broken.write_text("{oops", encoding="utf-8")
    _, _, json_err = run_xd(["macro", "run", "m5dev", str(broken)],
                            xd.load_registry())
    ok_json = json_err is not None and "JSON" in str(json_err)
    notes.append("坏 JSON → 明确报错=%s（%r）"
                 % (ok_json, str(json_err)[:50] if json_err else "-"))

    ok_still_zero = len(audit_inputs(cfg_dir, since)) == 0
    return ok_reject and ok_no_req and ok_speed and ok_json and ok_still_zero, "；".join(notes)


# ---- 主流程 ----------------------------------------------------------------

class _Ctx:
    pass


CTX = _Ctx()


def main():
    parser = argparse.ArgumentParser(
        description="smoke_s6：B17 宏录制与回放自测（纯控制端 CLI，协议零变更）")
    parser.add_argument("--keep", action="store_true", help="保留临时目录")
    opts = parser.parse_args()

    tmp = Path(tempfile.mkdtemp(prefix="smoke_s6_"))
    # 断言可能读 node 子进程输出：强制子进程不缓冲（S2Node 复制 os.environ 传入）
    os.environ["PYTHONUNBUFFERED"] = "1"
    ctx = CTX
    ctx.tmp = tmp
    ctx.nodes = []

    print("smoke_s6（B17 宏录制与回放，纯控制端 CLI，协议零变更）")
    print("临时目录：%s" % tmp)
    print("node.py：%s" % NODE_PY)
    print("-" * 76)

    exit_code = 1
    try:
        tls1 = tmp / "tls1"
        tls1.mkdir(parents=True, exist_ok=True)
        ctx.cert1, ctx.key1 = tls1 / "cert.pem", tls1 / "key.pem"
        ctx.fp1 = gen_cert(tls1)
        print("证书指纹：%s" % ctx.fp1)

        # xd 注册表打补丁到临时目录（绝不触碰仓库 data/ 与真实 %LOCALAPPDATA%）
        xd.REGISTRY = tmp / "registry" / "devices.json"
        xd.DATA = xd.REGISTRY.parent
        xd.save_registry({"devices": {}})

        for code, title, fn in [
            ("M1", "宏格式严格校验", m1_validate),
            ("M2", "回放顺序与 delay 节奏", m2_replay_order),
            ("M3", "租约全程持有与中断释放", m3_lease_interrupt),
            ("M4", "录制事件映射白盒", m4_record_mapping),
            ("M5", "非法宏整体拒绝", m5_invalid_macro_rejected),
        ]:
            try:
                ok, evidence = fn(ctx, opts)
            except Exception as exc:
                ok, evidence = False, "测试框架异常：%r" % (exc,)
            record(code, title, ok, evidence)

        passed = sum(1 for _, _, ok in RESULTS if ok)
        print("-" * 76)
        print("S6 自测：%d/%d 通过" % (passed, len(RESULTS)))
        for code, title, ok in RESULTS:
            if not ok:
                print("  未通过：%s %s" % (code, title))
        exit_code = 0 if passed == len(RESULTS) else 1
    finally:
        for node in ctx.nodes:
            try:
                node.stop()
            except Exception:
                pass
        if opts.keep:
            print("临时目录保留：%s" % tmp)
        else:
            shutil.rmtree(tmp, ignore_errors=True)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
