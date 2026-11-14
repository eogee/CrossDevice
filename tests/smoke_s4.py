#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CrossDevice M4 阶段一键自测（验收载体，覆盖契约 V1.5 §23 设备一次确认配对）。

用法：
    py tests/smoke_s4.py                 # 全量：P1–P6 / N1–N7 + 末尾 smoke_s1/s2/s3 回归
    py tests/smoke_s4.py --skip-s1       # 跳过末尾 smoke_s1 回归（调试用，不计失败）
    py tests/smoke_s4.py --skip-s2       # 跳过末尾 smoke_s2 回归（调试用，不计失败）
    py tests/smoke_s4.py --skip-s3       # 跳过末尾 smoke_s3 回归（调试用，不计失败）
    py tests/smoke_s4.py --keep          # 保留临时目录便于排障
    py tests/smoke_s4.py --node X        # 指定 node.py 路径覆盖（默认 node/node.py）

用例编号：
    P1–P6  正向：begin → 回环确认（session/approve）→ confirm 签发 → 新令牌可用；
           幂等 approve；xd add 手工令牌路径兼容（E-02）。
    N1–N7  负例：本地拒绝、pending 超时、码过期、猜码超限作废、begin 限频 429、
           回环限定（白盒 + 本机私网 IP 黑盒佐证，对照测试要求口径 4）、
           非法参数不计次。审计核验（identity=""、§8.3 target、码与 token 不落盘）贯穿。
    C      末尾子进程回归：smoke_s1 8/8、smoke_s2 10/10、smoke_s3 10/10。

隔离性（绝不触碰真实 %LOCALAPPDATA%\\CrossDevice 与仓库 data/）：
    - 证书（tools/gen_cert.ps1）、node 配置、审计目录全部落在临时目录；
    - node 子进程以覆盖后的 LOCALAPPDATA 启动兜底；
    - xd 的注册表路径（xd.REGISTRY / xd.DATA）打补丁到临时文件；
    - 三个 node 实例（main/fast/rate）独立端口与配置目录：
      main  pair.begin_interval=0（正向链路编排，限频由 rate 实例专测）；
      fast  pair.pending_ttl=5 / code_ttl=5 / begin_interval=0（超时与过期负例）；
      rate  默认 pair 配置（begin_interval=10）且监听 0.0.0.0（N5 限频 + N6 回环黑盒）。
    - finally 中终止全部 node 子进程并清理临时目录。

仅标准库。复用 smoke_s1 / smoke_s2 脚手架。
"""

import argparse
import http.client
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.dont_write_bytecode = True      # 不在仓库中生成 __pycache__

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import smoke_s1                     # noqa: E402  复用 S1 脚手架
import smoke_s2                     # noqa: E402  复用 S2 脚手架（S2Node 等）
import xd                           # noqa: E402  P6 手工路径回归

# ---- 复用脚手架 -------------------------------------------------------------
S2Node = smoke_s2.S2Node
raw_request = smoke_s1.raw_request          # 带防重放头的裸请求（P4/P6/info 等）
err_code = smoke_s1.err_code
gen_cert = smoke_s1.gen_cert
pem_sha256 = smoke_s1.pem_sha256
write_json = smoke_s1.write_json
free_port = smoke_s1.free_port
run_xd = smoke_s1.run_xd
tls_context = smoke_s1.tls_context
HOST = smoke_s1.HOST
TOKEN_DEFAULT = smoke_s1.TOKEN_DEFAULT
NODE_PY = smoke_s1.NODE_PY

RESULTS = []


def record(code, title, ok, evidence):
    RESULTS.append((code, title, bool(ok)))
    evidence = " ".join(str(evidence).split())
    print("%s %s %s（%s）" % (code, title, "PASS" if ok else "FAIL", evidence))


# --------------------------------------------------------------------------
# 基础设施
# --------------------------------------------------------------------------

def pair_request(ip, port, method, path, payload=None, timeout=8):
    """pair 族裸请求（契约 §23.1）：不带令牌与防重放头（该族免鉴权免防重放，
    请求被拒即说明 guard 变体缺失），完全控制请求体。"""
    conn = http.client.HTTPSConnection(ip, port, context=tls_context(), timeout=timeout)
    try:
        conn.connect()
        hdrs = {}
        body = None
        if payload is not None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            hdrs["Content-Type"] = "application/json"
        conn.request(method, path, body=body, headers=hdrs)
        resp = conn.getresponse()
        data = resp.read()
        return resp.status, data
    finally:
        try:
            conn.close()
        except Exception:
            pass


def pdata(body):
    """裸响应体 → 包络 data（非成功包络返回 None）。"""
    try:
        parsed = json.loads(body.decode("utf-8"))
        return parsed.get("data") if parsed.get("ok") else None
    except Exception:
        return None


def pmessage(body):
    """失败包络的 error.message（非失败返回 None）。"""
    try:
        parsed = json.loads(body.decode("utf-8"))
        return (parsed.get("error") or {}).get("message") if not parsed.get("ok") else None
    except Exception:
        return None


def audit_entries(tmp):
    """汇总临时目录下全部审计文件条目（按 ts 升序）。"""
    entries = []
    for path in sorted(tmp.rglob("audit-*.jsonl")):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except ValueError:
                continue
            if isinstance(item, dict):
                entries.append(item)
    entries.sort(key=lambda e: e.get("ts") if isinstance(e.get("ts"), (int, float)) else 0)
    return entries


def pick_audit(entries, since, action_sub, result=None):
    """按时间下限 + action 子串（+ 可选状态码）抽取审计条目。"""
    hits = []
    for entry in entries:
        ts = entry.get("ts")
        if not isinstance(ts, (int, float)) or ts < since:
            continue
        if action_sub not in str(entry.get("action", "")):
            continue
        if result is not None and entry.get("result") != result:
            continue
        hits.append(entry)
    return hits


def wait_audit(tmp, since, action_sub, result=None, count=1, timeout=4.0):
    """轮询审计条目直至出现（审计在响应发出后的 finally 落盘，客户端读文件可能
    早于服务端写完——轮询消除竞态，超时返回当前已有条目）。"""
    deadline = time.time() + timeout
    while True:
        hits = pick_audit(audit_entries(tmp), since, action_sub, result=result)
        if len(hits) >= count or time.time() >= deadline:
            return hits
        time.sleep(0.2)


def is_16hex(value):
    return isinstance(value, str) and bool(re.fullmatch(r"[0-9a-f]{16}", value))


def audit_raw_text(tmp):
    """全部审计文件原文（token 泄漏扫描用：32hex 全文比对无误报）。"""
    chunks = []
    for path in sorted(tmp.rglob("audit-*.jsonl")):
        try:
            chunks.append(path.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            continue
    return "".join(chunks)


def pair_targets_bad(entries, sids, names):
    """pair 族审计 target 结构核验（§8.3 五行口径）：target ∈ {"", "session=<已知 sid>",
    "name=<已知名>"}。target 是配对码唯一可能的落点，逐一比对已知值即可确定性证明
    "配对码值永不落审计"（子串扫描会与 16hex session_id 误撞，不采用）。"""
    allowed = {""} | {"session=%s" % s for s in sids} | {"name=%s" % n for n in names}
    bad = []
    for entry in entries:
        action = str(entry.get("action", ""))
        if action.startswith("POST /v1/pair") or action.startswith("GET /v1/pair"):
            if entry.get("target") not in allowed:
                bad.append("%s→%r" % (action, entry.get("target")))
    return bad


class Ctx:
    pass


# --------------------------------------------------------------------------
# P1–P6 正向
# --------------------------------------------------------------------------

def p1_begin(ctx, opts):
    """P1 begin 正向：POST /v1/pair/begin（免鉴权免防重放头）→ 200
    {session_id(16hex), state=pending, expires_at}；审计 begin 条目 identity=""/target 空。"""
    t0 = time.time() - 1
    ok_req = False
    try:
        status, body = pair_request(HOST, ctx.port_a, "POST", "/v1/pair/begin", payload={})
        data = pdata(body)
        ok_req = (status == 200 and isinstance(data, dict)
                  and is_16hex(data.get("session_id"))
                  and data.get("state") == "pending"
                  and isinstance(data.get("expires_at"), (int, float)))
        ev_req = ("POST /v1/pair/begin → HTTP %s，session_id 16hex=%s，state=%s，"
                  "expires_at=%s" % (status, is_16hex((data or {}).get("session_id")),
                                     (data or {}).get("state"),
                                     (data or {}).get("expires_at")))
        if ok_req:
            ctx.sess_main = data
            ctx.all_sids.append(data["session_id"])
    except Exception as exc:
        ev_req = "begin 异常（node 侧）：%r" % (exc,)

    ok_audit = False
    try:
        hits = wait_audit(ctx.tmp, t0, "POST /v1/pair/begin", result=200)
        e = hits[-1] if hits else {}
        ok_audit = bool(hits) and e.get("identity") == "" and e.get("target") == ""
        ev_audit = ("审计 begin 条目 identity=%r target=%r result=%s"
                    % (e.get("identity"), e.get("target"), e.get("result")))
    except Exception as exc:
        ev_audit = "审计核验异常：%r" % (exc,)
    return ok_req and ok_audit, "%s；%s" % (ev_req, ev_audit)


def p2_confirm_ui(ctx, opts):
    """P2 回环确认：GET session（pending，不含 code、含 source_ip）→ approve 生成
    6 位码 → 再 GET approved 含 code 与 attempts_left=5；审计 approve target=session=。"""
    t0 = time.time() - 1
    sid = ctx.sess_main["session_id"]
    ok_get1 = False
    try:
        status, body = pair_request(HOST, ctx.port_a, "GET", "/v1/pair/session")
        data = pdata(body)
        ok_get1 = (status == 200 and isinstance(data, dict)
                   and data.get("state") == "pending"
                   and data.get("session_id") == sid
                   and data.get("source_ip") == HOST
                   and "code" not in data)
        ev_get1 = ("GET session（pending）→ HTTP %s，state=%s，source_ip=%s，"
                   "不含 code=%s" % (status, (data or {}).get("state"),
                                     (data or {}).get("source_ip"),
                                     "code" not in (data or {})))
    except Exception as exc:
        ev_get1 = "GET session 异常：%r" % (exc,)

    ok_approve = False
    try:
        status, body = pair_request(HOST, ctx.port_a, "POST", "/v1/pair/approve", payload={})
        data = pdata(body)
        code = (data or {}).get("code")
        ok_approve = (status == 200 and isinstance(data, dict)
                      and isinstance(code, str) and re.fullmatch(r"[0-9]{6}", code)
                      and data.get("session_id") == sid
                      and isinstance(data.get("expires_at"), (int, float)))
        ev_approve = "approve → HTTP %s，code 6 位数字=%s，expires_at=%s" % (
            status, bool(isinstance(code, str) and re.fullmatch(r"[0-9]{6}", code or "")),
            (data or {}).get("expires_at"))
        if ok_approve:
            ctx.code_main = code
    except Exception as exc:
        ev_approve = "approve 异常：%r" % (exc,)

    ok_get2 = False
    try:
        status, body = pair_request(HOST, ctx.port_a, "GET", "/v1/pair/session")
        data = pdata(body)
        ok_get2 = (status == 200 and isinstance(data, dict)
                   and data.get("state") == "approved"
                   and data.get("code") == ctx.code_main
                   and data.get("attempts_left") == ctx.max_attempts
                   and data.get("code_expires_at") == data.get("expires_at"))
        ev_get2 = "再 GET → state=%s，code 回读一致=%s，attempts_left=%s（max_attempts=%d）" % (
            (data or {}).get("state"), (data or {}).get("code") == ctx.code_main,
            (data or {}).get("attempts_left"), ctx.max_attempts)
    except Exception as exc:
        ev_get2 = "再 GET 异常：%r" % (exc,)

    ok_audit = False
    try:
        hits = wait_audit(ctx.tmp, t0, "POST /v1/pair/approve", result=200)
        e = hits[-1] if hits else {}
        ok_audit = (bool(hits) and e.get("identity") == ""
                    and e.get("target") == "session=%s" % sid)
        ev_audit = ("审计 approve 条目 identity=%r target=%r"
                    % (e.get("identity"), e.get("target")))
    except Exception as exc:
        ev_audit = "审计核验异常：%r" % (exc,)
    return ok_get1 and ok_approve and ok_get2 and ok_audit, \
        "%s；%s；%s；%s" % (ev_get1, ev_approve, ev_get2, ev_audit)


def p3_confirm_sign(ctx, opts):
    """P3 confirm 签发：正确码 + name → 200 {token(32hex), identity, device_id(12hex),
    cert_fingerprint(=证书实测指纹), node_version=0.5.0}；重复 confirm → 404 已消费。"""
    t0 = time.time() - 1
    ok_sign = False
    try:
        status, body = pair_request(HOST, ctx.port_a, "POST", "/v1/pair/confirm",
                                    payload={"code": ctx.code_main, "name": "pairdev"})
        data = pdata(body)
        token = (data or {}).get("token")
        fp = (data or {}).get("cert_fingerprint")
        ok_sign = (status == 200 and isinstance(data, dict)
                   and isinstance(token, str) and re.fullmatch(r"[0-9a-f]{32}", token)
                   and data.get("identity") == "pairdev"
                   and isinstance(data.get("device_id"), str)
                   and bool(re.fullmatch(r"[0-9a-f]{12}", data.get("device_id") or ""))
                   and fp == ctx.fp1 and len(fp or "") == 64
                   and data.get("node_version") == "0.5.0")
        ev_sign = ("confirm → HTTP %s，token 32hex=%s，identity=%s，device_id 12hex=%s，"
                   "cert_fingerprint 与 TLS 证书实测一致=%s，node_version=%s"
                   % (status, bool(re.fullmatch(r"[0-9a-f]{32}", token or "")),
                      (data or {}).get("identity"),
                      bool(re.fullmatch(r"[0-9a-f]{12}", (data or {}).get("device_id") or "")),
                      fp == ctx.fp1, (data or {}).get("node_version")))
        if ok_sign:
            ctx.token_new = token
            ctx.device_id_new = data["device_id"]
    except Exception as exc:
        ev_sign = "confirm 异常：%r" % (exc,)

    ok_repeat = False
    try:
        status, body = pair_request(HOST, ctx.port_a, "POST", "/v1/pair/confirm",
                                    payload={"code": ctx.code_main, "name": "pairdev"})
        ok_repeat = status == 404 and err_code(body) == "PAIR_NO_SESSION"
        ev_repeat = "重复 confirm（已消费）→ HTTP %s code=%s" % (status, err_code(body))
    except Exception as exc:
        ev_repeat = "重复 confirm 异常：%r" % (exc,)

    ok_audit = False
    ok_leak = False
    try:
        hits = wait_audit(ctx.tmp, t0, "POST /v1/pair/confirm", result=200, count=1)
        entries = audit_entries(ctx.tmp)
        e = hits[-1] if hits else {}
        ok_audit = (bool(hits) and e.get("identity") == ""
                    and e.get("target") == "name=pairdev")
        ev_audit = "审计 confirm 成功条目 identity=%r target=%r" % (
            e.get("identity"), e.get("target"))
        text = "".join(str(e.get("target", "")) + str(e.get("action", ""))
                       for e in entries if isinstance(e.get("ts"), (int, float))
                       and e.get("ts") >= t0)
        ok_leak = bool(ctx.code_main) and ctx.code_main not in text
        ev_leak = "审计动作/target 中不出现配对码=%s" % ok_leak
    except Exception as exc:
        ev_audit = ev_leak = "审计核验异常：%r" % (exc,)
    ctx.all_names.add("pairdev")
    return ok_sign and ok_repeat and ok_audit and ok_leak, \
        "%s；%s；%s；%s" % (ev_sign, ev_repeat, ev_audit, ev_leak)


def p4_new_token(ctx, opts):
    """P4 新令牌可用：新 token 调 /v1/exec（echo）与 /v1/info 成功；
    identity_count 增 1（E-02 与既有身份并存）；审计出现 pairdev 的记录且无 token。"""
    t0 = time.time() - 1
    ok_info = False
    try:
        status, body = raw_request(HOST, ctx.port_a, "GET", "/v1/info",
                                   token=ctx.token_new, timeout=8)
        data = pdata(body)
        ok_info = (status == 200 and isinstance(data, dict)
                   and data.get("identity_count") == ctx.ident_count_before + 1
                   and data.get("device_id") == ctx.device_id_new)
        ev_info = ("/v1/info（新 token）→ HTTP %s，identity_count=%s（前值 %d，增 1=%s），"
                   "device_id 与 confirm 一致=%s"
                   % (status, (data or {}).get("identity_count"), ctx.ident_count_before,
                      (data or {}).get("identity_count") == ctx.ident_count_before + 1,
                      (data or {}).get("device_id") == ctx.device_id_new))
    except Exception as exc:
        ev_info = "/v1/info 异常：%r" % (exc,)

    ok_exec = False
    job_id = None
    try:
        status, body = raw_request(HOST, ctx.port_a, "POST", "/v1/exec",
                                   token=ctx.token_new,
                                   payload={"cmd": "echo s4_p4_ok", "timeout": 15},
                                   timeout=15)
        data = pdata(body)
        job_id = (data or {}).get("job_id")
        ok_created = status == 200 and isinstance(job_id, str) and bool(job_id)
        status2, body2 = raw_request(HOST, ctx.port_a, "GET",
                                     "/v1/job/%s?wait=15" % job_id,
                                     token=ctx.token_new, timeout=30)
        job = pdata(body2)
        ok_exec = (ok_created and status2 == 200 and isinstance(job, dict)
                   and job.get("status") == "done" and job.get("exit_code") == 0
                   and "s4_p4_ok" in str(job.get("stdout", ""))
                   and job.get("identity") == "pairdev")
        ev_exec = ("/v1/exec（新 token）→ job=%s status=%s exit=%s stdout 命中=%s，"
                   "任务 identity=%s"
                   % (bool(job_id), (job or {}).get("status"), (job or {}).get("exit_code"),
                      "s4_p4_ok" in str((job or {}).get("stdout", "")),
                      (job or {}).get("identity")))
    except Exception as exc:
        ev_exec = "exec 链路异常：%r" % (exc,)

    ok_audit = False
    ok_leak = False
    try:
        hits = wait_audit(ctx.tmp, t0, "POST /v1/exec", result=200)
        ok_audit = bool(hits) and hits[-1].get("identity") == "pairdev"
        ev_audit = ("审计 exec 条目 identity=%r（配对身份与既有身份并存）"
                    % hits[-1].get("identity") if hits else "未找到 exec 审计条目")
        ok_leak = ctx.token_new not in audit_raw_text(ctx.tmp)
        ev_leak = "审计全文不出现签发 token=%s" % ok_leak
    except Exception as exc:
        ev_audit = ev_leak = "审计核验异常：%r" % (exc,)
    return ok_info and ok_exec and ok_audit and ok_leak, \
        "%s；%s；%s；%s" % (ev_info, ev_exec, ev_audit, ev_leak)


def p5_idempotent(ctx, opts):
    """P5 幂等 approve：新会话 approve 两次返回同一 code 与 expires_at；末尾 reject 清场。"""
    t0 = time.time() - 1
    sid = code1 = code2 = None
    exp1 = exp2 = None
    ok_begin = ok_a1 = ok_a2 = ok_clean = False
    evs = []
    try:
        status, body = pair_request(HOST, ctx.port_a, "POST", "/v1/pair/begin", payload={})
        data = pdata(body)
        ok_begin = status == 200 and is_16hex((data or {}).get("session_id"))
        sid = (data or {}).get("session_id")
        if sid:
            ctx.all_sids.append(sid)
        evs.append("begin → HTTP %s（begin_interval=0 编排实例）" % status)

        status, body = pair_request(HOST, ctx.port_a, "POST", "/v1/pair/approve", payload={})
        data = pdata(body)
        ok_a1 = status == 200 and isinstance((data or {}).get("code"), str)
        code1, exp1 = (data or {}).get("code"), (data or {}).get("expires_at")

        status, body = pair_request(HOST, ctx.port_a, "POST", "/v1/pair/approve", payload={})
        data = pdata(body)
        ok_a2 = status == 200
        code2, exp2 = (data or {}).get("code"), (data or {}).get("expires_at")
        evs.append("两次 approve code 相同=%s expires_at 相同=%s（幂等，§23.3）"
                   % (code1 == code2, exp1 == exp2))
    except Exception as exc:
        evs.append("approve 幂等链路异常：%r" % (exc,))

    try:
        status, body = pair_request(HOST, ctx.port_a, "POST", "/v1/pair/reject", payload={})
        data = pdata(body)
        ok_clean = status == 200 and (data or {}).get("rejected") is True \
            and (data or {}).get("session_id") == sid
        evs.append("清场 reject → HTTP %s rejected=%s" % (status, (data or {}).get("rejected")))
    except Exception as exc:
        evs.append("清场 reject 异常：%r" % (exc,))

    ok_audit = False
    try:
        hits = wait_audit(ctx.tmp, t0, "POST /v1/pair/begin", result=200)
        e = hits[-1] if hits else {}
        ok_audit = bool(hits) and e.get("identity") == "" and e.get("target") == ""
        evs.append("审计 begin 条目 target=%r（begin 永不 set_target）" % e.get("target"))
    except Exception as exc:
        evs.append("审计核验异常：%r" % (exc,))
    return ok_begin and ok_a1 and ok_a2 and (code1 == code2) and (exp1 == exp2) \
        and ok_clean and ok_audit, "；".join(evs)


def p6_xd_add(ctx, opts):
    """P6 xd add 手工路径兼容（E-02 回归）：临时注册表 add（既有令牌）→ exec 成功；
    配对端点纯新增不影响既有 CLI。两次调用各自从盘载注册表（对齐真实 CLI 每次独立进程）。"""
    out, err, error = run_xd(["add", HOST, "--port", str(ctx.port_a),
                              "--token", TOKEN_DEFAULT, "--name", "manual4"],
                             xd.load_registry())
    ok_add = error is None and "已注册" in out
    ev_add = "xd add → %s（err=%r out=%r）" % ("成功" if ok_add else "失败",
                                              error, out.strip()[:60])
    out2, err2, error2 = run_xd(["exec", "manual4", "echo", "s4_p6_ok"],
                                xd.load_registry())
    ok_exec = error2 is None and "s4_p6_ok" in out2 and "退出码 0" in out2
    ev_exec = ("xd exec（手工令牌）→ 输出命中=%s 退出码 0=%s err=%r"
               % ("s4_p6_ok" in out2, "退出码 0" in out2, error2))
    return ok_add and ok_exec, "%s；%s" % (ev_add, ev_exec)


# --------------------------------------------------------------------------
# N1–N7 负例
# --------------------------------------------------------------------------

def n1_reject(ctx, opts):
    """N1 拒绝：begin → approve → reject → confirm（正确码）→ 404 PAIR_NO_SESSION；
    reject 后 begin 可立即创建新会话（终态被覆盖）。"""
    t0 = time.time() - 1
    sid = code = None
    evs = []
    ok_begin = ok_approve = ok_reject = ok_confirm = ok_rebegin = ok_clean = False
    try:
        status, body = pair_request(HOST, ctx.port_a, "POST", "/v1/pair/begin", payload={})
        sid = (pdata(body) or {}).get("session_id")
        ok_begin = status == 200 and is_16hex(sid)
        if sid:
            ctx.all_sids.append(sid)
        evs.append("begin → HTTP %s" % status)

        status, body = pair_request(HOST, ctx.port_a, "POST", "/v1/pair/approve", payload={})
        code = (pdata(body) or {}).get("code")
        ok_approve = status == 200 and bool(code)
        evs.append("approve → HTTP %s" % status)

        status, body = pair_request(HOST, ctx.port_a, "POST", "/v1/pair/reject", payload={})
        data = pdata(body)
        ok_reject = (status == 200 and (data or {}).get("rejected") is True
                     and (data or {}).get("session_id") == sid)
        evs.append("reject → HTTP %s rejected=%s session_id 回带=%s"
                   % (status, (data or {}).get("rejected"),
                      (data or {}).get("session_id") == sid))

        status, body = pair_request(HOST, ctx.port_a, "POST", "/v1/pair/confirm",
                                    payload={"code": code, "name": "x1"})
        ok_confirm = status == 404 and err_code(body) == "PAIR_NO_SESSION"
        ctx.all_names.add("x1")
        evs.append("正确码 confirm（已作废）→ HTTP %s code=%s" % (status, err_code(body)))

        status, body = pair_request(HOST, ctx.port_a, "POST", "/v1/pair/begin", payload={})
        new_sid = (pdata(body) or {}).get("session_id")
        ok_rebegin = status == 200 and is_16hex(new_sid) and new_sid != sid
        if new_sid:
            ctx.all_sids.append(new_sid)
        evs.append("reject 后立即 begin → HTTP %s 新会话=%s" % (status, is_16hex(new_sid)))

        status, body = pair_request(HOST, ctx.port_a, "POST", "/v1/pair/reject", payload={})
        ok_clean = status == 200
        evs.append("清场 reject → HTTP %s" % status)
    except Exception as exc:
        evs.append("N1 链路异常：%r" % (exc,))

    ok_audit = False
    try:
        rej = wait_audit(ctx.tmp, t0, "POST /v1/pair/reject", result=200, count=2)
        conf = wait_audit(ctx.tmp, t0, "POST /v1/pair/confirm", result=404)
        ok_audit = (any(e.get("target") == "session=%s" % sid for e in rej)
                    and bool(conf) and conf[-1].get("target") == ""
                    and conf[-1].get("identity") == "")
        evs.append("审计 reject 含 target='session=%s'=%s（首会话）；"
                   "confirm 失败条目 identity=%r target=%r"
                   % (sid, any(e.get("target") == "session=%s" % sid for e in rej),
                      conf[-1].get("identity") if conf else None,
                      conf[-1].get("target") if conf else None))
    except Exception as exc:
        evs.append("审计核验异常：%r" % (exc,))
    return (ok_begin and ok_approve and ok_reject and ok_confirm and ok_rebegin
            and ok_clean and ok_audit), "；".join(evs)


def n2_pending_timeout(ctx, opts):
    """N2 pending 超时：pair.pending_ttl=5 → begin → 等 6 秒 → approve → 404
    PAIR_NO_SESSION（惰性过期转移，§23.2）。"""
    t0 = time.time() - 1
    evs = []
    ok_begin = ok_approve = False
    try:
        status, body = pair_request(HOST, ctx.port_b, "POST", "/v1/pair/begin", payload={})
        ok_begin = status == 200
        sid = (pdata(body) or {}).get("session_id")
        if sid:
            ctx.all_sids.append(sid)
        evs.append("begin → HTTP %s（fast 实例 pending_ttl=5）" % status)
        time.sleep(6)
        status, body = pair_request(HOST, ctx.port_b, "POST", "/v1/pair/approve", payload={})
        ok_approve = status == 404 and err_code(body) == "PAIR_NO_SESSION"
        evs.append("等 6 秒后 approve → HTTP %s code=%s（message=%r）"
                   % (status, err_code(body), pmessage(body)))
    except Exception as exc:
        evs.append("N2 链路异常：%r" % (exc,))
    ok_audit = False
    try:
        hits = wait_audit(ctx.tmp, t0, "POST /v1/pair/approve", result=404)
        e = hits[-1] if hits else {}
        ok_audit = bool(hits) and e.get("identity") == "" and e.get("target") == ""
        evs.append("审计 approve 404 条目 identity=%r target=%r"
                   % (e.get("identity"), e.get("target")))
    except Exception as exc:
        evs.append("审计核验异常：%r" % (exc,))
    return ok_begin and ok_approve and ok_audit, "；".join(evs)


def n3_code_expired(ctx, opts):
    """N3 码过期：pair.code_ttl=5 → begin → approve → 等 6 秒 → confirm（正确码）
    → 400 PAIR_EXPIRED（过期会话保留供回报，§23.3）。"""
    t0 = time.time() - 1
    evs = []
    code = None
    ok_begin = ok_approve = ok_confirm = False
    try:
        status, body = pair_request(HOST, ctx.port_b, "POST", "/v1/pair/begin", payload={})
        ok_begin = status == 200
        sid = (pdata(body) or {}).get("session_id")
        if sid:
            ctx.all_sids.append(sid)
        status, body = pair_request(HOST, ctx.port_b, "POST", "/v1/pair/approve", payload={})
        code = (pdata(body) or {}).get("code")
        ok_approve = status == 200 and bool(code)
        evs.append("begin → HTTP %s；approve → HTTP %s（fast 实例 code_ttl=5）"
                   % (status, status))
        time.sleep(6)
        status, body = pair_request(HOST, ctx.port_b, "POST", "/v1/pair/confirm",
                                    payload={"code": code, "name": "x2"})
        ok_confirm = status == 400 and err_code(body) == "PAIR_EXPIRED"
        ctx.all_names.add("x2")
        evs.append("等 6 秒后正确码 confirm → HTTP %s code=%s（message=%r）"
                   % (status, err_code(body), pmessage(body)))
    except Exception as exc:
        evs.append("N3 链路异常：%r" % (exc,))
    ok_audit = False
    try:
        hits = wait_audit(ctx.tmp, t0, "POST /v1/pair/confirm", result=400)
        e = hits[-1] if hits else {}
        ok_audit = (bool(hits) and e.get("identity") == "" and e.get("target") == ""
                    and e.get("code") == "PAIR_EXPIRED")
        evs.append("审计 confirm 过期条目 code=%s target=%r" % (e.get("code"), e.get("target")))
    except Exception as exc:
        evs.append("审计核验异常：%r" % (exc,))
    return ok_begin and ok_approve and ok_confirm and ok_audit, "；".join(evs)


def n4_attempts_exceeded(ctx, opts):
    """N4 猜码超限：approve 后连续 5 次错码 → 前 4 次 401 PAIR_CODE_MISMATCH
    （message 含剩余次数）→ 第 5 次 403 PAIR_ATTEMPTS_EXCEEDED → 正确码 → 404 已作废。"""
    t0 = time.time() - 1
    evs = []
    code = None
    wrong = "000000"
    ok_begin = ok_approve = ok_four = ok_fifth = ok_voided = ok_leak = False
    try:
        status, body = pair_request(HOST, ctx.port_b, "POST", "/v1/pair/begin", payload={})
        ok_begin = status == 200
        sid = (pdata(body) or {}).get("session_id")
        if sid:
            ctx.all_sids.append(sid)
        status, body = pair_request(HOST, ctx.port_b, "POST", "/v1/pair/approve", payload={})
        code = (pdata(body) or {}).get("code")
        ok_approve = status == 200 and bool(code)
        if code == wrong:
            wrong = "999999"
        ctx.all_names.add("x3")
        evs.append("begin/approve → HTTP %s/%s" % (status, status))

        statuses = []
        codes = []
        messages = []
        for _ in range(4):
            status, body = pair_request(HOST, ctx.port_b, "POST", "/v1/pair/confirm",
                                        payload={"code": wrong, "name": "x3"})
            statuses.append(status)
            codes.append(err_code(body))
            messages.append(pmessage(body) or "")
        ok_four = (all(s == 401 for s in statuses)
                   and all(c == "PAIR_CODE_MISMATCH" for c in codes))
        nums = [re.search(r"(\d+)", m) for m in messages]
        ok_msg = all(n is not None and n.group(1) == str(4 - i)
                     for i, n in enumerate(nums))
        evs.append("4 次错码 → %s/%s（全 401 PAIR_CODE_MISMATCH=%s），"
                   "message 剩余次数=%s（递减 4→1=%s）"
                   % (statuses, codes, ok_four,
                      [n.group(1) if n else "?" for n in nums], ok_msg))

        status, body = pair_request(HOST, ctx.port_b, "POST", "/v1/pair/confirm",
                                    payload={"code": wrong, "name": "x3"})
        ok_fifth = status == 403 and err_code(body) == "PAIR_ATTEMPTS_EXCEEDED"
        evs.append("第 5 次错码 → HTTP %s code=%s" % (status, err_code(body)))

        status, body = pair_request(HOST, ctx.port_b, "POST", "/v1/pair/confirm",
                                    payload={"code": code, "name": "x3"})
        ok_voided = status == 404 and err_code(body) == "PAIR_NO_SESSION"
        evs.append("正确码 confirm（已作废）→ HTTP %s code=%s（message=%r）"
                   % (status, err_code(body), pmessage(body)))
    except Exception as exc:
        evs.append("N4 链路异常：%r" % (exc,))
    ok_audit = False
    ok_clean = False
    try:
        wait_audit(ctx.tmp, t0, "POST /v1/pair/confirm", result=403, count=1)
        entries = audit_entries(ctx.tmp)
        mismatch = pick_audit(entries, t0, "POST /v1/pair/confirm", result=401)
        exceeded = pick_audit(entries, t0, "POST /v1/pair/confirm", result=403)
        ok_audit = (len(mismatch) >= 4 and bool(exceeded)
                    and all(e.get("identity") == "" and e.get("target") == ""
                            for e in mismatch[-4:] + exceeded)
                    and exceeded[-1].get("code") == "PAIR_ATTEMPTS_EXCEEDED")
        evs.append("审计 401×%d/403 条目 identity=target='' 达标=%s"
                   % (len(mismatch), ok_audit))
        # 贯穿核验（N4 为最后一个 pair 负例）：全部 pair 条目 target ∈ {"",
        # session=<已知 sid>, name=<已知名>} → 确定性证明配对码值永不落审计（§8.3）
        bad_targets = pair_targets_bad(entries, set(ctx.all_sids), ctx.all_names)
        ok_clean = not bad_targets
        evs.append("全量 pair 审计条目 target 结构核验（已知 sid×%d/name×%d）违例=%s"
                   % (len(set(ctx.all_sids)), len(ctx.all_names),
                      bad_targets if bad_targets else "无"))
        ok_leak = ok_clean and bool(code) \
            and code not in "".join(str(e.get("action", "")) + str(e.get("target", ""))
                                    for e in entries)
        evs.append("pair 动作/target 不出现配对码=%s" % ok_leak)
    except Exception as exc:
        evs.append("审计核验异常：%r" % (exc,))
        ok_leak = False
    return (ok_begin and ok_approve and ok_four and ok_msg and ok_fifth and ok_voided
            and ok_audit and ok_clean and ok_leak), "；".join(evs)


def n5_rate_limit(ctx, opts):
    """N5 begin 限频：默认 begin_interval=10（rate 实例默认 pair 配置）下连续两次
    begin → 第二次 429 PAIR_RATE_LIMITED；含被 429 拒绝的也刷新（第三次仍 429）。"""
    t0 = time.time() - 1
    evs = []
    ok_first = ok_second = ok_third = ok_audit = False
    try:
        status, body = pair_request(HOST, ctx.port_c, "POST", "/v1/pair/begin", payload={})
        ok_first = status == 200
        sid = (pdata(body) or {}).get("session_id")
        if sid:
            ctx.all_sids.append(sid)
        evs.append("第一次 begin → HTTP %s" % status)

        status, body = pair_request(HOST, ctx.port_c, "POST", "/v1/pair/begin", payload={})
        ok_second = status == 429 and err_code(body) == "PAIR_RATE_LIMITED"
        evs.append("第二次 begin → HTTP %s code=%s（message=%r）"
                   % (status, err_code(body), pmessage(body)))

        status, body = pair_request(HOST, ctx.port_c, "POST", "/v1/pair/begin", payload={})
        ok_third = status == 429 and err_code(body) == "PAIR_RATE_LIMITED"
        evs.append("第三次 begin（被拒请求也刷新间隔）→ HTTP %s" % status)

        status, body = pair_request(HOST, ctx.port_c, "POST", "/v1/pair/reject", payload={})
        evs.append("清场 reject → HTTP %s" % status)
    except Exception as exc:
        evs.append("N5 链路异常：%r" % (exc,))
    try:
        hits = wait_audit(ctx.tmp, t0, "POST /v1/pair/begin", result=429, count=2)
        e = hits[-1] if hits else {}
        ok_audit = (len(hits) >= 2 and all(x.get("identity") == "" and x.get("target") == ""
                                           for x in hits)
                    and e.get("code") == "PAIR_RATE_LIMITED")
        evs.append("审计 429 条目 %d 条 identity=target='' 达标=%s code=%s"
                   % (len(hits), ok_audit, e.get("code")))
    except Exception as exc:
        evs.append("审计核验异常：%r" % (exc,))
    return ok_first and ok_second and ok_third and ok_audit, "；".join(evs)


def n6_loopback(ctx, opts):
    """N6 回环限定：白盒（is_loopback 样例 + guard_pair 代码顺序：is_private →
    回环检查，且不出现令牌/防重放校验）+ 黑盒佐证（本机另一私网 IP 直连仅回环端点
    → 403，对照测试要求口径 4：单机无法伪造非私网源 IP）。"""
    evs = []
    # ① 白盒：函数级样例
    node_dir = str(ROOT / "node")
    if node_dir not in sys.path:
        sys.path.insert(0, node_dir)
    ok_wb_func = False
    try:
        import node
        samples = [("127.0.0.1", True), ("::1", True), ("192.168.1.5", False),
                   ("10.0.0.5", False), ("172.16.0.9", False), ("169.254.1.2", False),
                   ("127.0.0.2", False)]     # 契约仅 127.0.0.1/::1（§23.1）
        bad = []
        for ip, expect in samples:
            got = bool(node.is_loopback(ip))
            if got != expect:
                bad.append("%s→%s(期望%s)" % (ip, got, expect))
        ok_wb_func = not bad
        evs.append("is_loopback 样例 %d/%d 正确%s"
                   % (len(samples) - len(bad), len(samples),
                      ("；异常：" + ",".join(bad)) if bad else ""))
    except Exception as exc:
        evs.append("import node / is_loopback 失败：%r" % (exc,))

    # ② 白盒：guard_pair 代码顺序（is_private 先于回环检查；无令牌/防重放校验）
    ok_wb_order = False
    try:
        src = NODE_PY.read_text(encoding="utf-8")
        match = re.search(r"def guard_pair\s*\(.*?(?=\n    def |\n\S)", src, re.S)
        block = match.group(0) if match else ""
        if not block:
            evs.append("未定位 guard_pair 函数（node 侧结构变化），顺序断言未完成")
        else:
            i_private = block.find("is_private")
            i_loop = block.find("is_loopback")
            ok_wb_order = (0 <= i_private < i_loop
                           and "X-Auth-Token" not in block
                           and "check_replay" not in block)
            evs.append("guard_pair 顺序：is_private@%d → is_loopback@%d，"
                       "无令牌/防重放校验=%s" % (i_private, i_loop,
                                               "X-Auth-Token" not in block
                                               and "check_replay" not in block))
    except Exception as exc:
        evs.append("读 node 源码失败：%r" % (exc,))

    # ③ 黑盒佐证：仅回环端点经 127.0.0.1 → 200；经本机另一私网 IP → 403 FORBIDDEN
    ok_bl_loop = ok_bl_priv = ok_bl_audit = False
    try:
        status, body = pair_request(HOST, ctx.port_c, "GET", "/v1/pair/session")
        ok_bl_loop = status == 200 and (pdata(body) or {}).get("state") == "idle"
        evs.append("GET /v1/pair/session（127.0.0.1，rate 实例监听 0.0.0.0）→ HTTP %s state=%s"
                   % (status, (pdata(body) or {}).get("state")))

        t_bl = time.time() - 1
        status, body = raw_request(HOST, ctx.port_c, "GET", "/v1/info",
                                   token=TOKEN_DEFAULT, timeout=8)
        addresses = [a for a in ((pdata(body) or {}).get("addresses") or [])
                     if isinstance(a, str) and a and a not in ("127.0.0.1", "::1")]
        verdict = None
        used_ip = None
        for ip in addresses:
            try:
                status, body = pair_request(ip, ctx.port_c, "GET", "/v1/pair/session",
                                            timeout=6)
            except Exception:
                continue        # 个别地址可能不可直达（断开的适配器），逐个尝试
            used_ip = ip
            verdict = (status, err_code(body))
            break
        ok_bl_priv = verdict is not None and verdict[0] == 403 \
            and verdict[1] == "FORBIDDEN"
        evs.append("GET /v1/pair/session（本机私网 IP %s）→ %s（单机无法伪造非私网源 IP，"
                   "以通过私网校验后的回环限定拒绝作黑盒佐证，测试要求口径 4）"
                   % (used_ip, verdict))

        hits = wait_audit(ctx.tmp, t_bl, "GET /v1/pair/session", result=403)
        e = hits[-1] if hits else {}
        ok_bl_audit = (bool(hits) and e.get("identity") == "" and e.get("target") == ""
                       and e.get("client") == used_ip)
        evs.append("审计回环限定 403 条目 identity=%r target=%r client=%s"
                   % (e.get("identity"), e.get("target"), e.get("client")))
    except Exception as exc:
        evs.append("N6 黑盒佐证异常：%r" % (exc,))
    return ok_wb_func and ok_wb_order and ok_bl_loop and ok_bl_priv and ok_bl_audit, \
        "；".join(evs)


def n7_bad_params(ctx, opts):
    """N7 非法参数不计次：code 非 6 位数字 → 400 BAD_REQUEST 且 attempts 不消耗
    （GET session attempts_left 不变）。"""
    t0 = time.time() - 1
    evs = []
    sid = None
    ok_begin = ok_approve = ok_bad = ok_left = ok_clean = False
    try:
        status, body = pair_request(HOST, ctx.port_a, "POST", "/v1/pair/begin", payload={})
        sid = (pdata(body) or {}).get("session_id")
        ok_begin = status == 200 and is_16hex(sid)
        if sid:
            ctx.all_sids.append(sid)
        status, body = pair_request(HOST, ctx.port_a, "POST", "/v1/pair/approve", payload={})
        ok_approve = status == 200
        ctx.all_names.add("x4")
        evs.append("begin/approve → HTTP %s/%s" % (status, status))

        verdicts = []
        for bad_code in ("12a45b", "12345", "1234567", 123456):
            status, body = pair_request(HOST, ctx.port_a, "POST", "/v1/pair/confirm",
                                        payload={"code": bad_code, "name": "x4"})
            verdicts.append((status, err_code(body)))
        ok_bad = all(s == 400 and c == "BAD_REQUEST" for s, c in verdicts)
        evs.append("非法 code（非 6 位数字/非字符串）→ %s（全 400 BAD_REQUEST=%s）"
                   % (verdicts, ok_bad))

        status, body = pair_request(HOST, ctx.port_a, "GET", "/v1/pair/session")
        data = pdata(body) or {}
        ok_left = data.get("attempts_left") == ctx.max_attempts
        evs.append("GET session attempts_left=%s（预期 %d，未消耗=%s）"
                   % (data.get("attempts_left"), ctx.max_attempts, ok_left))

        status, body = pair_request(HOST, ctx.port_a, "POST", "/v1/pair/reject", payload={})
        ok_clean = status == 200
        evs.append("清场 reject → HTTP %s" % status)
    except Exception as exc:
        evs.append("N7 链路异常：%r" % (exc,))
    ok_audit = False
    try:
        hits = wait_audit(ctx.tmp, t0, "POST /v1/pair/confirm", result=400, count=4)
        e = hits[-1] if hits else {}
        ok_audit = (len(hits) >= 4 and all(x.get("identity") == ""
                                           and x.get("target") == "" for x in hits))
        evs.append("审计 confirm 400 条目 %d 条 identity=target='' 达标=%s"
                   % (len(hits), ok_audit))
    except Exception as exc:
        evs.append("审计核验异常：%r" % (exc,))
    return ok_begin and ok_approve and ok_bad and ok_left and ok_clean and ok_audit, \
        "；".join(evs)


# --------------------------------------------------------------------------
# C 末尾回归
# --------------------------------------------------------------------------

def c_regression(ctx, opts):
    """C 回归：末尾子进程跑 smoke_s1 → 8/8、smoke_s2 → 10/10、smoke_s3 → 10/10
    （各自动回归亦须通过；汇总行文本核对）。--skip-sX 跳过（调试用不计失败）。"""
    notes = []

    def run_one(script, summary_re, expect, timeout):
        print("  [C] 子进程运行 tests/%s（约数分钟）…" % script)
        try:
            proc = subprocess.run([sys.executable, str(HERE / script)],
                                  capture_output=True, text=True, encoding="utf-8",
                                  errors="replace", timeout=timeout, cwd=str(ROOT))
            out = (proc.stdout or "") + (proc.stderr or "")
            match = re.search(summary_re, out)
            ok = proc.returncode == 0 and match and match.group(1) == expect
            notes.append("%s 子进程 → rc=%s，汇总行：%s"
                         % (script, proc.returncode,
                            match.group(0) if match else "未找到汇总行"))
            return ok
        except Exception as exc:
            notes.append("%s 子进程异常：%r" % (script, exc))
            return False

    ok_s1 = True
    if opts.skip_s1:
        notes.append("smoke_s1 回归已跳过（--skip-s1，调试模式不计入失败）")
    else:
        ok_s1 = run_one("smoke_s1.py", r"S1 自测：(\d+)/8 通过", "8", 1200)

    ok_s2 = True
    if opts.skip_s2:
        notes.append("smoke_s2 回归已跳过（--skip-s2，调试模式不计入失败）")
    else:
        ok_s2 = run_one("smoke_s2.py", r"S2 自测：(\d+)/10 通过", "10", 3600)

    ok_s3 = True
    if opts.skip_s3:
        notes.append("smoke_s3 回归已跳过（--skip-s3，调试模式不计入失败）")
    else:
        ok_s3 = run_one("smoke_s3.py", r"S3 自测：(\d+)/10 通过", "10", 7200)
    return ok_s1 and ok_s2 and ok_s3, "；".join(notes)


# --------------------------------------------------------------------------
# 主流程
# --------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="CrossDevice M4 一键自测（P/N/C）")
    ap.add_argument("--skip-s1", action="store_true",
                    help="跳过末尾 smoke_s1 回归（调试用，不计入失败）")
    ap.add_argument("--skip-s2", action="store_true",
                    help="跳过末尾 smoke_s2 回归（调试用，不计入失败）")
    ap.add_argument("--skip-s3", action="store_true",
                    help="跳过末尾 smoke_s3 回归（调试用，不计入失败）")
    ap.add_argument("--keep", action="store_true", help="保留临时目录便于排障")
    ap.add_argument("--node", default=None, help="node.py 路径覆盖（默认 node/node.py）")
    opts = ap.parse_args()
    if opts.node:
        global NODE_PY
        NODE_PY = Path(opts.node).resolve()
        smoke_s1.NODE_PY = NODE_PY             # S2Node 复用同一覆盖

    tmp = Path(tempfile.mkdtemp(prefix="xd_s4_smoke_"))
    ctx = Ctx()
    ctx.tmp = tmp
    ctx.nodes = []
    ctx.max_attempts = 5
    ctx.all_sids = []                   # 全部创建过的 session_id（审计结构核验用）
    ctx.all_names = set()               # confirm 用过的 name（同上）
    print("临时目录：%s" % tmp)
    print("node.py：%s" % NODE_PY)
    print("-" * 76)

    exit_code = 1
    try:
        # 证书与配置（全部临时目录）
        tls1 = tmp / "tls1"
        ctx.cert1, ctx.key1 = tls1 / "cert.pem", tls1 / "key.pem"
        ctx.fp1 = gen_cert(tls1)
        print("证书指纹：%s" % ctx.fp1)
        ctx.work = tmp / "work"
        ctx.work.mkdir(parents=True, exist_ok=True)

        tokens = [{"name": "default", "token": TOKEN_DEFAULT}]
        base_cfg = {
            "version": 1, "tokens": tokens,
            "tls": {"cert": str(ctx.cert1), "key": str(ctx.key1)},
            "audit": {"retention_days": 180},
            "workspace": [str(ctx.work)],
        }
        # main 实例：正向链路编排（begin_interval=0 防用例间限频；限频由 rate 实例专测）
        ctx.cfg_a = tmp / "cfga" / "node.json"
        cfg_a = dict(base_cfg)
        cfg_a["pair"] = {"begin_interval": 0}
        write_json(ctx.cfg_a, cfg_a)
        # fast 实例：pending/code 时效调短（契约 §9.1 下限 5 供测试调短）
        ctx.cfg_b = tmp / "cfgb" / "node.json"
        cfg_b = dict(base_cfg)
        cfg_b["pair"] = {"pending_ttl": 5, "code_ttl": 5, "begin_interval": 0}
        write_json(ctx.cfg_b, cfg_b)
        # rate 实例：默认 pair 配置（begin_interval=10）+ 监听 0.0.0.0（N6 黑盒）
        ctx.cfg_c = tmp / "cfgc" / "node.json"
        write_json(ctx.cfg_c, dict(base_cfg))

        # xd 注册表打补丁到临时目录（绝不触碰仓库 data/）
        xd.REGISTRY = tmp / "registry" / "devices.json"
        xd.DATA = xd.REGISTRY.parent
        xd.save_registry({"devices": {}})

        # 三个 node 实例（独立端口/配置；LOCALAPPDATA 兜底由 S2Node 完成）
        ctx.port_a = free_port()
        ctx.port_b = free_port()
        ctx.port_c = free_port()
        node_a = S2Node("main", tmp, ["--host", HOST, "--port", str(ctx.port_a),
                                      "--config", str(ctx.cfg_a),
                                      "--cert", str(ctx.cert1), "--key", str(ctx.key1),
                                      "--verbose"])
        node_b = S2Node("fast", tmp, ["--host", HOST, "--port", str(ctx.port_b),
                                      "--config", str(ctx.cfg_b),
                                      "--cert", str(ctx.cert1), "--key", str(ctx.key1),
                                      "--verbose"])
        node_c = S2Node("rate", tmp, ["--host", "0.0.0.0", "--port", str(ctx.port_c),
                                      "--config", str(ctx.cfg_c),
                                      "--cert", str(ctx.cert1), "--key", str(ctx.key1),
                                      "--verbose"])
        ctx.nodes += [node_a, node_b, node_c]
        ready_ok = True
        for tag, obj, port in (("main", node_a, ctx.port_a),
                               ("fast", node_b, ctx.port_b),
                               ("rate", node_c, ctx.port_c)):
            try:
                obj.ready(TOKEN_DEFAULT, port, timeout=45)
                print("node[%s] 就绪（端口 %d）" % (tag, port))
            except smoke_s1.NodeNotReady as exc:
                ready_ok = False
                print("!! node[%s] 未就绪（node 侧）：%s" % (tag, str(exc)[:200]))
        print("-" * 76)

        # 正向链路前置基线：identity_count（P4 用）与首会话（P1 独立发起）
        ctx.sess_main = None
        ctx.code_main = None
        ctx.token_new = None
        ctx.device_id_new = None
        ctx.ident_count_before = None
        if ready_ok:
            try:
                status, body = raw_request(HOST, ctx.port_a, "GET", "/v1/info",
                                           token=TOKEN_DEFAULT, timeout=8)
                ctx.ident_count_before = (pdata(body) or {}).get("identity_count")
            except Exception:
                ctx.ident_count_before = None

        for code, title, fn in [
            ("P1", "begin 正向", p1_begin),
            ("P2", "回环确认", p2_confirm_ui),
            ("P3", "confirm 签发", p3_confirm_sign),
            ("P4", "新令牌可用", p4_new_token),
            ("P5", "幂等 approve", p5_idempotent),
            ("P6", "xd add 兼容", p6_xd_add),
            ("N1", "拒绝", n1_reject),
            ("N7", "非法参数不计次", n7_bad_params),
            ("N6", "回环限定", n6_loopback),
            ("N5", "begin 限频", n5_rate_limit),
            ("N2", "pending 超时", n2_pending_timeout),
            ("N3", "码过期", n3_code_expired),
            ("N4", "猜码超限", n4_attempts_exceeded),
            ("C", "回归", c_regression),
        ]:
            if not ready_ok and code != "C":
                record(code, title, False, "node 实例未就绪，无法验证（node 侧）")
                continue
            try:
                ok, evidence = fn(ctx, opts)
            except Exception as exc:
                ok, evidence = False, "测试框架异常：%r" % (exc,)
            record(code, title, ok, evidence)

        passed = sum(1 for _, _, ok in RESULTS if ok)
        print("-" * 76)
        print("S4 自测：%d/%d 通过" % (passed, len(RESULTS)))
        for code, title, ok in RESULTS:
            if not ok:
                print("  未通过：%s %s" % (code, title))
        exit_code = 0 if passed == len(RESULTS) == 14 else 1
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
