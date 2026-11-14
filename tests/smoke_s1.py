#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CrossDevice S1 阶段一键自测（验收载体，覆盖验收表 A1–A8）。

用法：
    py tests/smoke_s1.py            # 跑完 A1–A8，输出逐项 PASS/FAIL 与汇总
    py tests/smoke_s1.py --keep     # 保留临时目录便于排障
    py tests/smoke_s1.py --node X   # 指定 node.py 路径（默认 node/node.py）

隔离性（绝不触碰真实 %LOCALAPPDATA%\\CrossDevice 与仓库 data/）：
    - 证书（tools/gen_cert.ps1）、node 配置、审计目录、截屏产物全部落在临时目录；
    - node 子进程以覆盖后的 LOCALAPPDATA 启动，兜底防止 node 忽略 --config 时写真实目录；
    - xd 的注册表路径（xd.REGISTRY / xd.DATA）打补丁到临时文件；
    - finally 中终止全部 node 子进程并清理临时目录。

仅标准库。node/ 由并行阶段按契约改造，node 侧未就绪导致的 FAIL 会在证据中标注。
"""

import argparse
import base64
import contextlib
import hashlib
import http.client
import io
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import uuid
from pathlib import Path

sys.dont_write_bytecode = True      # 不在仓库中生成 __pycache__

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import xd                            # noqa: E402

GEN_CERT_PS1 = ROOT / "tools" / "gen_cert.ps1"
NODE_PY = ROOT / "node" / "node.py"

HOST = "127.0.0.1"
TOKEN_DEFAULT = "5f8c1d2e3a4b5c6d7e8f9a0b1c2d3e4f"   # 固定测试令牌（32 hex）
TOKEN_TESTER = "a1b2c3d4e5f60718293a4b5c6d7e8f90"
TOKEN_BAD = "00000000000000000000000000000000"
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"

RESULTS = []


def record(code, title, ok, evidence):
    RESULTS.append((code, title, bool(ok)))
    evidence = " ".join(str(evidence).split())
    print("%s %s %s（%s）" % (code, title, "PASS" if ok else "FAIL", evidence))


# --------------------------------------------------------------------------
# 基础设施
# --------------------------------------------------------------------------

def free_port():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((HOST, 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def tls_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def raw_request(ip, port, method, path, token=None, headers=None, payload=None,
                timeout=8, plaintext=False):
    """绕开 xd 客户端的裸请求（A1 / A4 / 探活用），可完全控制请求头。"""
    if plaintext:
        conn = http.client.HTTPConnection(ip, port, timeout=timeout)
    else:
        conn = http.client.HTTPSConnection(ip, port, context=tls_context(), timeout=timeout)
    try:
        conn.connect()
        hdrs = {
            "X-Timestamp": str(int(time.time())),
            "X-Nonce": uuid.uuid4().hex,
        }
        if token:
            hdrs["X-Auth-Token"] = token
        if headers:
            hdrs.update(headers)
        body = None
        if payload is not None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            hdrs.setdefault("Content-Type", "application/json")
        conn.request(method, path, body=body, headers=hdrs)
        resp = conn.getresponse()
        data = resp.read()
        return resp.status, data
    finally:
        try:
            conn.close()
        except Exception:
            pass


def err_code(body):
    try:
        data = json.loads(body.decode("utf-8"))
        return (data.get("error") or {}).get("code")
    except Exception:
        return None


def pem_sha256(path):
    """证书 PEM → DER 的 SHA-256 小写 64 hex（契约 4.1 指纹口径）。"""
    text = Path(path).read_bytes().decode("utf-8-sig")
    b64 = "".join(line.strip() for line in text.splitlines()
                  if line.strip() and not line.startswith("-----"))
    der = base64.b64decode(b64)
    return hashlib.sha256(der).hexdigest()


def write_json(path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")


def tail_text(path, limit=1200):
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")[-limit:].replace("\n", " | ")
    except Exception:
        return "<无日志>"


class NodeNotReady(RuntimeError):
    pass


class NodeProc:
    """node 子进程封装：契约参数行 + 日志落盘 + 可靠终止。"""

    def __init__(self, tag, port, extra_args, cfg_path, tmp, cert=None, key=None):
        self.tag = tag
        self.port = port
        self.log_path = tmp / ("node_%s.log" % tag)
        args = ["--host", HOST, "--port", str(port), "--config", str(cfg_path), "--verbose"]
        if cert:
            args += ["--cert", str(cert), "--key", str(key)]
        args += list(extra_args)
        env = dict(os.environ)
        env["LOCALAPPDATA"] = str(tmp / "localappdata")   # 兜底：防 node 忽略 --config 写真实目录
        self._fh = open(self.log_path, "wb")
        self.proc = subprocess.Popen(
            [sys.executable, str(NODE_PY)] + args,
            stdout=self._fh, stderr=subprocess.STDOUT,
            cwd=str(tmp), env=env)

    def ready(self, token, timeout=45, plaintext=False):
        deadline = time.time() + timeout
        last = ""
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise NodeNotReady("node[%s] 进程提前退出 code=%s，日志尾部：%s"
                                   % (self.tag, self.proc.returncode, tail_text(self.log_path)))
            try:
                status, body = raw_request(HOST, self.port, "GET", "/v1/health",
                                           token=token, timeout=3, plaintext=plaintext)
                data = json.loads(body.decode("utf-8"))
                if status == 200 and data.get("ok") is True \
                        and data.get("data", {}).get("status") == "up":
                    return
                last = "HTTP %s %s" % (status, body[:160])
            except Exception as exc:
                last = repr(exc)
            time.sleep(0.4)
        raise NodeNotReady("node[%s] %d 秒内未就绪：%s；日志尾部：%s"
                           % (self.tag, timeout, last, tail_text(self.log_path)))

    def stop(self):
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=8)
            except Exception:
                self.proc.kill()
        try:
            self.proc.wait(timeout=5)
        except Exception:
            pass
        try:
            self._fh.close()
        except Exception:
            pass


def gen_cert(out_dir, days=2):
    """调 tools/gen_cert.ps1 造证书，返回证书指纹（契约 4.1 口径）。"""
    ps = shutil.which("powershell") or "powershell"
    cmd = [ps, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(GEN_CERT_PS1),
           "-OutDir", str(out_dir), "-Days", str(days), "-Force"]
    proc = subprocess.run(cmd, capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=180)
    cert, key = Path(out_dir) / "cert.pem", Path(out_dir) / "key.pem"
    if proc.returncode != 0 or not cert.exists() or not key.exists():
        raise RuntimeError("gen_cert.ps1 失败（code=%s）：%s %s"
                           % (proc.returncode, (proc.stdout or "")[-400:],
                              (proc.stderr or "")[-400:]))
    return pem_sha256(cert)


def run_xd(argv, registry):
    """进程内跑 xd 子命令（真实 argparse 解析），捕获输出。"""
    out, err = io.StringIO(), io.StringIO()
    error = None
    try:
        args = xd.build_parser().parse_args(argv)
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            args.func(args, registry)
    except (SystemExit, RuntimeError) as exc:
        error = str(exc)
    except Exception as exc:
        error = "%s: %s" % (type(exc).__name__, exc)
    return out.getvalue(), err.getvalue(), error


class Ctx:
    pass


# --------------------------------------------------------------------------
# A1–A8
# --------------------------------------------------------------------------

def a1_tls(ctx):
    """A1：TLS 开启时明文 HTTP 被拒；--debug-plaintext 显式开启时可用。"""
    # ① 明文请求 TLS 端口：任何异常即视为被拒
    reject_exc = None
    try:
        raw_request(HOST, ctx.port_main, "GET", "/v1/health", token=ctx.token_default,
                    plaintext=True, timeout=5)
    except Exception as exc:
        reject_exc = exc
    ok1 = reject_exc is not None
    ev1 = ("明文请求 TLS 端口被拒（%s: %s）" % (type(reject_exc).__name__, reject_exc)) \
        if ok1 else "明文请求 TLS 端口未被拒绝（node 侧未启用 TLS？）"

    # ② --debug-plaintext 第二实例（另一端口、独立配置目录）
    ok2 = False
    ev2 = ""
    plain_node = None
    try:
        plain_node = NodeProc("plain", ctx.port_plain, ["--debug-plaintext"],
                              ctx.cfg_plain, ctx.tmp, cert=ctx.cert1, key=ctx.key1)
        ctx.nodes.append(plain_node)
        plain_node.ready(ctx.token_default, plaintext=True)
        status, body = raw_request(HOST, ctx.port_plain, "GET", "/v1/health",
                                   token=ctx.token_default, plaintext=True, timeout=8)
        data = json.loads(body.decode("utf-8"))
        ok2 = status == 200 and data.get("ok") is True \
            and data.get("data", {}).get("status") == "up"
        ev2 = "--debug-plaintext 实例明文 /v1/health → HTTP %s ok=%s" % (status, data.get("ok"))
    except Exception as exc:
        ev2 = "--debug-plaintext 实例异常（node 侧）：%r" % (exc,)
    finally:
        if plain_node:
            plain_node.stop()
    return ok1 and ok2, "%s；%s" % (ev1, ev2)


def a2_source_limit(ctx):
    """A2：非私网来源 403（函数级 + guard 代码顺序验证；本机无法伪造源 IP）。"""
    node_dir = str(ROOT / "node")
    if node_dir not in sys.path:
        sys.path.insert(0, node_dir)
    try:
        import node
    except Exception as exc:
        return False, "import node 失败（node 侧）：%r" % (exc,)

    samples = [
        ("203.0.113.9", False), ("8.8.8.8", False), ("192.169.1.1", False),
        ("172.32.0.1", False), ("100.64.0.1", False),
        ("127.0.0.1", True), ("::1", True), ("10.0.0.5", True),
        ("172.16.0.9", True), ("172.31.255.255", True), ("192.168.1.2", True),
        ("169.254.10.5", True),
    ]
    bad = []
    for ip, expect in samples:
        try:
            got = bool(node.is_private(ip))
        except Exception as exc:
            bad.append("%s(异常%r)" % (ip, exc))
            continue
        if got != expect:
            bad.append("%s→%s(期望%s)" % (ip, got, expect))
    ok_func = not bad
    ev_func = "is_private 样例 %d/%d 正确%s" % (
        len(samples) - len(bad), len(samples),
        ("；异常样例：" + ",".join(bad)) if bad else "")

    # guard 代码顺序证据：契约 2.3，来源校验（403 FORBIDDEN）必须先于身份校验（401）
    ok_guard = False
    try:
        src = NODE_PY.read_text(encoding="utf-8")
        match = re.search(r"def guard\s*\(.*?(?=\n    def |\n\S)", src, re.S)
        block = match.group(0) if match else ""
        if not block:
            ev_guard = "未在 node 源码中定位 guard 函数（node 侧结构变化），顺序断言未完成"
        else:
            i_private = block.find("is_private")
            i_403 = block.find("403")
            i_token = block.find("X-Auth-Token")
            i_401 = block.find("401")
            ok_guard = (i_private >= 0
                        and (i_403 < 0 or i_403 > i_private)
                        and (i_token < 0 or i_token > i_private)
                        and (i_401 < 0 or (i_403 >= 0 and i_403 < i_401)))
            ev_guard = ("guard 代码顺序：is_private@%d，FORBIDDEN/403@%s，token@%s，401@%s "
                        "（非私网→403 先于令牌校验）"
                        % (i_private, i_403, i_token, i_401))
    except Exception as exc:
        ev_guard = "读 node 源码失败：%r" % (exc,)

    note = "；本机无法伪造非私网源 IP，函数级+代码顺序验证即验收口径"
    return ok_func and ok_guard, "%s；%s%s" % (ev_func, ev_guard, note)


def a3_auth(ctx):
    """A3：错误令牌 401；两身份并发均 200 且审计可区分。"""
    if not ctx.node_up:
        return False, "node 未就绪，无法验证（node 侧）"
    # ① 错误令牌 → 401 UNAUTHORIZED
    dev_bad = {"name": "", "ip": HOST, "port": ctx.port_main, "token": TOKEN_BAD,
               "identity": "default", "cert_fingerprint": ctx.fp1}
    unauthorized = None
    try:
        xd.request(dev_bad, "GET", "/v1/health", timeout=10)
    except RuntimeError as exc:
        unauthorized = str(exc)
    except Exception as exc:
        unauthorized = "异常类型错误：%r" % (exc,)
    ok1 = bool(unauthorized) and "UNAUTHORIZED" in unauthorized
    ev1 = "错误令牌 → %s" % (unauthorized or "未报错（node 侧）")

    # ② default / tester 两身份并发请求均 200（走 xd 客户端，各自独立 nonce）
    t0 = time.time() - 1
    errors = []

    def worker(identity, token):
        dev = {"name": "", "ip": HOST, "port": ctx.port_main, "token": token,
               "identity": identity, "cert_fingerprint": ctx.fp1}
        try:
            for _ in range(3):
                # xd.request 返回包络解包后的 data（health data 含 status=up）
                data = xd.request(dev, "GET", "/v1/health", timeout=10)
                if not (isinstance(data, dict) and data.get("status") == "up"):
                    errors.append("%s 响应异常：%r" % (identity, data))
        except Exception as exc:
            errors.append("%s：%r" % (identity, exc))

    threads = [threading.Thread(target=worker, args=("default", ctx.token_default)),
               threading.Thread(target=worker, args=("tester", ctx.token_tester))]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    ok2 = not errors
    ev2 = "default/tester 两身份并发各 3 次均 200" if ok2 else "并发错误：%s" % (errors,)

    # ③ /v1/audit 能区分两个身份的记录
    ok3 = False
    ev3 = ""
    try:
        audit = xd.request(ctx.dev, "GET", "/v1/audit?limit=1000", timeout=15)
        entries = audit.get("entries", [])
        idents = {e.get("identity") for e in entries
                  if isinstance(e.get("ts"), (int, float)) and e["ts"] >= t0
                  and e.get("result") == 200
                  and "/v1/health" in str(e.get("action", ""))}
        ok3 = {"default", "tester"} <= idents
        ev3 = "审计中近期 200 的 health 记录身份集合=%s" % sorted(
            x for x in idents if x)
    except Exception as exc:
        ev3 = "审计查询失败（node 侧）：%r" % (exc,)
    return ok1 and ok2 and ok3, "%s；%s；%s" % (ev1, ev2, ev3)


def a4_replay(ctx):
    """A4：同 nonce 原样重放 → 409 REPLAY_DETECTED；时间窗外 → 409。"""
    if not ctx.node_up:
        return False, "node 未就绪，无法验证（node 侧）"
    nonce = uuid.uuid4().hex
    ts = str(int(time.time()))
    replay_headers = {"X-Timestamp": ts, "X-Nonce": nonce}

    ok_first = False
    try:
        status, body = raw_request(HOST, ctx.port_main, "GET", "/v1/health",
                                   token=ctx.token_default,
                                   headers=dict(replay_headers))
        data = json.loads(body.decode("utf-8"))
        ok_first = status == 200 and data.get("ok") is True
        ev_first = "首次请求（新 nonce）HTTP %s ok=%s" % (status, data.get("ok"))
    except Exception as exc:
        ev_first = "首次请求异常（node 侧）：%r" % (exc,)

    ok_replay = False
    try:
        status, body = raw_request(HOST, ctx.port_main, "GET", "/v1/health",
                                   token=ctx.token_default,
                                   headers=dict(replay_headers))   # 原样重放
        code = err_code(body)
        ok_replay = status == 409 and code == "REPLAY_DETECTED"
        ev_replay = "原样重放 → HTTP %s code=%s" % (status, code or "-")
    except Exception as exc:
        ev_replay = "重放异常：%r" % (exc,)

    ok_window = False
    try:
        status, body = raw_request(HOST, ctx.port_main, "GET", "/v1/health",
                                   token=ctx.token_default,
                                   headers={"X-Timestamp": str(int(time.time()) - 400),
                                            "X-Nonce": uuid.uuid4().hex})
        code = err_code(body)
        ok_window = status == 409 and code == "REPLAY_DETECTED"
        ev_window = "now-400s（窗口外）→ HTTP %s code=%s" % (status, code or "-")
    except Exception as exc:
        ev_window = "时间窗验证异常（node 侧）：%r" % (exc,)
    return ok_first and ok_replay and ok_window, "%s；%s；%s" % (ev_first, ev_replay, ev_window)


def a5_audit(ctx):
    """A5：exec / fs/read / screen 均有身份+时间+结果记录；令牌不落盘；?token= 脱敏。"""
    if not ctx.node_up:
        return False, "node 未就绪，无法验证（node 侧）"
    dev = ctx.dev
    notes = []
    ok_requests = True

    # ① exec（POST /v1/exec + 任务轮询）
    t_exec = time.time() - 1
    try:
        data = xd.request(dev, "POST", "/v1/exec",
                          {"cmd": "echo smoke_a5_exec", "timeout": 15}, timeout=30)
        job = xd.request(dev, "GET", "/v1/job/%s?wait=15" % data["job_id"], timeout=30)
        notes.append("exec job=%s status=%s exit=%s"
                     % (data["job_id"], job.get("status"), job.get("exit_code")))
    except Exception as exc:
        ok_requests = False
        notes.append("exec 失败：%r" % (exc,))

    # ② fs/write 造文件 + fs/read
    target = ctx.work / "a5_file.txt"
    t_fs = time.time() - 1
    try:
        xd.request(dev, "POST", "/v1/fs/write",
                   {"path": str(target), "text": "审计样例内容 smoke-a5"}, timeout=15)
        read = xd.request(dev, "GET",
                          "/v1/fs/read?" + urllib.parse.urlencode({"path": str(target)}),
                          timeout=15)
        notes.append("fs/write+read size=%s" % read.get("size"))
    except Exception as exc:
        ok_requests = False
        notes.append("fs 失败：%r" % (exc,))

    # ③ screen（失败不阻断：审计仍应记录该次请求）
    t_screen = time.time() - 1
    try:
        png = xd.request(dev, "GET", "/v1/screen?monitor=-1&max_width=800",
                         timeout=60, raw=True)
        notes.append("screen %d 字节 PNG头=%s" % (len(png), png[:8] == PNG_MAGIC))
    except Exception as exc:
        notes.append("screen 异常（记录后审计验证）：%r" % (exc,))

    # ④ 查审计：三条均有 identity + ts + result
    ok_entries = False
    try:
        audit = xd.request(dev, "GET", "/v1/audit?limit=1000", timeout=15)
        entries = audit.get("entries", [])

        def picked(since, action_sub):
            return [e for e in entries
                    if isinstance(e.get("ts"), (int, float)) and e["ts"] >= since
                    and action_sub in str(e.get("action", ""))]

        groups = [("POST /v1/exec", t_exec), ("GET /v1/fs/read", t_fs),
                  ("GET /v1/screen", t_screen)]
        missing, bad_fields, hits_text = [], [], []
        for sub, since in groups:
            hits = picked(since, sub)
            if not hits:
                missing.append(sub)
                continue
            e = hits[-1]
            if not (e.get("identity") and isinstance(e.get("ts"), (int, float))
                    and isinstance(e.get("result"), int)):
                bad_fields.append(sub)
            hits_text.append("%s→identity=%s,ts=%s,result=%s"
                             % (sub, e.get("identity"), e.get("ts"), e.get("result")))
        ok_entries = (not missing) and (not bad_fields) and ok_requests
        ev_entries = "%s%s%s" % (
            "；".join(hits_text),
            ("；缺审计记录：" + ",".join(missing)) if missing else "",
            ("；字段缺失：" + ",".join(bad_fields)) if bad_fields else "")
    except Exception as exc:
        ev_entries = "审计查询失败（node 侧）：%r" % (exc,)

    # ⑤ 审计文件原文不含完整令牌
    ok_leak = False
    try:
        jsonl = sorted(ctx.tmp.rglob("audit-*.jsonl"))
        if not jsonl:
            ev_leak = "找不到审计文件 audit-*.jsonl（node 侧）"
        else:
            text = "".join(p.read_text(encoding="utf-8", errors="replace") for p in jsonl)
            leaks = [t for t in (ctx.token_default, ctx.token_tester) if t in text]
            ok_leak = not leaks
            ev_leak = "审计文件 %d 个，完整令牌出现=%s" % (len(jsonl), leaks or "无")
    except Exception as exc:
        ev_leak = "读审计文件失败：%r" % (exc,)

    # ⑥ ?token= 查询串请求：鉴权可用，且审计条目 action/target 含 token=***（脱敏）
    #    node 对已知路径的 action 记 "METHOD /path"（不含查询串）；查询串脱敏痕迹出现在
    #    /v1/audit 的 target（filter=<脱敏查询串>）与未知路径的请求行 action 中（§8.2/§8.3）
    t_q = time.time() - 1
    ok_query = False
    try:
        status, body = raw_request(HOST, ctx.port_main, "GET",
                                   "/v1/audit?token=" + ctx.token_default
                                   + "&identity=default", timeout=8)
        ok_req = status == 200 and json.loads(body.decode("utf-8")).get("ok") is True
        status2, body2 = raw_request(HOST, ctx.port_main, "GET",
                                     "/v1/not-exist-s1?token=" + TOKEN_BAD, timeout=8)
        # 鉴权先于路由（契约 §2.3）：坏令牌 → 401；任意 4xx 都会以脱敏请求行入审计
        ok_req2 = 400 <= status2 < 500
        audit = xd.request(dev, "GET", "/v1/audit?limit=1000", timeout=15)
        masked = [e for e in audit.get("entries", [])
                  if isinstance(e.get("ts"), (int, float)) and e["ts"] >= t_q
                  and "token=***" in (str(e.get("action", "")) + str(e.get("target", "")))]
        raw_leak = any((ctx.token_default in str(e.get("action", ""))
                        + str(e.get("target", "")))
                       for e in audit.get("entries", [])
                       if isinstance(e.get("ts"), (int, float)) and e["ts"] >= t_q)
        ok_query = ok_req and ok_req2 and bool(masked) and not raw_leak
        ev_query = ("?token= 鉴权 HTTP %s ok=%s；未知路径 ?token= HTTP %s；"
                    "审计含 token=*** 记录=%d 条，未脱敏原文=%s"
                    % (status, ok_req, status2, len(masked), raw_leak))
    except Exception as exc:
        ev_query = "?token= 脱敏验证异常（node 侧）：%r" % (exc,)

    notes_text = "；".join(notes)
    return (ok_requests and ok_entries and ok_leak and ok_query,
            "%s；%s；%s；%s" % (notes_text, ev_entries, ev_leak, ev_query))


def a6_registry(ctx):
    """A6：8 线程×5 次经 registry_update 并发读改写，计数精确、文件可解析。"""
    errors = []

    def worker():
        try:
            for _ in range(5):
                def fn(reg):
                    reg["counter"] = reg.get("counter", 0) + 1
                    dev = reg["devices"].setdefault(
                        "counter_dev", {"name": "counter_dev", "writes": 0})
                    dev["writes"] = dev.get("writes", 0) + 1
                xd.registry_update(fn)
        except Exception as exc:
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    try:
        raw_text = xd.REGISTRY.read_text(encoding="utf-8")
        reg = json.loads(raw_text)
        counter = reg.get("counter")
        writes = reg.get("devices", {}).get("counter_dev", {}).get("writes")
        ok = (not errors) and counter == 40 and writes == 40
        ev = ("8 线程×5 次并发读改写：counter=%s/40，writes=%s/40，"
              "文件 JSON 可解析=True，锁文件存在=%s%s"
              % (counter, writes,
                 Path(str(xd.REGISTRY) + ".lock").exists(),
                 ("；线程错误：" + ";".join(errors)) if errors else ""))
    except Exception as exc:
        ok = False
        ev = "注册表读取/解析失败：%r" % (exc,)
    leftovers = [p.name for p in xd.REGISTRY.parent.glob("*.tmp-*")]
    if leftovers:
        ok = False
        ev += "；残留临时文件：%s" % leftovers
    return ok, ev


def a7_tofu(ctx):
    """A7：首连记录指纹；换证书后被拒；--trust 后恢复且注册表更新。"""
    if not ctx.node_up:
        return False, "node 未就绪，无法验证（node 侧）"
    # ① 首次连接后注册表出现 64hex 指纹（A3/A5 经 xd 客户端首连触发 TOFU 记录）
    reg = xd.load_registry()
    entry = reg["devices"]["selftest"]
    stored = (entry.get("cert_fingerprint") or "")
    ok1 = stored == ctx.fp1 and len(stored) == 64 and stored == stored.lower()
    ev1 = "注册表指纹=%s…（与证书1指纹一致=%s）" % (stored[:16], stored == ctx.fp1)

    # ② 用第二套证书重启 node（同一端口、同一配置）
    try:
        ctx.node_main.stop()
        node2 = NodeProc("rotated", ctx.port_main, [], ctx.cfg, ctx.tmp,
                         cert=ctx.cert2, key=ctx.key2)
        ctx.nodes.append(node2)
        ctx.node_main = node2
        node2.ready(ctx.token_default)
        ctx.node_up = True
        ev2 = "node 已用证书2重启（指纹 %s…）" % ctx.fp2[:16]
    except Exception as exc:
        ctx.node_up = False
        return False, "%s；换证书重启失败（node 侧）：%r" % (ev1, exc)

    # ③ 旧指纹请求 → 本地拒绝（TOFU 开头，含期望/实际指纹），注册表不得被更新
    dev_old = dict(xd.load_registry()["devices"]["selftest"])
    ok3 = False
    try:
        xd.request(dev_old, "GET", "/v1/health", timeout=10)
        ev3 = "指纹变更后请求未被拒绝（客户端 bug）"
    except RuntimeError as exc:
        msg = str(exc)
        reg_fp = xd.load_registry()["devices"]["selftest"].get("cert_fingerprint")
        ok3 = (msg.startswith("TOFU") and ctx.fp1 in msg and ctx.fp2 in msg
               and reg_fp == ctx.fp1)
        ev3 = "拒绝信息首行=[%s]，含期望/实际指纹=%s/%s，注册表保持旧指纹=%s" % (
            msg.split("\n")[0][:60], ctx.fp1[:8], ctx.fp2[:8], reg_fp == ctx.fp1)
    except Exception as exc:
        ev3 = "异常类型错误（客户端 bug）：%r" % (exc,)

    # ④ --trust：确认新指纹，请求成功且注册表更新
    ok4 = False
    try:
        # xd.request 返回包络解包后的 data（无异常即请求成功，health data 含 status=up）
        data = xd.request(dev_old, "GET", "/v1/health", timeout=10, trust=True)
        new_fp = xd.load_registry()["devices"]["selftest"].get("cert_fingerprint")
        ok4 = (isinstance(data, dict) and data.get("status") == "up"
               and new_fp == ctx.fp2)
        ev4 = "--trust 后请求成功（data.status=%s），注册表指纹已更新为新指纹=%s" % (
            data.get("status"), new_fp == ctx.fp2)
    except Exception as exc:
        ev4 = "--trust 流程异常（客户端 bug）：%r" % (exc,)
    return ok1 and ok3 and ok4, "%s；%s；%s；%s" % (ev1, ev2, ev3, ev4)


def a8_compat(ctx):
    """A8：ping/info/exec/shot/ls/cat（附加 put/get 往返）行为不变。"""
    if not ctx.node_up:
        return False, "node 未就绪，无法验证（node 侧）"
    registry = xd.load_registry()
    failures = []
    evidences = []

    def check(name, ok, ev):
        evidences.append("%s:%s" % (name, ev))
        if not ok:
            failures.append("%s（%s）" % (name, ev))

    out, err, error = run_xd(["ping", "selftest"], registry)
    check("ping", error is None and "在线" in out and "往返" in out,
          "err=%s out=%r" % (error, out.strip()[:50]))

    out, err, error = run_xd(["info", "selftest"], registry)
    check("info", error is None and "主机" in out and "锁屏" in out,
          "err=%s 含主机=%s 含锁屏=%s" % (error, "主机" in out, "锁屏" in out))

    out, err, error = run_xd(["exec", "selftest", "echo", "smoke_a8_ok"], registry)
    check("exec", error is None and "smoke_a8_ok" in out and "退出码 0" in out,
          "err=%s 含退出码0=%s" % (error, "退出码 0" in out))

    shot_path = ctx.work / "a8_shot.png"
    out, err, error = run_xd(["shot", "selftest", "-o", str(shot_path)], registry)
    png_ok = shot_path.exists() and shot_path.read_bytes()[:8] == PNG_MAGIC
    check("shot", error is None and png_ok,
          "err=%s PNG头正确=%s size=%s" % (
              error, png_ok,
              shot_path.stat().st_size if shot_path.exists() else 0))

    out, err, error = run_xd(["ls", "selftest", str(ctx.work)], registry)
    check("ls", error is None and "a5_file.txt" in out and "共" in out,
          "err=%s 含a5_file.txt=%s 含共N项=%s" % (
              error, "a5_file.txt" in out, "共" in out))

    out, err, error = run_xd(["cat", "selftest", str(ctx.work / "a5_file.txt")], registry)
    check("cat", error is None and "smoke-a5" in out,
          "err=%s 内容命中=%s" % (error, "smoke-a5" in out))

    # 附加：put/get 往返（契约 11 兼容清单内的命令）
    src = ctx.work / "a8_put_src.bin"
    src.write_bytes(b"CrossDevice-A8-roundtrip-" + bytes(range(64)))
    out, err, error = run_xd(["put", "selftest", str(src),
                              str(ctx.work / "a8_put_remote.bin")], registry)
    check("put", error is None and "已上传" in out, "err=%s out=%r" % (error, out.strip()[:40]))
    back = ctx.work / "a8_get_back.bin"
    out, err, error = run_xd(["get", "selftest",
                              str(ctx.work / "a8_put_remote.bin"), str(back)], registry)
    roundtrip = back.exists() and back.read_bytes() == src.read_bytes()
    check("get", error is None and roundtrip, "err=%s 字节一致=%s" % (error, roundtrip))

    return not failures, "全部通过（%s）" % "；".join(evidences) if not failures \
        else "失败项：%s" % "；".join(failures)


# --------------------------------------------------------------------------
# 主流程
# --------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="CrossDevice S1 一键自测（A1–A8）")
    ap.add_argument("--keep", action="store_true", help="保留临时目录便于排障")
    ap.add_argument("--node", default=None, help="node.py 路径覆盖（默认 node/node.py）")
    opts = ap.parse_args()
    if opts.node:
        global NODE_PY
        NODE_PY = Path(opts.node).resolve()

    tmp = Path(tempfile.mkdtemp(prefix="xd_s1_smoke_"))
    ctx = Ctx()
    ctx.tmp = tmp
    ctx.token_default = TOKEN_DEFAULT
    ctx.token_tester = TOKEN_TESTER
    ctx.nodes = []
    ctx.node_main = None
    ctx.node_up = False
    print("临时目录：%s" % tmp)
    print("node.py：%s" % NODE_PY)
    print("-" * 76)

    exit_code = 1
    try:
        # 证书与配置（全部临时目录）
        tls1, tls2 = tmp / "tls1", tmp / "tls2"
        ctx.cert1, ctx.key1 = tls1 / "cert.pem", tls1 / "key.pem"
        ctx.cert2, ctx.key2 = tls2 / "cert.pem", tls2 / "key.pem"
        ctx.fp1 = gen_cert(tls1)
        ctx.fp2 = gen_cert(tls2)
        print("证书1指纹：%s" % ctx.fp1)
        print("证书2指纹：%s" % ctx.fp2)

        ctx.cfg = tmp / "config" / "node.json"
        ctx.cfg_plain = tmp / "config_plain" / "node.json"
        tokens = [{"name": "default", "token": TOKEN_DEFAULT},
                  {"name": "tester", "token": TOKEN_TESTER}]
        write_json(ctx.cfg, {
            "version": 1, "tokens": tokens,
            "tls": {"cert": str(ctx.cert1), "key": str(ctx.key1)},
            "audit": {"retention_days": 180},
        })
        write_json(ctx.cfg_plain, {
            "version": 1, "tokens": tokens,
            "tls": {"cert": str(ctx.cert1), "key": str(ctx.key1)},
            "audit": {"retention_days": 180},
        })

        # xd 注册表打补丁到临时目录（绝不触碰仓库 data/）
        ctx.port_main = free_port()
        ctx.port_plain = free_port()
        ctx.work = tmp / "work"
        ctx.work.mkdir(parents=True, exist_ok=True)
        xd.REGISTRY = tmp / "registry" / "devices.json"
        xd.DATA = xd.REGISTRY.parent
        xd.save_registry({"devices": {}})

        def seed(reg):
            reg["devices"]["selftest"] = {
                "name": "selftest", "ip": HOST, "port": ctx.port_main,
                "token": TOKEN_DEFAULT, "identity": "default",
                "cert_fingerprint": "", "added_at": time.time(),
                "last_seen": None, "info": {},
            }
        xd.registry_update(seed)
        ctx.dev = xd.load_registry()["devices"]["selftest"]

        # node 主实例（TLS）
        ctx.node_main = NodeProc("main", ctx.port_main, [], ctx.cfg, ctx.tmp,
                                 cert=ctx.cert1, key=ctx.key1)
        ctx.nodes.append(ctx.node_main)
        try:
            ctx.node_main.ready(TOKEN_DEFAULT)
            ctx.node_up = True
        except NodeNotReady as exc:
            ctx.node_up = False
            print("!! node 主实例未就绪（node 侧，可能尚未完成 S1 改造）：%s" % exc)
        print("-" * 76)

        for code, title, fn in [
            ("A1", "TLS", a1_tls),
            ("A2", "来源限制", a2_source_limit),
            ("A3", "鉴权", a3_auth),
            ("A4", "防重放", a4_replay),
            ("A5", "审计", a5_audit),
            ("A6", "注册表", a6_registry),
            ("A7", "TOFU", a7_tofu),
            ("A8", "兼容", a8_compat),
        ]:
            try:
                ok, evidence = fn(ctx)
            except Exception as exc:
                ok, evidence = False, "测试框架异常：%r" % (exc,)
            record(code, title, ok, evidence)

        passed = sum(1 for _, _, ok in RESULTS if ok)
        print("-" * 76)
        print("S1 自测：%d/8 通过" % passed)
        for code, title, ok in RESULTS:
            if not ok:
                print("  未通过：%s %s" % (code, title))
        exit_code = 0 if passed == len(RESULTS) == 8 else 1
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
