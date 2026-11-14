#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CrossDevice S2 阶段一键自测（验收载体，覆盖验收清单 C1–C10）。

用法：
    py tests/smoke_s2.py             # 快速档（大文件 256MB）+ 末尾 smoke_s1 回归
    py tests/smoke_s2.py --full      # 正式档（大文件 ≥2GB，实测耗时/峰值内存）
    py tests/smoke_s2.py --skip-s1   # 跳过末尾 smoke_s1 回归（调试用）
    py tests/smoke_s2.py --keep      # 保留临时目录便于排障

隔离性（绝不触碰真实 %LOCALAPPDATA%\\CrossDevice 与仓库 data/）：
    - 证书 / node 配置 / 注册表 / 工作目录 / 大文件全部落在临时目录；
    - xd.REGISTRY / xd.DATA 打补丁到临时文件；xd 子命令进程内经 run_xd（真实 argparse）；
    - 大文件 put/get 与中途 kill 用独立子进程跑（xd_runner 注入临时注册表，产物不入仓库）；
    - node 子进程 LOCALAPPDATA 兜底覆盖（照抄 smoke_s1 做法）；
    - finally 终止全部 node 子进程并清理临时目录。

复用 smoke_s1 脚手架（import smoke_s1）：NodeProc / gen_cert / raw_request / run_xd /
write_json / free_port / tail_text 等；record 使用本文件自己的 RESULTS，不污染 smoke_s1。
仅标准库。node/ 由并行阶段（SA-1）按契约改造，node 侧未就绪导致的 FAIL 在证据中
标注"node 侧待集成"。
"""

import argparse
import base64
import ctypes
import hashlib
import http.client
import json
import os
import random
import re
import shutil
import socket
import sqlite3
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

import smoke_s1                     # noqa: E402  复用 S1 脚手架
import xd                           # noqa: E402

# ---- 复用 smoke_s1 脚手架 -------------------------------------------------
NodeProc = smoke_s1.NodeProc
NodeNotReady = smoke_s1.NodeNotReady
raw_request = smoke_s1.raw_request
err_code = smoke_s1.err_code
gen_cert = smoke_s1.gen_cert
write_json = smoke_s1.write_json
free_port = smoke_s1.free_port
run_xd = smoke_s1.run_xd
tail_text = smoke_s1.tail_text
tls_context = smoke_s1.tls_context
HOST = smoke_s1.HOST
TOKEN_DEFAULT = smoke_s1.TOKEN_DEFAULT
TOKEN_TESTER = smoke_s1.TOKEN_TESTER

RESULTS = []


def record(code, title, ok, evidence):
    RESULTS.append((code, title, bool(ok)))
    evidence = " ".join(str(evidence).split())
    print("%s %s %s（%s）" % (code, title, "PASS" if ok else "FAIL", evidence))


# ---- 常量 -----------------------------------------------------------------
CHUNK = 4 * 1024 * 1024                     # 契约 §13：4MB 分块
BIG_SIZE = 256 * 1024 * 1024                # 快速档大文件
BIG_SIZE_FULL = 2 * 1024 * 1024 * 1024      # 正式档 ≥2GB
PEAK_LIMIT = 64 * 1024 * 1024               # 峰值内存通过线（4MB 分块 + base64/JSON + 解释器基线）


# --------------------------------------------------------------------------
# 基础设施（S2 增补）
# --------------------------------------------------------------------------

def raw2(ip, port, method, path, token=None, headers=None, payload=None, timeout=10):
    """带响应头的裸请求（C3/C6/C10：需要 X-File-Size / Content-Range / 状态码）。"""
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
        return resp.status, {k.lower(): v for k, v in resp.getheaders()}, data
    finally:
        try:
            conn.close()
        except Exception:
            pass


def bare_request(ip, port, method, path, token=None, headers=None, payload=None, timeout=10):
    """不带防重放头的裸请求（C10 缺头 → 400 用例），完全控制请求头。"""
    conn = http.client.HTTPSConnection(ip, port, context=tls_context(), timeout=timeout)
    try:
        conn.connect()
        hdrs = {}
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


def jdata(body):
    """裸响应体 → 包络 data（非成功包络返回 None）。"""
    try:
        parsed = json.loads(body.decode("utf-8"))
        return parsed.get("data") if parsed.get("ok") else None
    except Exception:
        return None


class S2Node:
    """S2 专用 node 子进程封装：不强制 --port/--config，支持 --instance 与配置文件端口。

    smoke_s1.NodeProc 硬编码 --port/--config，无法用于"配置文件端口顺延"与
    "--instance（与 --config 互斥）"用例（C7），故按同款模式另写本封装。
    """

    def __init__(self, tag, tmp, args):
        self.tag = tag
        self.log_path = tmp / ("node_%s.log" % tag)
        env = dict(os.environ)
        env["LOCALAPPDATA"] = str(tmp / "localappdata")   # 兜底：防 node 写真实目录
        self._fh = open(self.log_path, "wb")
        self.proc = subprocess.Popen(
            [sys.executable, str(smoke_s1.NODE_PY)] + list(args),
            stdout=self._fh, stderr=subprocess.STDOUT,
            cwd=str(tmp), env=env)

    def ready(self, token, port, timeout=30):
        deadline = time.time() + timeout
        last = ""
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise NodeNotReady("node[%s] 进程提前退出 code=%s，日志尾部：%s"
                                   % (self.tag, self.proc.returncode, tail_text(self.log_path)))
            try:
                status, _, body = raw2(HOST, port, "GET", "/v1/health",
                                       token=token, timeout=3)
                data = json.loads(body.decode("utf-8"))
                if status == 200 and data.get("ok") is True \
                        and data.get("data", {}).get("status") == "up":
                    return
                last = "HTTP %s %s" % (status, body[:160])
            except Exception as exc:
                last = repr(exc)
            time.sleep(0.4)
        raise NodeNotReady("node[%s] %d 秒内未就绪（端口 %d）：%s；日志尾部：%s"
                           % (self.tag, timeout, port, last, tail_text(self.log_path)))

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


# ---- 子进程内存采样（C4 口径：psapi GetProcessMemoryInfo） ------------------

class _PROCESS_MEMORY_COUNTERS(ctypes.Structure):
    _fields_ = [("cb", ctypes.c_ulong),
                ("PageFaultCount", ctypes.c_ulong),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t)]


def _process_memory(pid):
    """取进程 WorkingSetSize / PeakWorkingSetSize（ctypes psapi，仅标准库）。"""
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    kernel32 = ctypes.windll.kernel32
    psapi = ctypes.windll.psapi
    handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return None, None
    try:
        counters = _PROCESS_MEMORY_COUNTERS()
        counters.cb = ctypes.sizeof(_PROCESS_MEMORY_COUNTERS)
        if psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters),
                                      ctypes.sizeof(_PROCESS_MEMORY_COUNTERS)):
            return int(counters.WorkingSetSize), int(counters.PeakWorkingSetSize)
        return None, None
    finally:
        kernel32.CloseHandle(handle)


class MemorySampler:
    """子进程内存采样器：每 interval（默认 200ms）读 WorkingSetSize 取最大。"""

    def __init__(self, pid, interval=0.2):
        self.pid = pid
        self.interval = interval
        self.peak = 0
        self.samples = 0
        self.os_peak = 0                     # 采样窗口内见到的系统记录峰值（兜底参考）
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self):
        while not self._stop.wait(self.interval):
            ws, peak = _process_memory(self.pid)
            if ws:
                self.samples += 1
                self.peak = max(self.peak, ws)
            if peak:
                self.os_peak = max(self.os_peak, peak)

    def finish(self):
        self._stop.set()
        self._thread.join(timeout=3)
        self.peak = max(self.peak, self.os_peak)
        return self.peak


def make_xd_runner(tmp):
    """生成 xd 子进程运行器（放测试临时目录，不入仓库）：把 xd.REGISTRY 注入为
    临时注册表后按真实 argparse 执行子命令（供 C4 内存采样 / C5 中途 kill）。"""
    runner = tmp / "xd_runner.py"
    runner.write_text(
        "# -*- coding: utf-8 -*-\n"
        "# S2 冒烟专用 xd 子进程运行器（临时产物，不入仓库）\n"
        "import sys\n"
        "from pathlib import Path\n"
        "sys.path.insert(0, %r)\n"
        "import xd\n"
        "xd.REGISTRY = Path(%r)\n"
        "xd.DATA = xd.REGISTRY.parent\n"
        "sys.argv = ['xd'] + sys.argv[1:]\n"
        "xd.main()\n" % (str(ROOT), str(xd.REGISTRY)))
    return runner


def run_xd_subprocess(runner, argv, timeout, label="xd", progress=30):
    """子进程执行 xd 子命令（真实 argparse + 真实网络 + 内存采样）。

    返回 (exit_code, 输出文本, 耗时秒, 峰值内存字节)。超时杀进程返回码记 -1。
    """
    started = time.time()
    proc = subprocess.Popen(
        [sys.executable, str(runner)] + [str(a) for a in argv],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, encoding="utf-8", errors="replace")
    sampler = MemorySampler(proc.pid)
    parts = []
    timed_out = False
    while True:
        try:
            out, _ = proc.communicate(timeout=progress)
            parts.append(out or "")
            break
        except subprocess.TimeoutExpired:
            elapsed = time.time() - started
            print("  [%s] 子进程运行中… 已 %.0fs（上限 %.0fs，峰值已采样 %.1fMB）"
                  % (label, elapsed, timeout, sampler.peak / 1048576.0))
            if elapsed > timeout:
                timed_out = True
                proc.kill()
                out, _ = proc.communicate()
                parts.append(out or "")
                break
    peak = sampler.finish()
    elapsed = time.time() - started
    code = -1 if timed_out else proc.returncode
    return code, "".join(parts), elapsed, peak


# ---- 文件与探测辅助 --------------------------------------------------------

def make_random_file(path, size, progress_every=0):
    """os.urandom 分块造随机文件（不一次性占大内存），返回全文件 MD5。"""
    digest = hashlib.md5()
    written = 0
    block = 8 * 1024 * 1024
    with open(path, "wb") as fh:
        while written < size:
            n = min(block, size - written)
            chunk = os.urandom(n)
            fh.write(chunk)
            digest.update(chunk)
            written += n
            if progress_every and written % progress_every == 0:
                print("  [造文件] %d/%d MB" % (written // (1024 * 1024), size // (1024 * 1024)))
    return digest.hexdigest()


def file_md5(path):
    """流式计算已有文件 MD5（1MB 缓冲）。"""
    digest = hashlib.md5()
    with open(path, "rb") as fh:
        while True:
            block = fh.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def s2_endpoints_ready(ctx):
    """用已存在的小文件探测 /v1/fs/checksum 是否存在（区分 S2 端点与未知路由 404）。

    SA-1 并行期间 node/ 仍为 v0.2.0（S2 端点缺失）→ 返回 False，让相关项快速
    FAIL 并标注 node 侧待集成，避免白造大文件。
    """
    probe_file = ctx.tmp / "s2_probe.txt"
    probe_file.write_text("s2 probe", encoding="utf-8")
    try:
        xd.request(ctx.dev, "GET", "/v1/fs/checksum?" +
                   urllib.parse.urlencode({"path": str(probe_file)}), timeout=10)
        return True
    except Exception:
        return False


def node_version(ctx):
    try:
        data = xd.request(ctx.dev, "GET", "/v1/health", timeout=8)
        return str((data or {}).get("node_version"))
    except Exception:
        return "?"


def node_tokens():
    return [{"name": "default", "token": TOKEN_DEFAULT},
            {"name": "tester", "token": TOKEN_TESTER}]


def dev_dict(port, fingerprint=""):
    """直连设备字典（不经注册表，指纹预填避免 TOFU 写盘）。"""
    return {"name": "", "ip": HOST, "port": port, "token": TOKEN_DEFAULT,
            "identity": "default", "cert_fingerprint": fingerprint}


# ---- 白盒：定位 node 侧白名单 helper（契约 14.3"可独立调用"） ---------------

def _helper_bool(result):
    """helper 返回值 → 布尔（兼容 (ok, reason, norm) 元组与纯 bool 两种口径）。"""
    if isinstance(result, tuple) and result:
        return bool(result[0])
    return bool(result)


def _helper_roots(node_mod, root):
    """按 node 侧 normalize_real 口径规范化白名单根（白盒准备）。"""
    normalizer = getattr(node_mod, "normalize_real", None)
    if callable(normalizer):
        return [normalizer(str(root))]
    return [str(root)]


def find_workspace_helper(node_mod, root):
    """在 node 模块中定位白名单 helper 并用语义样例验证。

    验证协议：helper(根内路径)=真 且 helper(根外路径)=假 且 helper(根内/../x)=假。
    支持三种签名口径（SA-1 实际实现 workspace_hit(path)->(ok,reason,norm)，
    白名单根在模块全局 WORKSPACE_ROOTS）：
      ① fn(path) + 模块全局 WORKSPACE_ROOTS（预置后验证，白盒口径）；
      ② fn(path, roots)；
      ③ fn(path)。
    找不到返回 None（冒烟标注 node 侧待集成/命名未对齐）。
    """
    inside = str(root / "helper_probe_in.txt")
    outside_p = str(root.parent / "helper_probe_out.txt")
    escape = str(root / ".." / "helper_probe_esc.txt")
    keywords = ("workspace", "sandbox", "whitelist", "allow", "permit")

    def semantic_ok(r_in, r_out, r_esc):
        return _helper_bool(r_in) and not _helper_bool(r_out) and not _helper_bool(r_esc)

    for name in sorted(dir(node_mod)):
        if name.startswith("__"):
            continue
        attr = getattr(node_mod, name, None)
        if not callable(attr):
            continue
        low = name.lower()
        if not any(k in low for k in keywords):
            continue
        # 口径①：模块全局 WORKSPACE_ROOTS 预置后调用（白盒口径，验证后还原）
        if hasattr(node_mod, "WORKSPACE_ROOTS"):
            saved = getattr(node_mod, "WORKSPACE_ROOTS")
            try:
                setattr(node_mod, "WORKSPACE_ROOTS", _helper_roots(node_mod, root))
                if semantic_ok(attr(inside), attr(outside_p), attr(escape)):
                    return name, "全局 WORKSPACE_ROOTS 预置后：根内=真/根外=假/../穿越=假"
            except Exception:
                pass
            finally:
                try:
                    setattr(node_mod, "WORKSPACE_ROOTS", saved)
                except Exception:
                    pass
        # 口径②/③：显式传 roots 或无参
        for with_roots in (True, False):
            try:
                roots = _helper_roots(node_mod, root)
                if with_roots:
                    result = (attr(inside, roots), attr(outside_p, roots),
                              attr(escape, roots))
                else:
                    result = (attr(inside), attr(outside_p), attr(escape))
                if semantic_ok(*result):
                    return name, "%s 签名：根内=真/根外=假/../穿越=假" % (
                        "fn(path, roots)" if with_roots else "fn(path)")
            except TypeError:
                continue
            except Exception:
                break
    return None


# --------------------------------------------------------------------------
# C1–C10
# --------------------------------------------------------------------------

def c1_task_history(ctx, opts):
    """C1 任务历史：持久化可查 / 重启标 failed / 本人可见口径（404/403）。"""
    if not ctx.node_up:
        return False, "node 未就绪，无法验证（node 侧）"
    dev = ctx.dev
    notes = []

    # ① exec 记录 job_id → 任务历史可查（done，identity=default）
    data = xd.request(dev, "POST", "/v1/exec",
                      {"cmd": "echo c1_done_task", "timeout": 20}, timeout=40)
    job1 = data["job_id"]
    ctx.c1_job_id = job1
    xd.request(dev, "GET", "/v1/job/%s?wait=15" % job1, timeout=30)
    try:
        listing = xd.request(dev, "GET", "/v1/task/list?limit=50", timeout=15)
        entries = listing.get("entries", [])
        hit = [e for e in entries if e.get("id") == job1]
        ok_list = bool(hit) and hit[0].get("status") == "done" \
            and hit[0].get("identity") == "default"
        notes.append("task/list 命中=%s identity=%s total=%s"
                     % (bool(hit), hit[0].get("identity") if hit else "-",
                        listing.get("total")))
        detail = xd.request(dev, "GET", "/v1/task/%s" % job1, timeout=15)
        ok_detail = detail.get("id") == job1 \
            and "c1_done_task" in (detail.get("stdout") or "")
        notes.append("task/<id> 详情 stdout 命中=%s" % ok_detail)
    except Exception as exc:
        return False, "任务历史查询失败（node 侧待集成）：%r" % (exc,)

    # ② xd task ls CLI 可查
    out, err, error = run_xd(["task", "ls", "self"], xd.load_registry())
    ok_cli = error is None and job1 in out and "共" in out
    notes.append("xd task ls=%s（%s）" % (ok_cli, (error or "ok")[:60]))

    # ③ 长任务 → stop node → 重启同配置 → 原任务仍可查；遗留 running 被标 failed
    data = xd.request(dev, "POST", "/v1/exec",
                      {"cmd": "ping -n 30 127.0.0.1 >nul", "timeout": 300}, timeout=30)
    job2 = data["job_id"]
    job = xd.request(dev, "GET", "/v1/job/%s?wait=2" % job2, timeout=15)
    ok_running = job.get("status") == "running"
    notes.append("长任务启动态=%s" % job.get("status"))

    ctx.node_main.stop()
    time.sleep(1.0)
    ctx.node_main = NodeProc("main2", ctx.port_main, [], ctx.cfg, ctx.tmp,
                             cert=ctx.cert1, key=ctx.key1)
    ctx.nodes.append(ctx.node_main)
    ctx.node_main.ready(TOKEN_DEFAULT)

    listing2 = xd.request(dev, "GET", "/v1/task/list?limit=50", timeout=15)
    hit1 = [e for e in listing2.get("entries", []) if e.get("id") == job1]
    ok_after = bool(hit1) and hit1[0].get("identity") == "default"
    detail2 = xd.request(dev, "GET", "/v1/task/%s" % job2, timeout=15)
    stderr2 = detail2.get("stderr") or ""
    ok_failed = detail2.get("status") == "failed" and "重启，任务中断" in stderr2
    out3, err3, error3 = run_xd(["task", "ls", "self"], xd.load_registry())
    ok_cli2 = error3 is None and job2[:8] in out3
    notes.append("重启后原任务可查=%s（identity=%s）；遗留 running=%s→%s"
                 "（stderr 含'重启，任务中断'=%s）；xd task ls 重启后=%s"
                 % (ok_after, hit1[0].get("identity") if hit1 else "-",
                    "running", detail2.get("status"), "重启，任务中断" in stderr2, ok_cli2))

    # ④ 本人可见口径：tester 查 default 任务 → 404；default 伪造 identity=tester → 403
    status, _, body = raw2(HOST, ctx.port_main, "GET", "/v1/task/%s" % job1,
                           token=TOKEN_TESTER, timeout=8)
    ok_cross = status == 404 and err_code(body) == "NOT_FOUND"
    status2, _, body2 = raw2(HOST, ctx.port_main, "GET",
                             "/v1/task/list?" + urllib.parse.urlencode({"identity": "tester"}),
                             token=TOKEN_DEFAULT, timeout=8)
    ok_forge = status2 == 403 and err_code(body2) == "FORBIDDEN"
    notes.append("tester 查他人任务=%s（HTTP %s）；identity=tester 越权参数=%s（HTTP %s）"
                 % (ok_cross, status, ok_forge, status2))
    return (ok_list and ok_detail and ok_cli and ok_running and ok_after
            and ok_failed and ok_cli2 and ok_cross and ok_forge, "；".join(notes))


def c2_retention(ctx, opts):
    """C2 留存清理：sqlite 直接造数（超龄+超量）→ node 启动清理，先到先清；审计不受影响。"""
    cfg_dir = ctx.tmp / "c2"
    cfg = cfg_dir / "node.json"
    audit_dir = cfg_dir / "audit"
    audit_dir.mkdir(parents=True, exist_ok=True)
    old_audit = "audit-%s.jsonl" % time.strftime(
        "%Y%m%d", time.localtime(time.time() - 10 * 86400))
    (audit_dir / old_audit).write_text(json.dumps(
        {"ts": time.time() - 10 * 86400, "time": "c2-old", "identity": "default",
         "action": "POST /v1/exec", "target": "", "result": 200, "code": None,
         "client": HOST}, ensure_ascii=False) + "\n", encoding="utf-8")
    write_json(cfg, {
        "version": 1, "tokens": node_tokens(),
        "tls": {"cert": str(ctx.cert1), "key": str(ctx.key1)},
        "audit": {"retention_days": 180},
        "tasks": {"retention_days": 1, "max_entries": 5},   # 小阈值便于验证
        "workspace": [str(cfg_dir / "ws")],
    })

    db_path = cfg_dir / "tasks.db"
    now = time.time()
    ddl = ("CREATE TABLE IF NOT EXISTS jobs ("
           "id TEXT PRIMARY KEY, identity TEXT NOT NULL DEFAULT '', "
           "cmd TEXT NOT NULL, shell TEXT NOT NULL DEFAULT 'cmd', cwd TEXT, "
           "status TEXT NOT NULL, exit_code INTEGER, stdout TEXT, stderr TEXT, "
           "started_at REAL NOT NULL, ended_at REAL, duration REAL);"
           "CREATE INDEX IF NOT EXISTS idx_jobs_started_at ON jobs(started_at);"
           "CREATE INDEX IF NOT EXISTS idx_jobs_identity ON jobs(identity);")
    rows = []
    for i in range(4):      # 4 行超龄（3 天前 > retention 1 天）
        rows.append(("c2old%04d" % i, "default", "echo old-%d" % i, "cmd", None,
                     "done", 0, "", "", now - 3 * 86400 - i, now - 3 * 86400 - i + 0.5, 0.5))
    for i in range(8):      # 8 行新鲜（逐条递减 60s，保证可按 started_at 定序）
        rows.append(("c2new%04d" % i, "default", "echo new-%d" % i, "cmd", None,
                     "done", 0, "", "", now - 60 * (i + 1), now - 60 * (i + 1) + 0.5, 0.5))
    conn = sqlite3.connect(str(db_path))
    try:
        conn.executescript(ddl)
        conn.executemany("INSERT INTO jobs (id,identity,cmd,shell,cwd,status,exit_code,"
                         "stdout,stderr,started_at,ended_at,duration) "
                         "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", rows)
        conn.commit()
        before = conn.execute("SELECT COUNT(*) FROM jobs").fetchone()[0]
    finally:
        conn.close()

    node = NodeProc("c2", free_port(), [], cfg, ctx.tmp, cert=ctx.cert1, key=ctx.key1)
    ctx.nodes.append(node)
    node.ready(TOKEN_DEFAULT)
    time.sleep(0.5)         # 留出启动期清理落盘
    conn = sqlite3.connect(str(db_path))
    try:
        after_count, after_min = conn.execute(
            "SELECT COUNT(*), MIN(started_at) FROM jobs").fetchone()
    finally:
        conn.close()
    audit_alive = (audit_dir / old_audit).exists()
    age_cleared = after_min is None or after_min > now - 86400
    count_capped = after_count <= 5
    ok = before == 12 and age_cleared and count_capped and audit_alive
    ev = ("sqlite 预置 %d 行（4 超龄 3 天 + 8 新鲜，阈值 1 天/5 条）→ 启动后 %d 行、"
          "最老 started_at=%s（年龄清=%s，数量清≤5=%s）；10 天前审计文件 %s 存活=%s"
          "（清理不影响审计）；%s"
          % (before, after_count,
             "无" if after_min is None
             else time.strftime("%m-%d %H:%M", time.localtime(after_min)),
             age_cleared, count_capped, old_audit, audit_alive,
             "node 侧待集成" if not ok else ""))
    return ok, ev


def c3_sandbox(ctx, opts):
    """C3 沙箱：空 workspace 全拒（写方向）/读不受限；配置根 → 根内过、根外/穿越/
    junction 逃逸拒、8.3 短名规范化；白名单 helper 白盒直测。"""
    notes = []
    # 实例 W0：workspace 缺省（空 = 拒绝一切写/删/建目录/移动/上传）
    cfg_dir0 = ctx.tmp / "c3a"
    cfg0 = cfg_dir0 / "node.json"
    write_json(cfg0, {
        "version": 1, "tokens": node_tokens(),
        "tls": {"cert": str(ctx.cert1), "key": str(ctx.key1)},
        "audit": {"retention_days": 180},
    })
    seed_file = ctx.tmp / "c3_seed.txt"
    seed_file.write_text("c3 seed content", encoding="utf-8")
    port0 = free_port()
    node0 = NodeProc("c3a", port0, [], cfg0, ctx.tmp, cert=ctx.cert1, key=ctx.key1)
    ctx.nodes.append(node0)
    node0.ready(TOKEN_DEFAULT)

    deny_cases = [
        ("fs/write", "/v1/fs/write", {"path": str(ctx.tmp / "c3a_deny.txt"), "text": "x"}),
        ("fs/delete", "/v1/fs/delete", {"path": str(seed_file), "confirm": True}),
        ("fs/mkdir", "/v1/fs/mkdir", {"path": str(ctx.tmp / "c3a_dir")}),
        ("fs/move", "/v1/fs/move",
         {"src": str(seed_file), "dst": str(ctx.tmp / "c3a_moved")}),
        ("upload/begin", "/v1/fs/upload/begin",
         {"path": str(ctx.tmp / "c3a_up.bin"), "size": 1, "md5": "0" * 32}),
    ]
    deny_ok = []
    for label, path, payload in deny_cases:
        status, _, body = raw2(HOST, port0, "POST", path, token=TOKEN_DEFAULT,
                               payload=payload, timeout=10)
        deny_ok.append(status == 403 and err_code(body) == "SANDBOX_DENIED")
        notes.append("空根 %s→%s/%s" % (label, status, err_code(body) or "-"))

    read_cases = [
        ("fs/list", "/v1/fs/list?" + urllib.parse.urlencode({"path": str(ctx.tmp)})),
        ("fs/read", "/v1/fs/read?" + urllib.parse.urlencode({"path": str(seed_file)})),
        ("fs/stat", "/v1/fs/stat?" + urllib.parse.urlencode({"path": str(seed_file)})),
        ("download", "/v1/fs/download?" + urllib.parse.urlencode({"path": str(seed_file)})),
        ("checksum", "/v1/fs/checksum?" + urllib.parse.urlencode({"path": str(seed_file)})),
    ]
    read_ok = []
    for label, path in read_cases:
        status, _, body = raw2(HOST, port0, "GET", path, token=TOKEN_DEFAULT, timeout=15)
        read_ok.append(status == 200)
        notes.append("空根读 %s→%s" % (label, status))

    # 实例 W1：workspace = 根目录
    root = ctx.tmp / "c3_root"
    root.mkdir(parents=True, exist_ok=True)
    outside = ctx.tmp / "c3_outside"
    outside.mkdir(parents=True, exist_ok=True)
    cfg_dir1 = ctx.tmp / "c3b"
    cfg1 = cfg_dir1 / "node.json"
    write_json(cfg1, {
        "version": 1, "tokens": node_tokens(),
        "tls": {"cert": str(ctx.cert1), "key": str(ctx.key1)},
        "audit": {"retention_days": 180},
        "workspace": [str(root)],
    })
    port1 = free_port()
    node1 = NodeProc("c3b", port1, [], cfg1, ctx.tmp, cert=ctx.cert1, key=ctx.key1)
    ctx.nodes.append(node1)
    node1.ready(TOKEN_DEFAULT)

    def w1_post(path, payload):
        status, _, body = raw2(HOST, port1, "POST", path, token=TOKEN_DEFAULT,
                               payload=payload, timeout=15)
        return status, err_code(body)

    ok_inside = w1_post("/v1/fs/write",
                        {"path": str(root / "inside.txt"), "text": "ok"}) == (200, None)
    st_out, code_out = w1_post("/v1/fs/write",
                               {"path": str(outside / "outside.txt"), "text": "x"})
    ok_outside = st_out == 403 and code_out == "SANDBOX_DENIED"
    st_dot, code_dot = w1_post("/v1/fs/write",
                               {"path": str(root / ".." / "c3_escape.txt"), "text": "x"})
    ok_dotdot = st_dot == 403 and code_dot == "SANDBOX_DENIED"
    notes.append("配置根：根内写=%s 根外写=%s/%s ..穿越=%s/%s"
                 % (ok_inside, st_out, code_out or "-", st_dot, code_dot or "-"))

    # junction 逃逸（mklink /J 免管理员权限）：根内 junction 指向根外 → 经 junction 写被拒
    junction = root / "c3_jlink"
    mk = subprocess.run(["cmd", "/c", "mklink", "/J", str(junction), str(outside)],
                        capture_output=True, timeout=20)
    ok_junction = False
    if junction.exists():
        st, code = w1_post("/v1/fs/write",
                           {"path": str(junction / "escape.txt"), "text": "x"})
        ok_junction = st == 403 and code == "SANDBOX_DENIED"
        notes.append("junction 逃逸写→%s/%s" % (st, code or "-"))
    else:
        notes.append("junction 创建失败 rc=%s" % mk.returncode)
    if junction.exists():
        subprocess.run(["cmd", "/c", "rmdir", str(junction)],
                       capture_output=True, timeout=20)

    # 8.3 短名：根短名构造路径应命中白名单（规范化正确）；卷禁用 8.3 则跳过
    def short_name(path):
        buf = ctypes.create_unicode_buffer(1024)
        if ctypes.windll.kernel32.GetShortPathNameW(str(path), buf, 1024):
            return buf.value
        return ""

    short_root = short_name(root)
    short_outside = short_name(outside)
    skip_83 = not short_root
    ok_short_in = True
    ok_short_out = True
    if skip_83:
        notes.append("8.3 短名：GetShortPathNameW 返回空（卷禁用 8.3 生成），按约定跳过")
    else:
        st, code = w1_post("/v1/fs/write",
                           {"path": short_root + "\\c3_short_in.txt", "text": "ok"})
        ok_short_in = st == 200
        notes.append("8.3 根短名写→%s（命中白名单/规范化正确）" % st)
        if short_outside:
            st, code = w1_post("/v1/fs/write",
                               {"path": short_outside + "\\c3_short_out.txt", "text": "x"})
            ok_short_out = st == 403 and code == "SANDBOX_DENIED"
            notes.append("8.3 根外短名写→%s/%s" % (st, code or "-"))

    # 白盒：白名单 helper 可独立调用（契约 14.3）
    ok_helper = False
    node_dir = str(ROOT / "node")
    try:
        sys.modules.pop("node", None)
        if node_dir not in sys.path:
            sys.path.insert(0, node_dir)
        import node as node_mod
        helper = find_workspace_helper(node_mod, root)
        if helper:
            helper_name, helper_ev = helper
            ok_helper = True
            notes.append("白盒 helper node.%s（%s）" % (helper_name, helper_ev))
        else:
            notes.append("白盒：node 侧未找到可独立调用的白名单 helper"
                         "（node 侧待集成/命名未对齐）")
    except Exception as exc:
        notes.append("白盒 import node 失败：%r" % (exc,))

    ok = (all(deny_ok) and all(read_ok) and ok_inside and ok_outside and ok_dotdot
          and ok_junction and ok_short_in and ok_short_out and ok_helper)
    return ok, "；".join(notes)


def c4_big_file(ctx, opts):
    """C4 大文件：xd put/get 子进程上传下载，MD5 与字节级一致；记录耗时与峰值内存。"""
    if not ctx.node_up:
        return False, "node 未就绪，无法验证（node 侧）"
    if not s2_endpoints_ready(ctx):
        return False, ("node S2 流式端点未就绪（checksum 探测失败）→ node 侧待集成，"
                       "跳过大文件造数")
    size = ctx.big_size
    big = ctx.tmp / "big.bin"
    back = ctx.tmp / "big_back.bin"
    remote = str(ctx.work / "big_remote.bin")
    try:
        print("  [C4] 造随机文件 %d MB（os.urandom 分块）…" % (size // (1024 * 1024)))
        t0 = time.time()
        md5_local = make_random_file(big, size, progress_every=256 * 1024 * 1024)
        print("  [C4] 造文件完成 %.1fs md5=%s…" % (time.time() - t0, md5_local[:12]))
        limit_s = 3600 if opts.full else 900
        code, out, t_put, peak_put = run_xd_subprocess(
            ctx.runner, ["put", "self", str(big), remote], limit_s, label="C4-put")
        ok_put = code == 0 and "已上传" in out
        md5_remote = None
        try:
            data = xd.request(ctx.dev, "GET", "/v1/fs/checksum?" +
                              urllib.parse.urlencode({"path": remote}), timeout=120)
            md5_remote = (data or {}).get("md5")
        except Exception as exc:
            print("  [C4] checksum 异常（node 侧）：%r" % (exc,))
        ok_md5 = md5_remote == md5_local
        print("  [C4] 上传完成 %.1fs（峰值 %.1fMB），开始下载回读…" % (t_put, peak_put / 1048576.0))
        code2, out2, t_get, peak_get = run_xd_subprocess(
            ctx.runner, ["get", "self", remote, str(back)], limit_s, label="C4-get")
        ok_get = code2 == 0 and "已下载" in out2
        md5_back = file_md5(back) if back.exists() else None
        ok_round = md5_back == md5_local
        peak_ok = peak_put <= PEAK_LIMIT and peak_get <= PEAK_LIMIT
        ev = ("%dMB 档：put 子进程 %.1fs 峰值 %.1fMB / get %.1fs 峰值 %.1fMB"
              "（采样口径：每 200ms 读 WorkingSetSize 取最大，ctypes psapi "
              "GetProcessMemoryInfo，另以 PeakWorkingSetSize 兜底）；"
              "远端 checksum md5==本地=%s；下载回读 md5==本地（字节级）=%s；"
              "峰值≤%dMB（远小于文件）=%s"
              % (size // (1024 * 1024), t_put, peak_put / 1048576.0, t_get,
                 peak_get / 1048576.0, ok_md5, ok_round, PEAK_LIMIT // (1024 * 1024),
                 peak_ok))
        return (ok_put and ok_md5 and ok_get and ok_round and peak_ok, ev)
    finally:
        for p in (big, back):
            try:
                if p.exists():
                    p.unlink()
            except OSError:
                pass


def c5_resume(ctx, opts):
    """C5 断点续传：上传手发 2 块后重入 begin 验证 resume_offset；xd put 补完；
    下载子进程中途 kill → 断点文件 → 二次 get 续拉，MD5 一致。"""
    if not ctx.node_up:
        return False, "node 未就绪，无法验证（node 侧）"
    if not s2_endpoints_ready(ctx):
        return False, "node S2 流式端点未就绪 → node 侧待集成"
    notes = []
    f = ctx.tmp / "resume.bin"
    dl_file = ctx.tmp / "dlkill.bin"
    dl_local = ctx.tmp / "dlkill_local.bin"
    part = Path(str(dl_local) + ".crosspart")
    try:
        # ① 上传断点续传：begin + 手发 2 个 4MB chunk → 再 begin 验证复用会话
        size = 16 * 1024 * 1024
        remote = str(ctx.work / "resume_remote.bin")
        md5 = make_random_file(f, size)
        status, _, body = raw2(HOST, ctx.port_main, "POST", "/v1/fs/upload/begin",
                               token=TOKEN_DEFAULT,
                               payload={"path": remote, "size": size, "md5": md5},
                               timeout=15)
        data1 = jdata(body)
        if status != 200 or not data1:
            return False, "upload/begin 失败（node 侧）：HTTP %s %s" % (status, body[:120])
        up_id = data1["upload_id"]
        sent = 0
        with open(f, "rb") as fh:
            for _ in range(2):
                block = fh.read(CHUNK)
                st, _, bd = raw2(HOST, ctx.port_main, "POST", "/v1/fs/upload/chunk",
                                 token=TOKEN_DEFAULT,
                                 payload={"upload_id": up_id, "offset": sent,
                                          "data_b64": base64.b64encode(block).decode("ascii")},
                                 timeout=60)
                if st != 200 or not jdata(bd):
                    return False, "upload/chunk 失败（node 侧）：HTTP %s %s" % (st, bd[:120])
                sent += len(block)
        status, _, body = raw2(HOST, ctx.port_main, "POST", "/v1/fs/upload/begin",
                               token=TOKEN_DEFAULT,
                               payload={"path": remote, "size": size, "md5": md5},
                               timeout=15)
        data2 = jdata(body) or {}
        resume_offset = data2.get("resume_offset")
        ok_reuse = status == 200 and resume_offset == 2 * CHUNK
        notes.append("手发 2×4MB 后重入 begin：resume_offset=%s（期望 %d），"
                     "复用会话=%s" % (resume_offset, 2 * CHUNK,
                                      data2.get("upload_id") == up_id))
        code, out, _, _ = run_xd_subprocess(
            ctx.runner, ["put", "self", str(f), remote], 600, label="C5-put")
        ok_tail = code == 0 and "已上传" in out
        md5_remote = None
        try:
            d = xd.request(ctx.dev, "GET", "/v1/fs/checksum?" +
                           urllib.parse.urlencode({"path": remote}), timeout=60)
            md5_remote = (d or {}).get("md5")
        except Exception:
            pass
        ok_md5 = md5_remote == md5
        code3, out3, _, _ = run_xd_subprocess(
            ctx.runner, ["put", "self", str(f), remote, "--fresh"], 600, label="C5-fresh")
        ok_fresh = code3 == 0 and "已上传" in out3
        notes.append("xd put 续传补完=%s 最终 md5 一致=%s；--fresh 全新上传=%s"
                     % (ok_tail, ok_md5, ok_fresh))

        # ② 下载断点续传：xd get 子进程中途 kill → 断点文件 → 重新 get 续拉
        dl_size = 128 * 1024 * 1024
        dl_remote = str(ctx.work / "dlkill_remote.bin")
        md5_dl = make_random_file(dl_file, dl_size)
        codeU, outU, _, _ = run_xd_subprocess(
            ctx.runner, ["put", "self", str(dl_file), dl_remote], 600, label="C5-put-dl")
        if codeU != 0:
            return False, "；".join(notes) + "；下载源上传失败（node 侧）：%r" % outU[-120:]
        killed = False
        for _attempt in range(4):
            if part.exists():
                part.unlink()
            if dl_local.exists():
                dl_local.unlink()
            proc = subprocess.Popen(
                [sys.executable, str(ctx.runner), "get", "self", dl_remote, str(dl_local)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=str(ctx.tmp))
            deadline = time.time() + 300
            while time.time() < deadline and proc.poll() is None:
                try:
                    sz = part.stat().st_size
                except OSError:
                    sz = 0
                if 2 * 1024 * 1024 <= sz < dl_size - 4 * 1024 * 1024:
                    proc.kill()                 # 中途 kill
                    killed = True
                    break
                time.sleep(0.01)
            if proc.poll() is None:
                proc.kill()
            try:
                proc.wait(timeout=10)
            except Exception:
                pass
            if killed and part.exists():
                break
        part_size = part.stat().st_size if part.exists() else 0
        ok_part = killed and 0 < part_size < dl_size
        code2, out2, _, _ = run_xd_subprocess(
            ctx.runner, ["get", "self", dl_remote, str(dl_local)], 600, label="C5-get")
        ok_resume = code2 == 0 and "已下载" in out2
        md5_back = file_md5(dl_local) if dl_local.exists() else None
        ok_md5_dl = md5_back == md5_dl
        ok_clean = not part.exists()
        notes.append("下载中途 kill=%s 断点 %d/%d 字节（保留=%s）；二次 get 续拉=%s "
                     "md5 一致=%s 断点清理=%s"
                     % (killed, part_size, dl_size, ok_part, ok_resume, ok_md5_dl, ok_clean))
        return (ok_reuse and ok_tail and ok_md5 and ok_fresh and ok_part
                and ok_resume and ok_md5_dl and ok_clean, "；".join(notes))
    finally:
        for p in (f, dl_file, dl_local, part):
            try:
                if p.exists():
                    p.unlink()
            except OSError:
                pass


def c6_range(ctx, opts):
    """C6 Range 下载：随机三段闭区间偏移拉取，拼接与原文件字节一致；全量 200 头校验。"""
    if not ctx.node_up:
        return False, "node 未就绪，无法验证（node 侧）"
    if not s2_endpoints_ready(ctx):
        return False, "node S2 流式端点未就绪 → node 侧待集成"
    f = ctx.tmp / "range.bin"
    size = 8 * 1024 * 1024
    remote = str(ctx.work / "range_remote.bin")
    try:
        md5 = make_random_file(f, size)
        code, out, _, _ = run_xd_subprocess(
            ctx.runner, ["put", "self", str(f), remote], 300, label="C6-put")
        if code != 0:
            return False, "put 失败（node 侧）：%r" % out[-140:]
        url = "/v1/fs/download?" + urllib.parse.urlencode({"path": remote})
        rnd = random.Random(20261114)
        notes = []
        seg_ok = []
        for i in range(3):
            start = rnd.randrange(0, size - 1024)
            length = rnd.randrange(1024, 1024 * 1024)
            end = min(start + length - 1, size - 1)
            status, hdrs, body = raw2(HOST, ctx.port_main, "GET", url,
                                      token=TOKEN_DEFAULT,
                                      headers={"Range": "bytes=%d-%d" % (start, end)},
                                      timeout=30)
            with open(f, "rb") as fh:
                fh.seek(start)
                expect = fh.read(end - start + 1)
            content_range = hdrs.get("content-range", "")
            hit = (status == 206 and body == expect
                   and content_range == "bytes %d-%d/%d" % (start, end, size))
            seg_ok.append(hit)
            notes.append("段%d bytes=%d-%d→%s CR=%s 字节一致=%s"
                         % (i, start, end, status, content_range, body == expect))
        status, hdrs, body = raw2(HOST, ctx.port_main, "GET", url,
                                  token=TOKEN_DEFAULT, timeout=60)
        full_ok = (status == 200 and hdrs.get("x-file-size") == str(size)
                   and hdrs.get("x-file-md5") == md5
                   and hashlib.md5(body).hexdigest() == md5)
        notes.append("全量→%s X-File-Size=%s X-File-MD5 一致=%s"
                     % (status, hdrs.get("x-file-size"),
                        hdrs.get("x-file-md5") == md5))
        return all(seg_ok) and full_ok, "；".join(notes)
    finally:
        try:
            if f.exists():
                f.unlink()
        except OSError:
            pass


def occupy_ports(base, count):
    """连续占用 count 个端口（bind 即占，不必 listen），失败返回 None。"""
    socks = []
    for p in range(base, base + count):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.bind((HOST, p))
            socks.append(s)
        except OSError:
            for opened in socks:
                opened.close()
            return None
    return socks


def find_port_run(count, tries=300):
    """找一段连续空闲端口并全部占用，返回 (base, sockets)。"""
    for _ in range(tries):
        base = random.randrange(40000, 60000 - count)
        socks = occupy_ports(base, count)
        if socks:
            return base, socks
    raise RuntimeError("找不到 %d 个连续空闲端口" % count)


def c7_ports_instances(ctx, opts):
    """C7 端口与实例：配置端口顺延+持久化+复用；51 端口占满 → PORT_EXHAUSTED；
    --instance 两实例并行且文件/任务互不串扰。"""
    version = node_version(ctx)
    if version not in ("0.3.0", "0.4.0"):   # S3 起同时接受 0.4.0（SA-3 既定适配，其余断言不变）
        return False, ("node 侧待集成（node_version=%s，S2 端口顺延/多实例未实现，"
                       "跳过重试用例避免无效等待）" % version)
    notes = []

    # ① 配置端口顺延：node.json port=R 并占用 R → 启动绑定 R+1 且持久化 → 重启复用
    base, socks = find_port_run(2)
    socks[1].close()                        # 释放 R+1 供 node 顺延绑定；R 保持占用
    holder = socks[0]
    cfg_dir = ctx.tmp / "c7a"
    cfg = cfg_dir / "node.json"
    write_json(cfg, {
        "version": 1, "tokens": node_tokens(),
        "tls": {"cert": str(ctx.cert1), "key": str(ctx.key1)},
        "audit": {"retention_days": 180},
        "port": base,
    })
    ok_shift = ok_persist = ok_reuse = False
    try:
        node = S2Node("c7a", ctx.tmp, ["--host", HOST, "--config", str(cfg), "--verbose"])
        ctx.nodes.append(node)
        try:
            node.ready(TOKEN_DEFAULT, base + 1, timeout=25)
            ok_shift = True
        except NodeNotReady as exc:
            notes.append("顺延启动未就绪：%s" % str(exc)[:140])
        if ok_shift:
            persisted = json.loads(cfg.read_text(encoding="utf-8")).get("port")
            ok_persist = persisted == base + 1
            notes.append("R=%d 被占用 → 顺延绑定 %d，配置持久化 port=%s"
                         % (base, base + 1, persisted))
            node.stop()
            time.sleep(1.5)
            node2 = S2Node("c7a2", ctx.tmp,
                           ["--host", HOST, "--config", str(cfg), "--verbose"])
            ctx.nodes.append(node2)
            try:
                node2.ready(TOKEN_DEFAULT, base + 1, timeout=25)
                ok_reuse = True
                notes.append("重启复用持久化端口 %d" % (base + 1))
            except NodeNotReady as exc:
                notes.append("重启未复用：%s" % str(exc)[:140])
    finally:
        holder.close()

    # ② 51 个端口全占 → PORT_EXHAUSTED 非零退出
    base2, socks2 = find_port_run(51)
    try:
        cfg_dir2 = ctx.tmp / "c7b"
        cfg2 = cfg_dir2 / "node.json"
        write_json(cfg2, {
            "version": 1, "tokens": node_tokens(),
            "tls": {"cert": str(ctx.cert1), "key": str(ctx.key1)},
            "audit": {"retention_days": 180},
            "port": base2,
        })
        node_ex = S2Node("c7b", ctx.tmp,
                         ["--host", HOST, "--config", str(cfg2), "--verbose"])
        ctx.nodes.append(node_ex)
        t0 = time.time()
        try:
            rc = node_ex.proc.wait(timeout=120)
        except subprocess.TimeoutExpired:
            rc = None
        elapsed = time.time() - t0
        log = tail_text(node_ex.log_path, 2000)
        ok_exhaust = rc is not None and rc != 0 and "PORT_EXHAUSTED" in log
        notes.append("占用 %d..%d（51 个）→ 退出码 %s（%.1fs，观测 node 逐候选重试耗时）"
                     "输出含 PORT_EXHAUSTED=%s"
                     % (base2, base2 + 50, rc, elapsed, "PORT_EXHAUSTED" in log))
    finally:
        for s in socks2:
            s.close()

    # ③ --instance 两实例并行（不传 --config，LOCALAPPDATA 覆盖 + 默认配置目录
    #    <LOCALAPPDATA>\CrossDevice\node-<名>.json，与 S2Node 的环境覆盖一致）
    inst_la = ctx.tmp / "localappdata"
    la_cross = inst_la / "CrossDevice"
    la_cross.mkdir(parents=True, exist_ok=True)
    port_a, port_b = free_port(), free_port()
    for name, port in (("alpha", port_a), ("beta", port_b)):
        write_json(la_cross / ("node-%s.json" % name), {
            "version": 1, "tokens": node_tokens(),
            "tls": {"cert": str(ctx.cert1), "key": str(ctx.key1)},
            "audit": {"retention_days": 180},
            "workspace": [str(la_cross / ("ws_" + name))],
            "port": port,
        })
    node_a = S2Node("inst_alpha", ctx.tmp,
                    ["--host", HOST, "--instance", "alpha", "--verbose"])
    node_b = S2Node("inst_beta", ctx.tmp,
                    ["--host", HOST, "--instance", "beta", "--verbose"])
    ctx.nodes += [node_a, node_b]
    ok_a = ok_b = False
    try:
        node_a.ready(TOKEN_DEFAULT, port_a, timeout=25)
        ok_a = True
    except NodeNotReady as exc:
        notes.append("alpha 实例未就绪：%s" % str(exc)[:120])
    try:
        node_b.ready(TOKEN_DEFAULT, port_b, timeout=25)
        ok_b = True
    except NodeNotReady as exc:
        notes.append("beta 实例未就绪：%s" % str(exc)[:120])

    ok_files = ok_isolation = False
    if ok_a and ok_b:
        # 各自 exec 落任务/审计 → 文件分离 + 任务互不串扰
        job_a = job_b = None
        try:
            job_a = xd.request(dev_dict(port_a, ctx.fp1), "POST", "/v1/exec",
                               {"cmd": "echo alpha-c7", "timeout": 10},
                               timeout=30)["job_id"]
            job_b = xd.request(dev_dict(port_b, ctx.fp1), "POST", "/v1/exec",
                               {"cmd": "echo beta-c7", "timeout": 10},
                               timeout=30)["job_id"]
            time.sleep(0.5)
            ids_a = {e.get("id") for e in xd.request(
                dev_dict(port_a, ctx.fp1), "GET", "/v1/task/list?limit=50",
                timeout=15).get("entries", [])}
            ids_b = {e.get("id") for e in xd.request(
                dev_dict(port_b, ctx.fp1), "GET", "/v1/task/list?limit=50",
                timeout=15).get("entries", [])}
            ok_isolation = (job_a in ids_a and job_b in ids_b
                            and job_a not in ids_b and job_b not in ids_a)
        except Exception as exc:
            notes.append("实例任务隔离查询异常（node 侧）：%r" % (exc,))
        ok_files = ((la_cross / "node-alpha.json").exists()
                    and (la_cross / "node-beta.json").exists()
                    and (la_cross / "audit-alpha").is_dir()
                    and (la_cross / "audit-beta").is_dir()
                    and (la_cross / "tasks-alpha.db").exists()
                    and (la_cross / "tasks-beta.db").exists())
        notes.append("两实例并行 health 可用=%s/%s；node-alpha/beta.json、"
                     "audit-alpha/beta/、tasks-alpha/beta.db 分离=%s；任务互不串扰=%s"
                     % (ok_a, ok_b, ok_files, ok_isolation))
    ok = (ok_shift and ok_persist and ok_reuse and ok_exhaust
          and ok_a and ok_b and ok_files and ok_isolation)
    return ok, "；".join(notes)


def c8_naming_drift(ctx, opts):
    """C8 命名冲突与漂移：hostname 冲突自动 -2；显式 --name 冲突报错；
    伪造漂移（改条目 IP）→ 主机名/MAC 兜底（discover.scan 注入假结果，白盒口径）。"""
    if not ctx.node_up:
        return False, "node 未就绪，无法验证（node 侧）"
    notes = []
    port_a, port_b = free_port(), free_port()
    cfg_dir = ctx.tmp / "c8"
    cfg_a, cfg_b = cfg_dir / "node_a.json", cfg_dir / "node_b.json"
    for cfg in (cfg_a, cfg_b):
        write_json(cfg, {
            "version": 1, "tokens": node_tokens(),
            "tls": {"cert": str(ctx.cert1), "key": str(ctx.key1)},
            "audit": {"retention_days": 180},
            "workspace": [str(cfg_dir / "ws")],
        })
    node_a = NodeProc("c8a", port_a, [], cfg_a, ctx.tmp, cert=ctx.cert1, key=ctx.key1)
    node_b = NodeProc("c8b", port_b, [], cfg_b, ctx.tmp, cert=ctx.cert1, key=ctx.key1)
    ctx.nodes += [node_a, node_b]
    node_a.ready(TOKEN_DEFAULT)
    node_b.ready(TOKEN_DEFAULT)
    hostname = xd.request(dev_dict(port_a, ctx.fp1), "GET", "/v1/info",
                          timeout=10)["hostname"]

    # ① 两台 node（同机同 hostname）先后 add 均不带 --name → 第二个自动 -2 后缀
    out1, err1, error1 = run_xd(["add", HOST, "--port", str(port_a),
                                 "--token", TOKEN_DEFAULT], xd.load_registry())
    out2, err2, error2 = run_xd(["add", HOST, "--port", str(port_b),
                                 "--token", TOKEN_DEFAULT], xd.load_registry())
    reg = xd.load_registry()
    ok1 = error1 is None and hostname in reg["devices"]
    ok2 = error2 is None and ("%s-2" % hostname) in reg["devices"]
    entry = reg["devices"].get(hostname, {})
    notes.append("add×2（不带 --name）→ %s%s、%s%s；条目含 mac=%s ips=%s"
                 % (hostname, "✓" if ok1 else "(%s)" % error1,
                    "%s-2" % hostname, "✓" if ok2 else "(%s)" % error2,
                    "mac" in entry, "ips" in entry))
    ok_suffix = ok1 and ok2

    # ② 显式 --name 冲突 → 报错退出，且不覆盖旧条目
    out3, err3, error3 = run_xd(["add", HOST, "--port", str(port_a),
                                 "--token", TOKEN_DEFAULT, "--name", hostname],
                                xd.load_registry())
    reg3 = xd.load_registry()
    ok_conflict = error3 is not None and "已存在" in error3 \
        and reg3["devices"].get(hostname, {}).get("port") == port_a
    notes.append("显式 --name 冲突 → 本地报错=%s（%s），旧条目未被覆盖=%s"
                 % (bool(error3), (error3 or "")[:70],
                    reg3["devices"].get(hostname, {}).get("port") == port_a))

    # ③ 伪造漂移：条目 ip/ips 全部指向不可达地址 → 主机名兜底（patch discover.scan）
    drift_name = hostname
    real_port = port_a

    def set_drift(registry):
        entry = registry["devices"][drift_name]
        entry["ip"] = "127.0.0.2"
        entry["port"] = real_port
        entry["ips"] = ["127.0.0.3"]
        entry["mac"] = "AA:BB:CC:DD:EE:FF"
        entry["cert_fingerprint"] = ctx.fp1
        entry["info"] = {"hostname": hostname}

    xd.registry_update(set_drift)
    fake_scan_host = {"self_ip": HOST, "network": "127.0.0.0/8",
                      "devices": [{"ip": HOST, "mac": "AA:BB:CC:DD:EE:FF",
                                   "hostname": hostname, "self": False}]}
    orig_scan = xd.discover.scan
    ok_host = ok_host_persist = False
    try:
        xd.discover.scan = lambda *a, **k: dict(fake_scan_host)   # 白盒口径：注入假扫描
        out_p, err_p, error_p = run_xd(["ping", drift_name], xd.load_registry())
        ok_host = error_p is None and "在线" in out_p
        reg_now = xd.load_registry()
        ok_host_persist = reg_now["devices"][drift_name]["ip"] == HOST
    finally:
        xd.discover.scan = orig_scan
    notes.append("伪造漂移（ip→127.0.0.2）：主机名兜底 ping=%s 落盘新 ip=%s"
                 "（discover.scan 注入假结果，白盒口径）" % (ok_host, ok_host_persist))

    # ④ MAC 兜底：主机名不可得（info.hostname 清空）→ patch scan 仅 mac 匹配
    def set_mac_only(registry):
        entry = registry["devices"][drift_name]
        entry["ip"] = "127.0.0.2"
        entry["port"] = real_port
        entry["ips"] = ["127.0.0.3"]
        entry["mac"] = "AA:BB:CC:DD:EE:FF"
        entry["info"] = {"hostname": ""}

    xd.registry_update(set_mac_only)
    fake_scan_mac = {"self_ip": HOST, "network": "127.0.0.0/8",
                     "devices": [{"ip": HOST, "mac": "AA:BB:CC:DD:EE:FF",
                                  "hostname": "other-host", "self": False}]}
    ok_mac = ok_mac_persist = False
    try:
        xd.discover.scan = lambda *a, **k: dict(fake_scan_mac)
        out_m, err_m, error_m = run_xd(["ping", drift_name], xd.load_registry())
        ok_mac = error_m is None and "在线" in out_m
        reg_m = xd.load_registry()
        ok_mac_persist = reg_m["devices"][drift_name]["ip"] == HOST
    finally:
        xd.discover.scan = orig_scan
    notes.append("主机名不可得：MAC 兜底 ping=%s 落盘新 ip=%s"
                 "（discover.scan 注入假结果，白盒口径）" % (ok_mac, ok_mac_persist))
    return (ok_suffix and ok_conflict and ok_host and ok_host_persist
            and ok_mac and ok_mac_persist, "；".join(notes))


def c9_cli(ctx, opts):
    """C9 CLI 对齐：wheel/task/del/mkdir/mv 全链路；del 缺 --yes 本地拒；越界拒。"""
    if not ctx.node_up:
        return False, "node 未就绪，无法验证（node 侧）"
    notes = []
    reg = xd.load_registry()

    # wheel：输入生效或明确报"未生效"（锁屏/非交互）均算 CLI 可用
    out_w, err_w, error_w = run_xd(["wheel", "self", "120"], xd.load_registry())
    out_w2, err_w2, error_w2 = run_xd(["wheel", "self", "-3"], xd.load_registry())
    wheel_msgs = (out_w + err_w + str(error_w or "") + out_w2 + err_w2
                  + str(error_w2 or ""))
    if (error_w is None and "已发送" in out_w) or \
            (error_w2 is None and "已发送" in out_w2):
        ok_wheel = True
        notes.append("wheel 输入已生效（+/−delta）")
    elif any(k in wheel_msgs for k in ("未生效", "锁屏", "交互")):
        ok_wheel = True
        notes.append("wheel 明确报未生效（锁屏/非交互环境，两种结果都算可用）：%s"
                     % (str(error_w or error_w2)[:70]))
    else:
        ok_wheel = False
        notes.append("wheel 异常：%r %r" % (error_w, out_w[:60]))

    # del 缺 --yes → 控制端本地拒绝（不发请求）
    out_d, err_d, error_d = run_xd(["del", "self", str(ctx.work / "no_such_c9.txt")],
                                   xd.load_registry())
    ok_del_guard = error_d is not None and "--yes" in error_d
    notes.append("del 缺 --yes → 本地拒绝=%s（%s）"
                 % (ok_del_guard, (error_d or "")[:70]))

    # del --yes / mkdir / mv 正向（白名单内）与越界（SANDBOX_DENIED）
    target = ctx.work / "c9_del.txt"
    mkdir_dir = ctx.work / "c9_mkdir"
    mv_src = ctx.work / "c9_mv_src.txt"
    mv_dst = ctx.work / "c9_mv_dst.txt"
    try:
        xd.request(ctx.dev, "POST", "/v1/fs/write",
                   {"path": str(target), "text": "c9"}, timeout=15)
        xd.request(ctx.dev, "POST", "/v1/fs/write",
                   {"path": str(mv_src), "text": "c9"}, timeout=15)
    except Exception as exc:
        notes.append("fs/write 造数失败（node 侧）：%r" % (exc,))

    out_d2, err_d2, error_d2 = run_xd(["del", "self", str(target), "--yes"],
                                      xd.load_registry())
    ok_del = error_d2 is None and "已删除" in out_d2 and not target.exists()
    notes.append("del --yes=%s（%s）" % (ok_del, (error_d2 or "已删除")[:60]))

    out_m, err_m, error_m = run_xd(["mkdir", "self", str(mkdir_dir)],
                                   xd.load_registry())
    ok_mkdir = error_m is None and "已创建目录" in out_m and mkdir_dir.is_dir()
    notes.append("mkdir=%s（目录落地=%s）" % (ok_mkdir, mkdir_dir.is_dir()))

    out_mv, err_mv, error_mv = run_xd(["mv", "self", str(mv_src), str(mv_dst)],
                                      xd.load_registry())
    ok_mv = error_mv is None and mv_dst.exists() and not mv_src.exists()
    notes.append("mv 白名单内=%s" % ok_mv)

    out_x, err_x, error_x = run_xd(["mv", "self", str(mv_dst),
                                    str(ctx.tmp / "c9_escape.txt")],
                                   xd.load_registry())
    ok_mv_escape = error_x is not None and "SANDBOX_DENIED" in error_x
    notes.append("mv 越界（dst 在根外）→ SANDBOX_DENIED=%s" % ok_mv_escape)

    out_y, err_y, error_y = run_xd(["del", "self", str(ctx.tmp / "c3_seed.txt"),
                                    "--yes"], xd.load_registry())
    ok_del_escape = error_y is not None and "SANDBOX_DENIED" in error_y
    notes.append("del 越界（根外）→ SANDBOX_DENIED=%s" % ok_del_escape)

    # task ls / task show（含 stdout/stderr 详情）
    out_tl, err_tl, error_tl = run_xd(["task", "ls", "self"], xd.load_registry())
    ok_task_ls = error_tl is None and "共" in out_tl
    notes.append("task ls=%s（%s）" % (ok_task_ls, (error_tl or "ok")[:60]))
    show_target = getattr(ctx, "c1_job_id", "") or ("0" * 12)
    out_ts, err_ts, error_ts = run_xd(["task", "show", "self", show_target],
                                      xd.load_registry())
    ok_task_show = error_ts is None and ("任务ID" in out_ts or "stdout" in out_ts)
    notes.append("task show=%s（%s）" % (ok_task_show, (error_ts or "ok")[:60]))
    ok = (ok_wheel and ok_del_guard and ok_del and ok_mkdir and ok_mv
          and ok_mv_escape and ok_del_escape and ok_task_ls and ok_task_show)
    return ok, "；".join(notes)


def c10_audit_regression(ctx, opts):
    """C10 回归与审计：新端点有审计记录；SANDBOX_DENIED 条目 target/code；
    新端点防重放（缺头 400 / 同 nonce 409）；smoke_s1 回归 8/8。"""
    if not ctx.node_up:
        return False, "node 未就绪，无法验证（node 侧）"
    notes = []
    dev = ctx.dev
    audit = xd.request(dev, "GET", "/v1/audit?limit=1000", timeout=20)
    entries = audit.get("entries", [])
    wanted = ["POST /v1/fs/upload/begin", "POST /v1/fs/upload/chunk",
              "POST /v1/fs/upload/commit", "GET /v1/fs/download",
              "GET /v1/fs/checksum", "GET /v1/task/list", "POST /v1/fs/delete"]
    missing = [w for w in wanted
               if not any(w in str(e.get("action", "")) for e in entries)]
    ok_audit = not missing
    notes.append("新端点审计记录缺失=%s（前置用例未跑到的端点计入缺失）" % (missing or "无"))

    sb = [e for e in entries if e.get("code") == "SANDBOX_DENIED"]
    ok_sb = bool(sb) and all(str(e.get("target") or "") for e in sb)
    notes.append("SANDBOX_DENIED 条目=%d，target 均非空=%s"
                 % (len(sb), all(str(e.get("target") or "") for e in sb) if sb else "-"))

    probe_file = ctx.tmp / "s2_probe.txt"
    if not probe_file.exists():
        probe_file.write_text("s2 probe", encoding="utf-8")
    url = "/v1/fs/checksum?" + urllib.parse.urlencode({"path": str(probe_file)})
    status, body = bare_request(HOST, ctx.port_main, "GET", url,
                                token=TOKEN_DEFAULT, timeout=8)
    ok_missing_hdr = status == 400 and err_code(body) == "BAD_REQUEST"
    nonce = uuid.uuid4().hex
    replay_hdr = {"X-Timestamp": str(int(time.time())), "X-Nonce": nonce}
    s1st, b1 = bare_request(HOST, ctx.port_main, "GET", url,
                            token=TOKEN_DEFAULT, headers=dict(replay_hdr), timeout=8)
    s2st, b2 = bare_request(HOST, ctx.port_main, "GET", url,
                            token=TOKEN_DEFAULT, headers=dict(replay_hdr), timeout=8)
    ok_replay = s1st != 409 and s2st == 409 and err_code(b2) == "REPLAY_DETECTED"
    notes.append("新端点缺防重放头→%s/%s；同 nonce 重放：首次 %s → 重放 %s/%s"
                 % (status, err_code(body) or "-", s1st, s2st, err_code(b2) or "-"))

    ok_s1 = True
    if opts.skip_s1:
        notes.append("smoke_s1 回归已跳过（--skip-s1，调试模式不计入失败）")
    else:
        print("  [C10] 子进程运行 tests/smoke_s1.py 回归…")
        try:
            proc = subprocess.run([sys.executable, str(HERE / "smoke_s1.py")],
                                  capture_output=True, text=True, encoding="utf-8",
                                  errors="replace", timeout=900, cwd=str(ROOT))
            out_s1 = (proc.stdout or "") + (proc.stderr or "")
            match = re.search(r"S1 自测：(\d)/8 通过", out_s1)
            ok_s1 = proc.returncode == 0 and "8/8 通过" in out_s1
            notes.append("smoke_s1 子进程 → rc=%s %s%s"
                         % (proc.returncode, match.group(0) if match else "未找到汇总行",
                            "" if ok_s1 else
                            "（node 未升级 0.3.0 时 A8 的 put/get 走新流式端点预期 FAIL，"
                            "属既定的 node 侧待集成）"))
        except Exception as exc:
            ok_s1 = False
            notes.append("smoke_s1 子进程异常：%r" % (exc,))
    return ok_audit and ok_sb and ok_missing_hdr and ok_replay and ok_s1, "；".join(notes)


# --------------------------------------------------------------------------
# 主流程
# --------------------------------------------------------------------------

class Ctx:
    pass


def main():
    ap = argparse.ArgumentParser(description="CrossDevice S2 一键自测（C1–C10）")
    ap.add_argument("--full", action="store_true",
                    help="正式档：大文件 ≥2GB（默认快速档 256MB）")
    ap.add_argument("--skip-s1", action="store_true",
                    help="跳过末尾 smoke_s1 回归（调试用）")
    ap.add_argument("--keep", action="store_true", help="保留临时目录便于排障")
    opts = ap.parse_args()

    tmp = Path(tempfile.mkdtemp(prefix="xd_s2_smoke_"))
    ctx = Ctx()
    ctx.tmp = tmp
    ctx.big_size = BIG_SIZE_FULL if opts.full else BIG_SIZE
    ctx.nodes = []
    ctx.node_main = None
    ctx.node_up = False
    print("临时目录：%s" % tmp)
    print("node.py：%s" % smoke_s1.NODE_PY)
    print("大文件档：%s" % ("--full ≥2GB" if opts.full else "快速 256MB"))
    print("-" * 76)

    exit_code = 1
    try:
        # 证书与配置（全部临时目录）
        tls1 = tmp / "tls1"
        ctx.cert1, ctx.key1 = tls1 / "cert.pem", tls1 / "key.pem"
        ctx.fp1 = gen_cert(tls1)
        print("证书指纹：%s" % ctx.fp1)

        ctx.port_main = free_port()
        ctx.work = tmp / "work"
        ctx.work.mkdir(parents=True, exist_ok=True)
        ctx.cfg = tmp / "config" / "node.json"
        write_json(ctx.cfg, {
            "version": 1, "tokens": node_tokens(),
            "tls": {"cert": str(ctx.cert1), "key": str(ctx.key1)},
            "audit": {"retention_days": 180},
            "workspace": [str(ctx.work)],          # 主实例白名单覆盖工作目录（契约 §14.5）
        })

        # xd 注册表打补丁到临时目录（绝不触碰仓库 data/）
        xd.REGISTRY = tmp / "registry" / "devices.json"
        xd.DATA = xd.REGISTRY.parent
        xd.save_registry({"devices": {}})

        def seed(reg):
            reg["devices"]["self"] = {
                "name": "self", "ip": HOST, "port": ctx.port_main,
                "token": TOKEN_DEFAULT, "identity": "default",
                "cert_fingerprint": "", "mac": "", "ips": [],
                "added_at": time.time(), "last_seen": None, "info": {},
            }
        xd.registry_update(seed)
        ctx.dev = xd.load_registry()["devices"]["self"]
        ctx.runner = make_xd_runner(tmp)

        # node 主实例（workspace=工作目录；S2 端点未就绪时相关项 FAIL 并标注）
        ctx.node_main = NodeProc("main", ctx.port_main, [], ctx.cfg, ctx.tmp,
                                 cert=ctx.cert1, key=ctx.key1)
        ctx.nodes.append(ctx.node_main)
        try:
            ctx.node_main.ready(TOKEN_DEFAULT)
            ctx.node_up = True
            print("node 主实例就绪，node_version=%s" % node_version(ctx))
        except NodeNotReady as exc:
            ctx.node_up = False
            print("!! node 主实例未就绪（node 侧，可能尚未完成 S2 改造）：%s" % exc)
        print("-" * 76)

        for code, title, fn in [
            ("C1", "任务历史", c1_task_history),
            ("C2", "留存清理", c2_retention),
            ("C3", "沙箱白名单", c3_sandbox),
            ("C4", "大文件流式", c4_big_file),
            ("C5", "断点续传", c5_resume),
            ("C6", "Range 下载", c6_range),
            ("C7", "端口与实例", c7_ports_instances),
            ("C8", "命名冲突与漂移", c8_naming_drift),
            ("C9", "CLI 对齐", c9_cli),
            ("C10", "回归与审计", c10_audit_regression),
        ]:
            try:
                ok, evidence = fn(ctx, opts)
            except Exception as exc:
                ok, evidence = False, "测试框架异常：%r" % (exc,)
            record(code, title, ok, evidence)

        passed = sum(1 for _, _, ok in RESULTS if ok)
        print("-" * 76)
        print("S2 自测：%d/%d 通过" % (passed, len(RESULTS)))
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
