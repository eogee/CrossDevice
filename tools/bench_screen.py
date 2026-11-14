#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CrossDevice B7 截屏压测（S4，需求 11.2 截屏行 / FR-05 / D18）。

压测对象：node 自研 PNG 截屏链路（GDI BitBlt 采集 + BGRA→RGB + zlib 压缩），
按契约默认参数请求原始尺寸（max_width=0，D18，不缩放、不分块）。

压测口径：自起临时 node 实例（绝不指向用户真实 node 实例），对
GET /v1/screen?monitor=<N>&max_width=0 连发 N 次（默认 10，与 11.2
"重复 10 次取中位数"口径一致），逐次记录端到端耗时（每次请求独立 TLS
连接、含握手开销，口径保守），输出中位数 / 最大值（秒）、每次与平均
PNG 字节数、node 进程内存峰值（psapi GetProcessMemoryInfo：200ms 采样
WorkingSetSize，PeakWorkingSetSize 兜底取大，照抄 tests/smoke_s2.py 口径）。

隔离性（绝不触碰真实 %LOCALAPPDATA%\\CrossDevice 与仓库文件）：
    - 证书（tools/gen_cert.ps1）、node 配置、日志全部落在 tempfile 临时目录；
    - node 子进程以覆盖后的 LOCALAPPDATA 启动（兜底防 node 忽略 --config
      时写真实目录，照抄 tests/smoke_s1.py 的 NodeProc 做法）；
    - finally 终止 node 进程并清理临时目录（--keep 可保留排障）；
    - 本脚本除 --out 指定的输出文件外不写任何仓库文件。

分辨率矩阵（S4 提示词 §3.2，三项资源已确认）：
    档 1（必测）：本机当前虚拟桌面 monitor=-1（单 1080p 屏时即 1080p 档）；
    档 2（如适用）：多屏环境逐显示器 monitor=0..N-1 各测一轮；单屏则如实
                    标注"单屏环境，逐显示器档不适用"；
    档 3（4K）：无 4K 资源，不实测，如实标注"4K 基线留实机"（Hyper-V
                虚拟方案本轮未采用，不作验收失败项）。

用法：
    py tools/bench_screen.py                  # 标准矩阵（虚拟桌面档 + 逐显示器档）
    py tools/bench_screen.py --runs 10        # 每档连发次数（默认 10）
    py tools/bench_screen.py --monitor 0      # 只压测指定显示器一档（0 起）
    py tools/bench_screen.py --out 结果.md    # 追加写出 markdown 结果段
    py tools/bench_screen.py --keep           # 保留临时目录便于排障

仅标准库；不 import tests/ 下模块（独立脚本，可入库复跑）。显示器清单与
虚拟桌面尺寸一律取自 node /v1/info 的 monitors / virtual_screen 字段，
本脚本不直接调用 Win32 枚举。
"""

import argparse
import base64
import ctypes
import hashlib
import http.client
import json
import os
import shutil
import socket
import ssl
import statistics
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path

sys.dont_write_bytecode = True      # 不在仓库中生成 __pycache__

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
GEN_CERT_PS1 = ROOT / "tools" / "gen_cert.ps1"
NODE_PY = ROOT / "node" / "node.py"

HOST = "127.0.0.1"
TOKEN = "5f8c1d2e3a4b5c6d7e8f9a0b1c2d3e4f"   # 固定测试令牌（32 hex，仅临时实例）
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
REQUEST_TIMEOUT = 30          # 单次截屏请求超时（秒；1080p 门槛 2s 的 15 倍余量）
READY_TIMEOUT = 45            # node 就绪等待（秒）
SAMPLE_INTERVAL = 0.2         # 内存采样间隔（秒，照抄 smoke_s2 口径）

# 11.2 截屏行门槛：1920×1080 原始尺寸 ≤ 2 秒（10 次取中位数）
GATE_WIDTH, GATE_HEIGHT, GATE_SECONDS = 1920, 1080, 2.0


# --------------------------------------------------------------------------
# 基础设施（照抄 tests/smoke_s1.py / smoke_s2.py 思路，不 import 测试模块）
# --------------------------------------------------------------------------

def free_port():
    """取一个空闲回环端口（bind 0 后释放；存在极小竞态窗口，冒烟同款可接受）。"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((HOST, 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def tls_context():
    """自签 + TOFU 场景的客户端上下文：不校验证书链与主机名（契约 §4.3）。"""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def raw_request(ip, port, method, path, token=None, timeout=REQUEST_TIMEOUT):
    """裸请求（照抄 tests/smoke_s1.py raw_request）：TLS 不校验自签 +
    X-Auth-Token + X-Timestamp / X-Nonce 防重放头（每次请求新 nonce，契约 §3.3）。
    返回 (HTTP 状态码, 响应体字节)；每次请求独立连接（含 TLS 握手开销）。"""
    conn = http.client.HTTPSConnection(ip, port, context=tls_context(), timeout=timeout)
    try:
        conn.connect()
        hdrs = {
            "X-Timestamp": str(int(time.time())),
            "X-Nonce": uuid.uuid4().hex,
        }
        if token:
            hdrs["X-Auth-Token"] = token
        conn.request(method, path, body=None, headers=hdrs)
        resp = conn.getresponse()
        data = resp.read()
        return resp.status, data
    finally:
        try:
            conn.close()
        except Exception:
            pass


def pem_sha256(path):
    """证书 PEM → DER 的 SHA-256 小写 64 hex（契约 §4.1 指纹口径）。"""
    text = Path(path).read_bytes().decode("utf-8-sig")
    b64 = "".join(line.strip() for line in text.splitlines()
                  if line.strip() and not line.startswith("-----"))
    der = base64.b64decode(b64)
    return hashlib.sha256(der).hexdigest()


def gen_cert(out_dir):
    """调 tools/gen_cert.ps1 造证书到临时目录（照抄 tests/smoke_s1.py gen_cert）。"""
    ps = shutil.which("powershell") or "powershell"
    cmd = [ps, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(GEN_CERT_PS1),
           "-OutDir", str(out_dir), "-Days", "2", "-Force"]
    proc = subprocess.run(cmd, capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=180)
    cert, key = Path(out_dir) / "cert.pem", Path(out_dir) / "key.pem"
    if proc.returncode != 0 or not cert.exists() or not key.exists():
        raise RuntimeError("gen_cert.ps1 失败（code=%s）：%s %s"
                           % (proc.returncode, (proc.stdout or "")[-400:],
                              (proc.stderr or "")[-400:]))
    return pem_sha256(cert)


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


# ---- 子进程内存采样（照抄 tests/smoke_s2.py：psapi GetProcessMemoryInfo）----

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
    """node 进程内存采样器：每 200ms 读 WorkingSetSize 取最大，
    PeakWorkingSetSize 兜底取大（照抄 tests/smoke_s2.py MemorySampler）。
    注意 PeakWorkingSetSize 是进程生命周期累计峰值（单调不减）。"""

    def __init__(self, pid, interval=SAMPLE_INTERVAL):
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


# --------------------------------------------------------------------------
# 临时 node 实例（照抄 tests/smoke_s1.py NodeProc 思路）
# --------------------------------------------------------------------------

class BenchNode:
    """压测专用临时 node：临时目录证书/配置 + 127.0.0.1 空闲端口启动 +
    LOCALAPPDATA 兜底覆盖 + /v1/health 探活 + 可靠终止。与用户真实 node
    实例完全无关（独立配置目录、独立证书、独立端口）。"""

    def __init__(self, tmp):
        self.tmp = Path(tmp)
        self.port = free_port()
        self.cert = self.tmp / "tls" / "cert.pem"
        self.key = self.tmp / "tls" / "key.pem"
        self.cfg = self.tmp / "config" / "node.json"
        self.log_path = self.tmp / "node_bench.log"
        self.fingerprint = gen_cert(self.tmp / "tls")
        write_json(self.cfg, {
            "version": 1,
            "tokens": [{"name": "default", "token": TOKEN}],
            "tls": {"cert": str(self.cert), "key": str(self.key)},
            "audit": {"retention_days": 180},
        })
        args = ["--host", HOST, "--port", str(self.port),
                "--config", str(self.cfg), "--verbose"]
        env = dict(os.environ)
        env["LOCALAPPDATA"] = str(self.tmp / "localappdata")   # 兜底：防写真实目录
        self._fh = open(self.log_path, "wb")
        self.proc = subprocess.Popen(
            [sys.executable, str(NODE_PY)] + args,
            stdout=self._fh, stderr=subprocess.STDOUT,
            cwd=str(self.tmp), env=env)

    def ready(self, timeout=READY_TIMEOUT):
        """探活 /v1/health（带令牌与防重放头）；超时或进程提前退出即报错。"""
        deadline = time.time() + timeout
        last = ""
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise NodeNotReady("node 进程提前退出 code=%s，日志尾部：%s"
                                   % (self.proc.returncode, tail_text(self.log_path)))
            try:
                status, body = raw_request(HOST, self.port, "GET", "/v1/health",
                                           token=TOKEN, timeout=3)
                data = json.loads(body.decode("utf-8"))
                if status == 200 and data.get("ok") is True \
                        and data.get("data", {}).get("status") == "up":
                    return
                last = "HTTP %s %s" % (status, body[:160])
            except Exception as exc:
                last = repr(exc)
            time.sleep(0.4)
        raise NodeNotReady("node %d 秒内未就绪：%s；日志尾部：%s"
                           % (timeout, last, tail_text(self.log_path)))

    def info(self):
        """GET /v1/info（显示器清单 monitors / 虚拟桌面 virtual_screen 等）。"""
        status, body = raw_request(HOST, self.port, "GET", "/v1/info", token=TOKEN)
        data = json.loads(body.decode("utf-8"))
        if status != 200 or data.get("ok") is not True:
            raise RuntimeError("/v1/info 失败：HTTP %s %s" % (status, body[:200]))
        return data["data"]

    def screen_once(self, monitor):
        """单次 GET /v1/screen（契约默认参数：原始尺寸 max_width=0，D18）。
        返回 (耗时秒, PNG 字节数)；非 200 或非 PNG 响应即报错。"""
        path = "/v1/screen?monitor=%d&max_width=0" % monitor
        t0 = time.perf_counter()
        status, body = raw_request(HOST, self.port, "GET", path, token=TOKEN)
        elapsed = time.perf_counter() - t0
        if status != 200 or not body.startswith(PNG_MAGIC):
            raise RuntimeError("截屏请求失败：HTTP %s %s" % (status, body[:200]))
        return elapsed, len(body)

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


# --------------------------------------------------------------------------
# 压测矩阵与结果
# --------------------------------------------------------------------------

def bench_one(node, stage_name, monitor, runs, info):
    """对一档连发 runs 次并采样内存，返回结果字典。"""
    monitors = info.get("monitors") or []
    if monitor < 0:
        vs = info.get("virtual_screen") or {}
        width, height = vs.get("width"), vs.get("height")
        region = "虚拟桌面"
    else:
        if monitor >= len(monitors):
            raise SystemExit("--monitor %d 超出显示器数量（/v1/info 共报 %d 个）"
                             % (monitor, len(monitors)))
        m = monitors[monitor]
        width, height = m.get("width"), m.get("height")
        region = "显示器 %d%s" % (monitor, "（主屏）" if m.get("primary") else "")
    print("-" * 76)
    print("档：%s（monitor=%d，%s×%s）— 连发 %d 次"
          % (stage_name, monitor, width, height, runs))
    sampler = MemorySampler(node.proc.pid)
    durations, sizes = [], []
    for i in range(runs):
        elapsed, size = node.screen_once(monitor)
        durations.append(elapsed)
        sizes.append(size)
        print("  第 %2d/%d 次：%.3fs，PNG %d 字节" % (i + 1, runs, elapsed, size))
    peak = sampler.finish()
    result = {
        "stage": stage_name,
        "monitor": monitor,
        "region": region,
        "width": width,
        "height": height,
        "runs": runs,
        "durations": durations,
        "sizes": sizes,
        "p50": statistics.median(durations),
        "max": max(durations),
        "avg_size": sum(sizes) // len(sizes),
        "peak_mem": peak,
        "samples": sampler.samples,
    }
    print("  小结：P50 %.3fs | Max %.3fs | 平均 PNG %d 字节 | "
          "node 峰值内存 %.1f MB（WorkingSet 采样 %d 次 + 系统峰值兜底，进程累计口径）"
          % (result["p50"], result["max"], result["avg_size"],
             peak / 1048576.0, sampler.samples))
    return result


def skipped_stage(stage_name, reason):
    """未实测档的占位结果（如实标注，不编造数据）。"""
    print("-" * 76)
    print("档：%s —— 未实测：%s" % (stage_name, reason))
    return {"stage": stage_name, "skipped": reason}


def run_matrix(node, info, runs, only_monitor=None):
    """标准三档矩阵；--monitor 指定时只跑该档（-1=虚拟桌面档）。"""
    monitors = info.get("monitors") or []
    results = []
    if only_monitor is not None:
        name = "虚拟桌面档" if only_monitor < 0 else "逐显示器档"
        results.append(bench_one(node, name, only_monitor, runs, info))
        return results
    # 档 1（必测）：本机当前虚拟桌面
    results.append(bench_one(node, "虚拟桌面档", -1, runs, info))
    # 档 2（如适用）：多屏环境逐显示器 monitor=0..N-1；单屏如实标注不适用
    if len(monitors) > 1:
        for idx in range(len(monitors)):
            results.append(bench_one(node, "逐显示器档", idx, runs, info))
    else:
        results.append(skipped_stage("逐显示器档",
                                     "单屏环境，逐显示器档不适用（monitor=-1 即该屏）"))
    # 档 3：4K（用户已确认无 4K 资源，不实测，如实标注；不作验收失败项）
    results.append(skipped_stage("4K 档",
                                 "4K 基线留实机（无实体/可用 4K 资源，"
                                 "Hyper-V 虚拟 4K 方案本轮未采用）"))
    return results


def gate_conclusion(results):
    """按 11.2 截屏行评估门槛：1920×1080 原始尺寸 10 次中位数 ≤ 2 秒。"""
    hits = [r for r in results
            if "p50" in r and r.get("width") == GATE_WIDTH and r.get("height") == GATE_HEIGHT]
    if not hits:
        return False, ("本次未包含 %d×%d 档，门槛结论不适用"
                       % (GATE_WIDTH, GATE_HEIGHT))
    worst = max(hits, key=lambda r: r["p50"])
    ok = worst["p50"] <= GATE_SECONDS
    detail = "；".join("%s（monitor=%d）P50 %.3fs / Max %.3fs"
                       % (r["stage"], r["monitor"], r["p50"], r["max"])
                       for r in hits)
    verdict = ("达标：%d×%d 原始尺寸 %d 次中位数 %.3fs ≤ %ss（11.2 截屏行"
               "\"重复 10 次取中位数\"口径）【%s】"
               % (GATE_WIDTH, GATE_HEIGHT, worst["runs"], worst["p50"],
                  GATE_SECONDS, detail))
    return ok, verdict if ok else ("未达标：" + detail
                                   + "（最差 P50 %.3fs > %ss）" % (worst["p50"], GATE_SECONDS))


def env_table(info):
    """环境表（/v1/info 口径，不自行调 Win32）。"""
    monitors = info.get("monitors") or []
    vs = info.get("virtual_screen") or {}
    mon_text = "；".join(
        "显示器 %d: (%d,%d) %d×%d%s"
        % (i, m.get("left", 0), m.get("top", 0), m.get("width", 0), m.get("height", 0),
           "，主屏" if m.get("primary") else "")
        for i, m in enumerate(monitors)) or "未知"
    rows = [
        ("操作系统", info.get("os", "-")),
        ("Python（node 运行时）", "%s（%s）" % (info.get("python", "-"), info.get("arch", "-"))),
        ("node 版本", info.get("node_version", "-")),
        ("主机名 / 用户", "%s / %s" % (info.get("hostname", "-"), info.get("user", "-"))),
        ("显示器清单", "%d 个：%s" % (len(monitors), mon_text)),
        ("虚拟桌面（monitor=-1）", "%d×%d（left=%d, top=%d）"
         % (vs.get("width", 0), vs.get("height", 0), vs.get("left", 0), vs.get("top", 0))),
        ("系统 DPI / DPI 感知", "%s（%s）" % (info.get("system_dpi", "-"),
                                             info.get("dpi_awareness", "-"))),
        ("单/双屏", "%d 屏" % len(monitors)),
        ("压测日期（本地）", time.strftime("%Y-%m-%d %H:%M:%S")),
        ("node 证书指纹（SHA-256，§4.1）", node_fingerprint),
    ]
    return rows


def markdown_report(results, info, runs, gate_ok, gate_text, rerun_cmd):
    """--out 输出的 markdown 结果段（环境表 + 逐档数据 + 复跑命令 + 结论）。"""
    lines = []
    lines.append("## 截屏压测结果（%s）" % time.strftime("%Y-%m-%d %H:%M"))
    lines.append("")
    lines.append("压测对象：node 自研 PNG 截屏链路（GDI BitBlt 采集 + BGRA→RGB + zlib 压缩），"
                 "契约默认参数原始尺寸（max_width=0，D18）。口径：工具自起临时 node 实例"
                 "（临时目录证书/配置，与真实 node 无关），每次请求独立 TLS 连接（含握手开销，"
                 "口径保守），每档连发 %d 次取中位数（11.2 口径）。" % runs)
    lines.append("")
    lines.append("### 环境表")
    lines.append("")
    lines.append("| 项 | 值 |")
    lines.append("|---|---|")
    for k, v in env_table(info):
        lines.append("| %s | %s |" % (k, v))
    lines.append("")
    lines.append("### 逐档基线")
    lines.append("")
    lines.append("| 档 | monitor | 分辨率 | P50（秒） | Max（秒） | 平均 PNG 字节数 | node 峰值内存 |")
    lines.append("|---|---|---|---|---|---|---|")
    for r in results:
        if "skipped" in r:
            lines.append("| %s | - | - | 未实测 | 未实测 | - | - |" % r["stage"])
            lines.append("| └ 说明 | | | %s | | | |" % r["skipped"])
        else:
            lines.append("| %s | %d | %d×%d | %.3f | %.3f | %d | %.1f MB |"
                         % (r["stage"], r["monitor"], r["width"], r["height"],
                            r["p50"], r["max"], r["avg_size"],
                            r["peak_mem"] / 1048576.0))
    lines.append("")
    lines.append("### 逐次明细")
    lines.append("")
    for r in results:
        if "skipped" in r:
            lines.append("- %s：未实测（%s）" % (r["stage"], r["skipped"]))
            continue
        lines.append("- %s（monitor=%d，%d×%d）：" % (r["stage"], r["monitor"],
                                                     r["width"], r["height"]))
        for i, (d, s) in enumerate(zip(r["durations"], r["sizes"])):
            lines.append("  - 第 %d 次：%.3fs，PNG %d 字节" % (i + 1, d, s))
    lines.append("")
    lines.append("### 与 11.2 门槛的达标结论")
    lines.append("")
    lines.append("**%s**" % gate_text)
    lines.append("")
    lines.append("### 4K 档标注")
    lines.append("")
    lines.append("4K（3840×2160）原始尺寸基线**留实机**：用户已确认本轮无实体/可用 4K 资源，"
                 "Hyper-V 虚拟 4K 桌面方案本轮未采用；按 S4 提示词 §3.1 预决策，"
                 "不作验收失败项。需求 11.2 的 4K 行验收方式为\"给出实测基线\"，"
                 "待有 4K 资源时以本工具复跑补录（复跑命令见下）。")
    lines.append("")
    lines.append("### 复跑方式")
    lines.append("")
    lines.append("```")
    lines.append(rerun_cmd)
    lines.append("```")
    lines.append("")
    lines.append("> 注：内存峰值为 node 进程生命周期累计口径"
                 "（WorkingSetSize 200ms 采样 + PeakWorkingSetSize 兜底取大，"
                 "psapi GetProcessMemoryInfo），跨档单调不减；单档值即\"截至该档结束"
                 "的进程峰值\"，全档最大值即本次压测整体峰值。")
    lines.append("")
    return "\n".join(lines)


# 全局：node 证书指纹（env_table 引用）
node_fingerprint = "-"


def main():
    global node_fingerprint
    ap = argparse.ArgumentParser(
        description="CrossDevice B7 截屏压测（自起临时 node 实例，仅标准库，可入库复跑）")
    ap.add_argument("--runs", type=int, default=10,
                    help="每档连发次数（默认 10，与 11.2 \"重复 10 次取中位数\"口径一致）")
    ap.add_argument("--monitor", type=int, default=-1,
                    help="只压测指定档：0 起为逐显示器档，-1 为虚拟桌面档"
                         "（默认 -1 = 跑标准矩阵：虚拟桌面档 + 逐显示器档 + 4K 标注）")
    ap.add_argument("--out", default=None,
                    help="markdown 结果段输出文件（可选；环境表 + 逐档数据 + 复跑命令）")
    ap.add_argument("--keep", action="store_true", help="保留临时目录便于排障")
    opts = ap.parse_args()

    if opts.runs < 1:
        raise SystemExit("--runs 必须为正整数（当前 %d）" % opts.runs)
    if not NODE_PY.is_file():
        raise SystemExit("找不到 node.py：%s" % NODE_PY)
    if not GEN_CERT_PS1.is_file():
        raise SystemExit("找不到 gen_cert.ps1：%s" % GEN_CERT_PS1)
    # --monitor 非 -1 时视为"只跑指定档"；显式传 -1 等价于默认矩阵
    only_monitor = None if opts.monitor == -1 else opts.monitor

    tmp = Path(tempfile.mkdtemp(prefix="xd_bench_screen_"))
    print("CrossDevice B7 截屏压测（自起临时实例，与真实 node 无关）")
    print("临时目录：%s" % tmp)
    print("node.py：%s" % NODE_PY)
    print("-" * 76)
    node = None
    try:
        node = BenchNode(tmp)
        node_fingerprint = node.fingerprint
        print("临时证书指纹：%s" % node.fingerprint)
        node.ready()
        info = node.info()
        monitors = info.get("monitors") or []
        vs = info.get("virtual_screen") or {}
        print("node 就绪：node_version=%s，显示器 %d 个，虚拟桌面 %d×%d，DPI %s（%s）"
              % (info.get("node_version"), len(monitors),
                 vs.get("width"), vs.get("height"),
                 info.get("system_dpi"), info.get("dpi_awareness")))

        results = run_matrix(node, info, opts.runs, only_monitor)

        gate_ok, gate_text = gate_conclusion(results)
        print("-" * 76)
        print("11.2 门槛：%s" % gate_text)

        rerun_cmd = "py tools/bench_screen.py --runs %d --out docs/压测基线-截屏.md" % opts.runs
        if opts.out:
            report = markdown_report(results, info, opts.runs, gate_ok, gate_text, rerun_cmd)
            out_path = Path(opts.out)
            if out_path.exists():
                # 结果段追加写：同文件多次复跑时保留历史段（每段自带日期标题）
                out_path.write_text(out_path.read_text(encoding="utf-8") + "\n" + report,
                                    encoding="utf-8")
            else:
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_path.write_text(report, encoding="utf-8")
            print("markdown 结果段已写出：%s" % out_path)
        return 0 if gate_ok or only_monitor is not None else 1
    finally:
        if node is not None:
            try:
                node.stop()
            except Exception:
                pass
        if opts.keep:
            print("临时目录保留：%s" % tmp)
        else:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
