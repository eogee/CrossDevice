#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CrossDevice S3 阶段一键自测（验收载体，覆盖验收清单 C1–C10）。

用法：
    py tests/smoke_s3.py                # 全量：C1–C10（含末尾 smoke_s1/s2 子进程回归）
    py tests/smoke_s3.py --skip-s1      # 跳过 smoke_s1 回归（调试用）
    py tests/smoke_s3.py --skip-s2      # 跳过 smoke_s2 回归（调试用）
    py tests/smoke_s3.py --keep         # 保留临时目录便于排障

隔离性（绝不触碰真实 %LOCALAPPDATA%\\CrossDevice 与仓库 data/；绝不真实弹 UAC；
绝不更新仓库 node/node.py 与 watchdog.py）：
    - 证书 / 配置 / 注册表 / 工作目录全部落在临时目录；xd.REGISTRY 打补丁；
    - C1/C2 的 node 运行 node/node.py 的临时副本（复制到临时目录运行），推送目标
      是该副本（self-update 替换的是副本 __file__），仓库 node/node.py 永不被更新；
      仓库 watchdog.py（若存在）复制到副本同目录（node 拉起看门狗路径解析第一优先级）；
    - 三身份配置：default / tester / third（third 为自造 32hex 令牌）；
    - 回滚后由看门狗独立重启的 node 是 detached 进程：收尾按端口（netstat→taskkill）
      与命令行（PowerShell Get-CimInstance，仅匹配本临时目录副本路径）清理，防孤儿；
    - node 子进程 LOCALAPPDATA 兜底覆盖（照抄 smoke_s1 做法）。

复用脚手架：import smoke_s1（NodeProc / gen_cert / run_xd / free_port / write_json /
raw_request / err_code 等）+ import smoke_s2（S2Node / raw2 / bare_request / jdata /
dev_dict / make_xd_runner 等）；RESULTS / record 使用本文件自己的，不污染前两者。
仅标准库。SA-1（node v0.4.0）与 SA-2（watchdog.py）并行开发期间，node/watchdog 侧
未就绪的各项优雅 FAIL 并标注"node 侧待集成"/"watchdog 侧待集成"（仿照 smoke_s2 的
s2_endpoints_ready 探测模式），绝不因缺文件直接崩溃；最终以主代理集成复跑为准。
"""

import argparse
import base64
import ctypes
import hashlib
import hmac
import json
import os
import re
import shutil
import socket
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
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import smoke_s1                     # noqa: E402  复用 S1 脚手架
import smoke_s2                     # noqa: E402  复用 S2 脚手架
import xd                           # noqa: E402

# ---- 复用脚手架 -------------------------------------------------------------
NodeProc = smoke_s1.NodeProc
NodeNotReady = smoke_s1.NodeNotReady
S2Node = smoke_s2.S2Node
raw2 = smoke_s2.raw2
bare_request = smoke_s2.bare_request
jdata = smoke_s2.jdata
dev_dict = smoke_s2.dev_dict
make_xd_runner = smoke_s2.make_xd_runner
err_code = smoke_s1.err_code
gen_cert = smoke_s1.gen_cert
write_json = smoke_s1.write_json
free_port = smoke_s1.free_port
run_xd = smoke_s1.run_xd
tail_text = smoke_s1.tail_text
HOST = smoke_s1.HOST
TOKEN_DEFAULT = smoke_s1.TOKEN_DEFAULT
TOKEN_TESTER = smoke_s1.TOKEN_TESTER
TOKEN_THIRD = "c3d4e5f60718293a4b5c6d7e8f90a1b2"   # 第三身份令牌（自造 32 hex）

RESULTS = []


def record(code, title, ok, evidence):
    RESULTS.append((code, title, bool(ok)))
    evidence = " ".join(str(evidence).split())
    print("%s %s %s（%s）" % (code, title, "PASS" if ok else "FAIL", evidence))


# --------------------------------------------------------------------------
# 基础设施（S3 增补）
# --------------------------------------------------------------------------

def s3_tokens():
    """三身份令牌列表（default / tester / third，契约 §2.1/§21 三身份并发）。"""
    return [{"name": "default", "token": TOKEN_DEFAULT},
            {"name": "tester", "token": TOKEN_TESTER},
            {"name": "third", "token": TOKEN_THIRD}]


def health_of(port):
    """裸查 /v1/health（default 令牌），失败返回空 dict。"""
    try:
        st, _, body = raw2(HOST, port, "GET", "/v1/health",
                           token=TOKEN_DEFAULT, timeout=6)
        return jdata(body) or {}
    except Exception:
        return {}


def s3_ready(health):
    """S3 就绪探测（仿 smoke_s2.s2_endpoints_ready 模式）：
    /v1/health 含 rollback_flag 字段且 node_version 为 0.4.x → S3 端点已实现。"""
    version = str(health.get("node_version") or "")
    return bool(re.match(r"0\.4\.", version)) and "rollback_flag" in health


def make_node_copy(tmp, tag):
    """把仓库 node/node.py 复制为临时副本（self-update 替换的是副本 __file__，
    绝不更新仓库 node/node.py）；仓库 watchdog.py 若存在则复制到副本同目录
    （node 拉起看门狗路径解析第一优先级 <node.py 同目录>/watchdog.py，契约 §20.4）。
    返回 (副本路径, watchdog 是否已复制)。"""
    dst_dir = tmp / "nodes" / tag
    dst_dir.mkdir(parents=True, exist_ok=True)
    dst = dst_dir / "node.py"
    shutil.copyfile(smoke_s1.NODE_PY, dst)
    wd = ROOT / "watchdog.py"
    copied = False
    if wd.exists():
        shutil.copyfile(wd, dst_dir / "watchdog.py")
        copied = True
    return dst, copied


def s3_copy_node(tag, tmp, node_py, args):
    """以指定 node.py 路径构造 S2Node（S2Node 硬编码 smoke_s1.NODE_PY，
    构造期间临时替换，完毕还原）。"""
    saved = smoke_s1.NODE_PY
    smoke_s1.NODE_PY = Path(node_py)
    try:
        return S2Node(tag, tmp, list(args))
    finally:
        smoke_s1.NODE_PY = saved


def kill_port_listener(port):
    """按端口找 LISTENING 进程并 taskkill /F /T（清理 detached 重启的 node 副本进程）。"""
    pids = set()
    try:
        out = subprocess.run(["netstat", "-ano", "-p", "TCP"], capture_output=True,
                             text=True, encoding="utf-8", errors="replace",
                             timeout=20).stdout or ""
    except Exception:
        return None
    for line in out.splitlines():
        parts = line.split()
        # 形如：TCP    127.0.0.1:51888    0.0.0.0:0    LISTENING    1234
        if len(parts) >= 5 and parts[3].upper() == "LISTENING" \
                and parts[1].endswith(":%d" % port):
            pids.add(parts[4])
    killed = []
    for pid in sorted(pids):
        try:
            subprocess.run(["taskkill", "/F", "/T", "/PID", pid],
                           capture_output=True, timeout=20)
            killed.append(pid)
        except Exception:
            pass
    return killed or None


def kill_by_cmdline(fragment):
    """按命令行片段清理进程（仅匹配本临时目录副本路径，PowerShell CIM，标准库外无依赖）。"""
    ps = ("Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like '*%s*' } | "
          "ForEach-Object { Stop-Process -Id $_.ProcessId -Force "
          "-ErrorAction SilentlyContinue }" % fragment)
    try:
        subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                       capture_output=True, timeout=90)
    except Exception:
        pass


def signed_payload(key, source_bytes):
    """按契约 §20.2 构造签名更新包：sha256=源码 64hex 小写，
    hmac=HMAC-SHA256(key=utf8(hmac_key), msg=utf8(sha256))。"""
    sha = hashlib.sha256(source_bytes).hexdigest()
    sig = hmac.new(key.encode("utf-8"), sha.encode("utf-8"), hashlib.sha256).hexdigest()
    return {"source_b64": base64.b64encode(source_bytes).decode("ascii"),
            "sha256": sha, "hmac": sig}


def bump_version(source_bytes, new_version):
    """正则替换 node 源码中的 NODE_VERSION 赋值（对单双引号书写格式容错）。
    替换失败返回 None。"""
    patched, n = re.subn(rb'(NODE_VERSION[ \t]*=[ \t]*).+',
                         b'\\1"' + new_version.encode("ascii") + b'"',
                         source_bytes, count=1)
    if n != 1 or patched == source_bytes:
        return None
    return patched


def run_pool(ctx, seconds, as_json=True):
    """子进程跑 `xd pool --seconds N [--json]`（真实 argparse + 真实 UDP 接收）。
    返回 (rc, 输出文本, JSON 快照或 None)。"""
    argv = ["pool", "--seconds", str(seconds)]
    if as_json:
        argv.append("--json")
    try:
        proc = subprocess.run(
            [sys.executable, str(ctx.runner)] + argv,
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=seconds + 90, cwd=str(ROOT))
        rc, out = proc.returncode, (proc.stdout or "") + (proc.stderr or "")
    except subprocess.TimeoutExpired as exc:
        rc, out = -1, "pool 子进程超时：%s" % ((exc.stdout or b"")[-200:] if isinstance(
            exc.stdout, bytes) else str(exc.stdout)[-200:])
    snap = None
    if as_json and "{" in out:
        try:
            snap = json.loads(out[out.index("{"):])
        except Exception:
            snap = None
    return rc, out, snap


def free_port_pair():
    """找相邻空闲端口 (E, E+1) 并占用 E（bind + listen(8)），返回 (E, holder)。
    调用方须以 accept 清道夫线程持续 accept-and-close（见 start_holder_drain），
    使 node 的 0.15 秒 connect 占用探测每次都识别为"活监听者"而顺延到 E+1：
    bind 未 listen 会被 node 按 §16.1 口径误判为 TIME_WAIT 残留而 SO_REUSEADDR 共绑；
    listen 但不 accept 则 backlog 被探测连接占满，后续探测被拒，同样误判。"""
    for _ in range(300):
        e = free_port()
        holder = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            holder.bind((HOST, e))
            holder.listen(8)
        except OSError:
            holder.close()
            continue
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            probe.bind((HOST, e + 1))
            probe.close()
            return e, holder
        except OSError:
            probe.close()
            holder.close()
    raise RuntimeError("找不到相邻空闲端口对")


def start_holder_drain(holder):
    """占用端口的 accept 清道夫：持续 accept 并立即关闭连接（后台 daemon 线程）。
    返回停止事件（finally 中 set 后再 close holder）。"""
    stop = threading.Event()

    def drain():
        holder.settimeout(0.5)
        while not stop.is_set():
            try:
                conn, _ = holder.accept()
                try:
                    conn.close()
                except OSError:
                    pass
            except socket.timeout:
                continue
            except OSError:
                break

    threading.Thread(target=drain, daemon=True).start()
    return stop


def registry_fingerprint(registry):
    """注册表结构指纹（C4/C5 不自动信任断言用）：名称集 + 每条目 port/hmac_key/
    cert_fingerprint。"""
    devices = registry.get("devices") or {}
    return (
        tuple(sorted(devices)),
        tuple(sorted((n, d.get("port")) for n, d in devices.items())),
        tuple(sorted((n, d.get("hmac_key")) for n, d in devices.items())),
        tuple(sorted((n, d.get("cert_fingerprint")) for n, d in devices.items())),
    )


# --------------------------------------------------------------------------
# C1–C10
# --------------------------------------------------------------------------

def c1_signed_update(ctx, opts):
    """C1 签名更新：push-node（enroll→签名）升级成功且版本正确；篡改源码/错误 hmac
    → 400 UPDATE_REJECTED 且副本字节不变；trusted_hashes 非空时未知 sha256 拒绝；
    /v1/update/pin 可用。C1/C2 使用各自独立 node 实例（临时副本），防白名单污染。"""
    if not ctx.s3_ready:
        return False, ("node 侧待集成（node_version=%s，/v1/health 无 rollback_flag，"
                       "S3 签名端点未实现）" % ctx.node_version)
    notes = []
    node_py = ctx.c1_node_py
    orig_bytes = node_py.read_bytes()

    # ① push-node 全链路：enroll（条目无 hmac_key）→ 签名 → 推送 → bat 重启 → 版本更新
    new_source = bump_version(orig_bytes, "0.4.1-c1")
    if new_source is None:
        return False, "node 侧待集成（副本源码未找到 NODE_VERSION 赋值，无法构造升级包）"
    ctx.c1_new_src = ctx.tmp / "c1_new_node.py"
    ctx.c1_new_src.write_bytes(new_source)
    out, err, error = run_xd(["push-node", "c1dev", "--file", str(ctx.c1_new_src)],
                             xd.load_registry())
    msgs = out + err + str(error or "")
    ok_push = error is None and "已推送" in msgs and "重启完成" in msgs \
        and "v0.4.1-c1" in msgs
    notes.append("push-node：err=%s 含已推送=%s 含重启完成+新版本=%s"
                 % ((error or "无")[:60], "已推送" in msgs, "v0.4.1-c1" in msgs))
    # 旧进程自退（bat 重启机制）：推送后 ~8 秒内原句柄进程应退出
    old_gone = False
    for _ in range(16):
        if ctx.c1_nodeobj.proc.poll() is not None:
            old_gone = True
            break
        time.sleep(0.5)
    notes.append("旧进程自退=%s" % old_gone)
    ctx.detached_ports.add(ctx.c1_port)       # 重启后的 node 为 detached，收尾按端口清理

    # 版本与字节：health 版本 == 0.4.1-c1；副本 node.py 字节 == 新包
    health = health_of(ctx.c1_port)
    ver = str(health.get("node_version") or "")
    ok_ver = ver == "0.4.1-c1"
    bytes_now = node_py.read_bytes()
    ok_bytes = bytes_now == new_source
    notes.append("health 版本=%s（期望 0.4.1-c1）副本字节==新包=%s 服务存活=%s"
                 % (ver or "-", ok_bytes, health.get("status") == "up"))

    # enroll 密钥已写入注册表条目（64hex 小写）
    entry = xd.load_registry()["devices"].get("c1dev") or {}
    key = str(entry.get("hmac_key") or "")
    ok_key = re.fullmatch(r"[0-9a-f]{64}", key) is not None
    notes.append("条目 hmac_key 已写入=%s（%s…）" % (ok_key, key[:8] if key else "-"))

    # ② 篡改 hmac → 400 UPDATE_REJECTED 且副本字节不变
    v2_source = bump_version(new_source, "0.4.2-c1")
    st, _, body = raw2(HOST, ctx.c1_port, "POST", "/v1/self-update",
                       token=TOKEN_DEFAULT, timeout=15,
                       payload={"source_b64": base64.b64encode(v2_source).decode("ascii"),
                                "sha256": hashlib.sha256(v2_source).hexdigest(),
                                "hmac": "0" * 64})
    ok_hmac = st == 400 and err_code(body) == "UPDATE_REJECTED" \
        and node_py.read_bytes() == new_source
    notes.append("错误 hmac → HTTP %s/%s 字节不变=%s"
                 % (st, err_code(body) or "-", node_py.read_bytes() == new_source))

    # ③ 篡改源码（sha256 与实际不符）→ 400 UPDATE_REJECTED
    tampered = v2_source + b"\n# S3C1 transit tamper\n"       # 签名按 v2_source，实体被改
    st, _, body = raw2(HOST, ctx.c1_port, "POST", "/v1/self-update",
                       token=TOKEN_DEFAULT, timeout=15,
                       payload={"source_b64": base64.b64encode(tampered).decode("ascii"),
                                "sha256": hashlib.sha256(v2_source).hexdigest(),
                                "hmac": hmac.new(key.encode("utf-8"),
                                                 hashlib.sha256(v2_source).hexdigest().encode(),
                                                 hashlib.sha256).hexdigest()})
    ok_tamper = st == 400 and err_code(body) == "UPDATE_REJECTED" \
        and node_py.read_bytes() == new_source
    notes.append("篡改源码 → HTTP %s/%s 字节不变=%s"
                 % (st, err_code(body) or "-", node_py.read_bytes() == new_source))

    # ④ pin 一个未知 sha256 后构造非白名单包 → UPDATE_REJECTED；/v1/update/pin 正常可用
    w_source = bump_version(new_source, "0.4.9-c1w")
    w_sha = hashlib.sha256(w_source).hexdigest()
    st, _, body = raw2(HOST, ctx.c1_port, "POST", "/v1/update/pin",
                       token=TOKEN_DEFAULT, payload={"sha256": w_sha}, timeout=15)
    d = jdata(body) or {}
    ok_pin = st == 200 and d.get("added") is True and w_sha in (d.get("trusted_hashes") or [])
    notes.append("/v1/update/pin → HTTP %s added=%s trusted=%d 项"
                 % (st, d.get("added"), len(d.get("trusted_hashes") or [])))
    v_source = bump_version(new_source, "0.4.3-c1v")          # 签名正确但不在白名单
    st, _, body = raw2(HOST, ctx.c1_port, "POST", "/v1/self-update",
                       token=TOKEN_DEFAULT, timeout=15,
                       payload=signed_payload(key, v_source))
    ok_wl = st == 400 and err_code(body) == "UPDATE_REJECTED" \
        and node_py.read_bytes() == new_source
    notes.append("非白名单包（签名正确）→ HTTP %s/%s 字节不变=%s"
                 % (st, err_code(body) or "-", node_py.read_bytes() == new_source))
    # node.json trusted_hashes 持久化
    try:
        cfg = json.loads(ctx.c1_cfg.read_text(encoding="utf-8"))
        ok_persist = w_sha in ((cfg.get("update") or {}).get("trusted_hashes") or [])
    except Exception as exc:
        ok_persist = False
        notes.append("node.json 读取失败：%r" % (exc,))
    notes.append("node.json trusted_hashes 持久化=%s" % ok_persist)

    ok = (ok_push and old_gone and ok_ver and ok_bytes and ok_key
          and ok_hmac and ok_tamper and ok_pin and ok_wl and ok_persist)
    return ok, "；".join(notes)


def c2_watchdog_rollback(ctx, opts):
    """C2 看门狗回滚：对 C2 专属实例（trusted_hashes 保持空）经签名路径推
    "语法合法但运行即崩"坏包（正常副本 + 首行 raise）→ 从推送完成计时 ≤60 秒
    /v1/health 恢复 + 副本 node.py 字节 == 旧版 + rollback.flag（old_sha256==旧版）
    + .bak 证据 + watchdog.log 存在。回滚后 watchdog 独立重启的 node 为 detached
    进程（收尾按端口/命令行清理）。"""
    if not ctx.s3_ready:
        return False, ("node 侧待集成（node_version=%s，S3 签名端点未实现，"
                       "不推坏包）" % ctx.node_version)
    if not ctx.c2_watchdog_copied:
        return False, ("watchdog 侧待集成（仓库根 watchdog.py 不存在，node 无法拉起"
                       "看门狗；为避免无回滚保护的替换，坏包推送已跳过）")
    notes = []
    node_py = ctx.c2_node_py
    orig_bytes = node_py.read_bytes()
    orig_sha = hashlib.sha256(orig_bytes).hexdigest()
    orig_version = ctx.c2_orig_version
    dev = ctx.c2_dev

    # ① enroll 拿签名密钥（与 push-node 内部同链路；C2 专属实例 trusted_hashes 保持空）
    try:
        data = xd.request(dev, "POST", "/v1/update/enroll", {}, timeout=15)
        key = str((data or {}).get("hmac_key") or "")
    except Exception as exc:
        return False, "enroll 失败（node 侧待集成）：%r" % (exc,)
    if not key:
        return False, "enroll 未返回 hmac_key（node 侧待集成）"

    def set_key(entry):
        entry["hmac_key"] = key

    xd.registry_update(lambda reg: set_key(reg["devices"]["c2dev"]))
    notes.append("enroll 完成（key=%s…，trusted_hashes 保持空）" % key[:8])

    # ② 坏包：首行 raise（语法合法、运行即崩）
    bad_source = b'raise RuntimeError("S3C2 bad package: crash on start")\n' + orig_bytes
    try:
        st, _, body = raw2(HOST, ctx.c2_port, "POST", "/v1/self-update",
                           token=TOKEN_DEFAULT, timeout=20,
                           payload=signed_payload(key, bad_source))
    except Exception as exc:
        return False, "坏包推送异常（node 侧）：%r" % (exc,)
    ok_push = st == 200 and jdata(body) is not None
    t0 = time.time()
    notes.append("坏包（%d 字节）推送 HTTP %s/%s"
                 % (len(bad_source), st, "ok" if ok_push else (err_code(body) or "-")))
    ctx.detached_ports.add(ctx.c2_port)

    # ③ 旧进程自退（bat 重启机制）
    old_gone = False
    for _ in range(20):
        if ctx.c2_nodeobj.proc.poll() is not None:
            old_gone = True
            break
        time.sleep(0.5)
    notes.append("推送后旧进程自退=%s" % old_gone)

    # ④ 从推送完成计时 ≤60 秒：/v1/health 恢复（版本回退为旧版）
    recovered = False
    version_after = None
    deadline = t0 + 60
    while time.time() < deadline:
        h = health_of(ctx.c2_port)
        if h.get("status") == "up":
            version_after = str(h.get("node_version") or "")
            recovered = True
            break
        time.sleep(1)
    elapsed = time.time() - t0
    ok_recover = recovered and version_after == orig_version and elapsed <= 60
    notes.append("health 恢复=%s 耗时 %.1fs（≤60s）版本 %s（旧版 %s）"
                 % (recovered, elapsed, version_after or "-", orig_version))

    # ⑤ rollback.flag / .bak / version.json / watchdog.log / 副本字节
    time.sleep(2)                              # 留出 flag/log 落盘（回滚动作最后写）
    flag_path = node_py.parent / "rollback.flag"
    bak_path = Path(str(node_py) + ".bak")
    vj_path = node_py.parent / "version.json"
    log_path = node_py.parent / "watchdog.log"
    flag_ok = flag_ev = ""
    if flag_path.exists():
        try:
            flag = json.loads(flag_path.read_text(encoding="utf-8"))
            ok_old = flag.get("old_sha256") == orig_sha
            flag_ok = ok_old and flag.get("restored") is True
            flag_ev = ("rollback.flag 存在：old_sha256==旧版=%s new_sha256=%s… "
                       "restored=%s" % (ok_old, str(flag.get("new_sha256"))[:12],
                                        flag.get("restored")))
        except Exception as exc:
            flag_ev = "rollback.flag 解析失败：%r" % (exc,)
    else:
        flag_ev = "rollback.flag 不存在"
    notes.append(flag_ev)
    bytes_ok = node_py.read_bytes() == orig_bytes
    # .bak 被回滚 os.replace 消费属契约既定行为（§20.4）；其内容以
    # rollback.flag.old_sha256（即 .bak 的 sha256）与 version.json 双证
    bak_ok = (not bak_path.exists()) or bak_path.read_bytes() == orig_bytes
    vj_ok = False
    if vj_path.exists():
        try:
            vj = json.loads(vj_path.read_text(encoding="utf-8"))
            vj_ok = vj.get("old_sha256") == orig_sha
        except Exception:
            vj_ok = False
    log_ok = log_path.exists() and log_path.stat().st_size > 0
    notes.append("副本字节==旧版=%s；.bak 存在=%s（存在则==旧版=%s，被消费属既定）；"
                 "version.json.old_sha256==旧版=%s；watchdog.log 存在=%s"
                 % (bytes_ok, bak_path.exists(), bak_ok, vj_ok, log_ok))

    ctx.c2_flag_ok = flag_ok
    # 失败自诊断：附看门狗日志与重启输出尾部（回滚完成但恢复探活失败时可直接定位）
    for log_name in ("watchdog.log", "watchdog-restart-out.log"):
        p = node_py.parent / log_name
        if p.exists():
            notes.append("%s 尾部：%s" % (log_name, tail_text(p, 500)))
    ok = ok_push and old_gone and ok_recover and flag_ok and bytes_ok \
        and bak_ok and vj_ok and log_ok
    return ok, "；".join(notes)


def c3_broadcast(ctx, opts):
    """C3 广播上线：node 启动后 `xd pool` 快照含该 device_id 且在线（预期 2 秒级）；
    心跳 10 秒（22 秒窗 ≥2 帧）；node 停止后 45 秒窗快照判离线（停止时距最近一帧
    ≥33 秒 > 30 秒阈值，判定为确定性）。另附 xd 侧结构校验（pool 子进程可运行、
    JSON 快照可解析）。若全程无帧：证据注明 Windows 防火墙可能拦截 UDP 51889。"""
    notes = []
    # xd 侧结构校验（不依赖 node 版本）：pool 子进程可运行、快照 JSON 可解析
    rc0, out0, snap0 = run_pool(ctx, 3)
    ok_struct = rc0 == 0 and isinstance(snap0, dict) and "devices" in snap0
    notes.append("xd pool 子进程 rc=%s JSON 快照可解析=%s（空池属正常）"
                 % (rc0, isinstance(snap0, dict)))

    info = {}
    try:
        info = xd.request(ctx.dev, "GET", "/v1/info", timeout=10) or {}
    except Exception as exc:
        notes.append("/v1/info 异常：%r" % (exc,))
    device_id = str(info.get("device_id") or "")
    if not device_id:
        return (ok_struct and False), ("；".join(notes) +
                "；node 侧待集成（/v1/info 无 device_id，UDP 广播未实现，"
                "node_version=%s）" % ctx.node_version)

    # ① 上线：12 秒窗快照含该 device_id 且在线（启动帧 + 10 秒心跳，12 秒窗必有 ≥1 帧）
    rc1, out1, snap1 = run_pool(ctx, 12)
    entry1 = ((snap1 or {}).get("devices") or {}).get(device_id) or {}
    ok_online = entry1.get("online") is True
    notes.append("上线：pool 12s 快照含 device_id=%s 在线=%s 帧=%s"
                 % (device_id in ((snap1 or {}).get("devices") or {}),
                    entry1.get("online"), entry1.get("frames")))

    # ② 心跳：22 秒窗 ≥2 帧（10 秒节奏）
    rc2, out2, snap2 = run_pool(ctx, 22)
    entry2 = ((snap2 or {}).get("devices") or {}).get(device_id) or {}
    ok_beat = entry2.get("frames", 0) >= 2
    notes.append("心跳：22s 窗帧数=%s（≥2 即 10 秒节奏成立）" % entry2.get("frames"))

    # ③ 离线：45 秒窗后台采样；12 秒后停主 node（保证窗内已收到 ≥1 帧，
    #    最近帧距快照 ≥33 秒 > 30 秒阈值 → 确定性判离线）
    proc = subprocess.Popen(
        [sys.executable, str(ctx.runner), "pool", "--seconds", "45", "--json"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        encoding="utf-8", errors="replace", cwd=str(ROOT))
    time.sleep(12)
    ctx.node_main.stop()
    time.sleep(1)
    out3 = ""
    try:
        out3, _ = proc.communicate(timeout=50)
    except subprocess.TimeoutExpired:
        proc.kill()
        out3, _ = proc.communicate()
        notes.append("离线采样 pool 子进程超时被杀")
    snap3 = None
    if "{" in (out3 or ""):
        try:
            snap3 = json.loads(out3[out3.index("{"):])
        except Exception:
            snap3 = None
    entry3 = ((snap3 or {}).get("devices") or {}).get(device_id) or {}
    ok_offline = entry3.get("online") is False
    notes.append("离线：45s 窗（12s 处停 node）快照含该设备=%s online=%s（期望 False）"
                 % (device_id in ((snap3 or {}).get("devices") or {}),
                    entry3.get("online")))

    # ④ 重启主实例供后续用例（C6/C7/C9/C10），同证书同端口（TOFU 指纹不变）
    ctx.node_main = NodeProc("main2", ctx.port_main, [], ctx.cfg, ctx.tmp,
                             cert=ctx.cert1, key=ctx.key1)
    ctx.nodes.append(ctx.node_main)
    restarted = True
    try:
        ctx.node_main.ready(TOKEN_DEFAULT)
    except NodeNotReady as exc:
        restarted = False
        notes.append("主实例重启失败：%s" % str(exc)[:120])

    if not (ok_online or ok_beat or ok_offline):
        notes.append("未收到任何广播帧：Windows 防火墙可能拦截 UDP 51889（若 node_version"
                     "=0.4.0 请放行后复跑）；node 侧广播未实现亦如此")
    ok = ok_struct and ok_online and ok_beat and ok_offline and restarted
    return ok, "；".join(notes)


def c4_flood_no_trust(ctx, opts):
    """C4 限频去重与不信任：先启动 pool 采样（UDP 无连接缓冲，帧必须落在采样窗内），
    向 51889 手工洪泛同一 (源IP, device_id) 伪造帧（20 帧）→ pool 快照该伪造
    device_id 的 frames ≤2（每秒 1 帧限频生效，未洪泛入库）；广播接收全程注册表
    （临时 registry）无新增条目、port/hmac_key/指纹无变化（D38 不自动信任）。
    本项为 xd 侧语义，不依赖 node v0.4.0。"""
    notes = []
    device_id = "f00dc0ffee12"                 # 伪造 device_id（与真实广播可区分）
    reg_before = xd.load_registry()
    fp_before = registry_fingerprint(reg_before)

    # ① 先起 pool 子进程（10 秒采样窗），留出其绑定 UDP 51889 的时间
    proc = subprocess.Popen(
        [sys.executable, str(ctx.runner), "pool", "--seconds", "10", "--json"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        encoding="utf-8", errors="replace", cwd=str(ROOT))
    time.sleep(2.5)

    # ② 洪泛：同一 (127.0.0.1, device_id) 20 帧（帧内容合法：XDCAST/proto=1）
    frame = json.dumps({
        "magic": "XDCAST", "proto": 1, "device_id": device_id,
        "hostname": "s3-flood-host", "port": ctx.port_main,
        "version": "9.9.9-flood", "caps": ["exec"], "ts": time.time(),
    }, ensure_ascii=False).encode("utf-8")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sent = 0
    flood_t0 = time.time()
    try:
        while sent < 20 and time.time() - flood_t0 < 1.5:
            sock.sendto(frame, ("127.0.0.1", 51889))
            sent += 1
    finally:
        sock.close()
    notes.append("洪泛 %d 帧（%.2fs 内，同一 源IP+device_id=%s）"
                 % (sent, time.time() - flood_t0, device_id))

    # ③ 读快照：伪造 device_id 仅应被接受 1–2 帧（限频：每秒最多 1 帧）
    out = ""
    try:
        out, _ = proc.communicate(timeout=30)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, _ = proc.communicate()
    snap = None
    if "{" in (out or ""):
        try:
            snap = json.loads(out[out.index("{"):])
        except Exception:
            snap = None
    rc = proc.returncode
    entry = ((snap or {}).get("devices") or {}).get(device_id) or {}
    frames = entry.get("frames", 0)
    ok_rate = 1 <= frames <= 2                  # 20 帧洪泛 → 限频后仅 1–2 帧入库
    notes.append("pool 10s 快照：伪造 device_id 帧数=%s（1≤frames≤2 即限频生效；"
                 "无限频时应≈20）count=%s rc=%s"
                 % (frames, (snap or {}).get("count"), rc))

    # ④ 注册表全程不变（D38：广播来源不自动信任、不自动 add）
    reg_after = xd.load_registry()
    ok_reg = registry_fingerprint(reg_after) == fp_before
    notes.append("注册表全程无新增条目、port/hmac_key/指纹无变化=%s（D38 不自动信任）"
                 % ok_reg)
    return ok_rate and ok_reg and rc == 0, "；".join(notes)


def c5_port_sync(ctx, opts):
    """C5 端口同步：条目预置 info.device_id=真实 device_id、port=期望端口 E；
    占用 E 让 node 顺延 E+1（广播帧 port=实际端口）→ pool 12s → 注册表条目 port
    自动变为 E+1（经完整 probe：TLS+TOFU+令牌+防重放）；负向：条目指纹预置为假
    → TOFU 拒绝 → port 不被校正。负向/正向用独立条目分两次 pool（60 秒冷却按
    (条目名, 帧端口) 记，互不影响）；device_id 精确匹配防同机多 node hostname 撞车。"""
    if not ctx.s3_ready:
        return False, ("node 侧待集成（node_version=%s，广播未实现，端口同步无从"
                       "触发）" % ctx.node_version)
    notes = []
    e, holder = free_port_pair()               # E 被占用（bind+listen），E+1 空闲
    drain_stop = start_holder_drain(holder)    # accept 清道夫：让 node 稳定识别活监听者
    cfg_dir = ctx.tmp / "c5cfg"
    cfg5 = cfg_dir / "node.json"
    write_json(cfg5, {"version": 1, "tokens": s3_tokens(),
                      "tls": {"cert": str(ctx.cert1), "key": str(ctx.key1)},
                      "audit": {"retention_days": 180}})
    node5 = None
    try:
        # --host 0.0.0.0：广播帧可能来自局域网定向广播（源 IP=LAN IP），
        # 端口同步 probe 打到广播源 ip:port，node 须在全部接口可达
        node5 = S2Node("c5", ctx.tmp,
                       ["--host", "0.0.0.0", "--port", str(e), "--config", str(cfg5),
                        "--verbose"])
        ctx.nodes.append(node5)
        try:
            node5.ready(TOKEN_DEFAULT, e + 1, timeout=30)
        except NodeNotReady as exc:
            return False, "node 顺延启动未就绪（%d 被占 → %d）：%s" % (e, e + 1, str(exc)[:120])
        info = xd.request(dev_dict(e + 1, ctx.fp1), "GET", "/v1/info", timeout=10) or {}
        device_id5 = str(info.get("device_id") or "")
        hostname5 = str(info.get("hostname") or "")
        if not device_id5:
            return False, "node 侧待集成（/v1/info 无 device_id）"
        notes.append("期望端口 %d 被占 → node 实际绑定 %d，device_id=%s"
                     % (e, e + 1, device_id5))

        # 负向先行：条目 c5bad（device_id 精确匹配 + 假指纹 + port=E）→ TOFU 拒绝 → 不校正
        def seed_bad(reg):
            reg["devices"]["c5bad"] = {
                "name": "c5bad", "ip": HOST, "port": e, "token": TOKEN_DEFAULT,
                "identity": "default", "cert_fingerprint": "f" * 64,
                "mac": "", "ips": [], "hmac_key": "",
                "added_at": time.time(), "last_seen": None,
                "info": {"device_id": device_id5, "hostname": hostname5},
            }

        xd.registry_update(seed_bad)
        fp_before = registry_fingerprint(xd.load_registry())
        rc_n, out_n, _ = run_pool(ctx, 12)
        port_bad = xd.load_registry()["devices"]["c5bad"]["port"]
        ok_negative = port_bad == e and \
            registry_fingerprint(xd.load_registry()) == fp_before
        notes.append("负向：假指纹条目 port=%s（期望保持 %d）注册表无任何变化=%s（rc=%s）"
                     % (port_bad, e, ok_negative, rc_n))

        # 正向：换用真实指纹条目 c5dev（60 秒冷却按条目名记，与 c5bad 互不影响）
        def swap(reg):
            reg["devices"].pop("c5bad", None)
            reg["devices"]["c5dev"] = {
                "name": "c5dev", "ip": HOST, "port": e, "token": TOKEN_DEFAULT,
                "identity": "default", "cert_fingerprint": ctx.fp1,
                "mac": "", "ips": [], "hmac_key": "",
                "added_at": time.time(), "last_seen": None,
                "info": {"device_id": device_id5, "hostname": hostname5},
            }

        xd.registry_update(swap)
        names_before = set(xd.load_registry()["devices"])
        rc_p, out_p, _ = run_pool(ctx, 12)
        entry = xd.load_registry()["devices"].get("c5dev") or {}
        ok_positive = entry.get("port") == e + 1
        ok_no_add = set(xd.load_registry()["devices"]) == names_before
        notes.append("正向：条目 port %d → %s（期望 %d）校正=%s；pool 未自动新增条目=%s"
                     "（rc=%s，同步输出=%s）"
                     % (e, entry.get("port"), e + 1, ok_positive, ok_no_add, rc_p,
                        "端口同步" in out_p or "-"))
        return ok_negative and ok_positive and ok_no_add, "；".join(notes)
    finally:
        try:
            drain_stop.set()
        except Exception:
            pass
        try:
            holder.close()
        except OSError:
            pass
        if node5:
            node5.stop()


def c6_input_lease(ctx, opts):
    """C6 输入租约（raw2 三身份并发）：A acquire → B 409 INPUT_LEASE_TAKEN；
    C take 抢占 → A 下一次 409（一次性标记）→ 再下一次正常判定 409；C release
    （空 actions）→ holder 清空 → A 无头隐式申请成功；lease_seconds=5 独立实例
    验证超时自动释放；--take CLI 与 xd release CLI 可用。租约判定先于锁屏/交互
    检查，锁屏环境不影响本项。"""
    if not ctx.s3_ready:
        return False, ("node 侧待集成（node_version=%s，输入租约/INPUT_LEASE_TAKEN "
                       "未实现）" % ctx.node_version)
    notes = []
    port = ctx.port_main

    def inp(token, headers=None, actions=None):
        payload = {"actions": [{"type": "move", "x": 1, "y": 1}]
                   if actions is None else actions}
        return raw2(HOST, port, "POST", "/v1/input", token=token,
                    headers=headers, payload=payload, timeout=10)

    # ① A acquire（无头隐式申请语义的显式版）
    st, _, body = inp(TOKEN_DEFAULT, {"X-Input-Lease": "acquire"})
    lease = (jdata(body) or {}).get("lease") or {}
    ok1 = st == 200 and lease.get("holder") == "default" and lease.get("mine") is True
    notes.append("A acquire → %s holder=%s mine=%s" % (st, lease.get("holder"),
                                                       lease.get("mine")))
    # ② B acquire → 409 INPUT_LEASE_TAKEN
    st, _, body = inp(TOKEN_TESTER, {"X-Input-Lease": "acquire"})
    ok2 = st == 409 and err_code(body) == "INPUT_LEASE_TAKEN"
    notes.append("B acquire → %s/%s" % (st, err_code(body) or "-"))
    # ③ C take 显式抢占
    st, _, body = inp(TOKEN_THIRD, {"X-Input-Lease": "take"})
    lease = (jdata(body) or {}).get("lease") or {}
    ok3 = st == 200 and lease.get("holder") == "third"
    notes.append("C take → %s holder=%s" % (st, lease.get("holder")))
    # ④ A 下一次 → 409（被抢占一次性标记），再下一次 → 409（正常判定：租约在 C 手中）
    st, _, body = inp(TOKEN_DEFAULT)
    ok4 = st == 409 and err_code(body) == "INPUT_LEASE_TAKEN"
    st, _, body = inp(TOKEN_DEFAULT)
    ok5 = st == 409 and err_code(body) == "INPUT_LEASE_TAKEN"
    notes.append("A 被抢占后第一次 → %s/%s（一次性标记）；第二次 → %s/%s（正常判定）"
                 % (ok4 and 409, err_code(body) if ok4 else "-",
                    ok5 and 409, err_code(body) if ok5 else "-"))
    # ⑤ C release（空 actions 合法）→ holder 清空
    st, _, body = inp(TOKEN_THIRD, {"X-Input-Lease": "release"}, actions=[])
    lease = (jdata(body) or {}).get("lease") or {}
    ok6 = st == 200 and lease.get("holder") is None
    notes.append("C release（空 actions）→ %s holder=%s" % (st, lease.get("holder")))
    # ⑥ A 无头隐式申请（兼容现状，偏差 10）
    st, _, body = inp(TOKEN_DEFAULT)
    lease = (jdata(body) or {}).get("lease") or {}
    ok7 = st == 200 and lease.get("mine") is True
    notes.append("A 无头隐式申请 → %s mine=%s" % (st, lease.get("mine")))
    # 清场（释放，便于 CLI 用例）
    try:
        inp(TOKEN_DEFAULT, {"X-Input-Lease": "release"}, actions=[])
    except Exception:
        pass

    # ⑦ lease_seconds=5 独立实例：超时自动释放（惰性判定）
    cfg_dir = ctx.tmp / "c6cfg"
    cfg6 = cfg_dir / "node.json"
    write_json(cfg6, {"version": 1, "tokens": s3_tokens(),
                      "tls": {"cert": str(ctx.cert1), "key": str(ctx.key1)},
                      "audit": {"retention_days": 180},
                      "input": {"lease_seconds": 5}})
    port6 = free_port()
    node6 = NodeProc("c6lease", port6, [], cfg6, ctx.tmp, cert=ctx.cert1, key=ctx.key1)
    ctx.nodes.append(node6)
    ok_timeout = False
    try:
        node6.ready(TOKEN_DEFAULT)
        dev6 = dev_dict(port6, ctx.fp1)
        d1 = xd.request(dev6, "POST", "/v1/input",
                        {"actions": [{"type": "move", "x": 1, "y": 1}]},
                        extra_headers={"X-Input-Lease": "acquire"}, timeout=10)
        granted1 = (d1.get("lease") or {}).get("holder") == "default"
        time.sleep(6.5)
        d2 = xd.request(dev6, "POST", "/v1/input",
                        {"actions": [{"type": "move", "x": 1, "y": 1}]}, timeout=10)
        lease2 = d2.get("lease") or {}
        ok_timeout = granted1 and st is not None and lease2.get("mine") is True
        notes.append("lease_seconds=5：acquire 授予=%s；6.5s 后无头请求 → %s "
                     "mine=%s（超时自动释放后重新授予）"
                     % (granted1, "200", lease2.get("mine")))
    except Exception as exc:
        notes.append("超时实例异常（node 侧）：%r" % (exc,))

    # ⑧ CLI：move --take（抢占/授予，输出语义不变）与 xd release（新文案）
    out_t, err_t, error_t = run_xd(["move", "self", "1", "1", "--take"],
                                   xd.load_registry())
    msgs_t = out_t + err_t + str(error_t or "")
    ok_take = (error_t is None and "已发送" in out_t) or "未生效" in str(error_t or "")
    out_r, err_r, error_r = run_xd(["release", "self"], xd.load_registry())
    ok_release = error_r is None and "已释放输入租约" in out_r
    notes.append("CLI move --take=%s（%s）；CLI release=%s（%s）"
                 % (ok_take, (msgs_t or "")[:40].strip(),
                    ok_release, (error_r or "已释放输入租约")[:30]))

    ok = ok1 and ok2 and ok3 and ok4 and ok5 and ok6 and ok7 \
        and ok_timeout and ok_take and ok_release
    return ok, "；".join(notes)


def c7_elevate(ctx, opts):
    """C7 高权限驻留（自动化口径，绝不真实弹 UAC）：白盒 build_schtasks_create_args
    逐项断言（/tn /sc onlogon /rl highest /f /tr 引号结构）；elevate_runexe 无效
    file → 明确错误；子进程直调 py <临时node副本> --elevate-task-install → 非提权
    环境预期非零退出（若恰好提权：真实创建则必须 schtasks /delete 清理并注明）；
    /v1/elevate/remove 幂等且清除预置 elevated 标记；info.elevated_resident 与
    横幅"驻留"行。真实 UAC 注册与重启驻留留 B25 实机（偏差 11）。"""
    if not ctx.s3_ready:
        return False, ("node 侧待集成（node_version=%s，elevate 端点/helper 未实现；"
                       "为避免真实弹 UAC，install 端点不在冒烟中调用）"
                       % ctx.node_version)
    notes = []
    node_dir = str(ROOT / "node")
    sys.modules.pop("node", None)
    if node_dir not in sys.path:
        sys.path.insert(0, node_dir)
    try:
        import node as node_mod
    except Exception as exc:
        return False, "白盒 import node 失败（node 侧）：%r" % (exc,)

    # ① build_schtasks_create_args 白盒断言
    builder = getattr(node_mod, "build_schtasks_create_args", None)
    ok_args = False
    if callable(builder):
        try:
            cargs = [str(x) for x in builder("xd_s3_probe", "PYEXE", "NODEPY",
                                             "CFGP", 51888)]

            def flag_val(flag):
                return cargs[cargs.index(flag) + 1] if flag in cargs else None

            tr = flag_val("/tr") or ""
            ok_args = (bool(cargs) and cargs[0].lower().endswith("schtasks")
                       and flag_val("/tn") == "xd_s3_probe"
                       and flag_val("/sc") == "onlogon"
                       and flag_val("/rl") == "highest"
                       and "/f" in cargs
                       and '"PYEXE"' in tr and '"NODEPY"' in tr
                       and "--config" in tr and "--port" in tr)
            notes.append("schtasks 构造白盒=%s（%s）" % (ok_args, " ".join(cargs)[:130]))
        except Exception as exc:
            notes.append("build_schtasks_create_args 异常：%r" % (exc,))
    else:
        notes.append("node 侧待集成（未找到可独立调用的 build_schtasks_create_args）")

    # ② elevate_runexe 无效 file → 明确错误（不弹真实 UAC）
    runner = getattr(node_mod, "elevate_runexe", None)
    ok_runexe = False
    if callable(runner):
        try:
            result = runner("Z:\\__s3_no_such_dir__\\no_such.exe", ["--probe"])
            ok_runexe = not (result is True or (isinstance(result, dict)
                                                and result.get("ok") is True))
            notes.append("elevate_runexe 无效 file → 返回 %r（明确错误）" % (result,))
        except Exception as exc:
            ok_runexe = bool(str(exc))
            notes.append("elevate_runexe 无效 file → %s: %s（明确错误）"
                         % (type(exc).__name__, str(exc)[:80]))
    else:
        notes.append("node 侧待集成（未找到可独立调用的 elevate_runexe）")

    # ③ 子进程直调提权子命令（非提权环境预期失败退出码非零；绝不弹真实 UAC）
    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        is_admin = False
    sub_dir = ctx.tmp / "nodes" / "c7sub"
    sub_dir.mkdir(parents=True, exist_ok=True)
    sub_py = sub_dir / "node.py"
    shutil.copyfile(smoke_s1.NODE_PY, sub_py)
    sub_cfg_dir = ctx.tmp / "c7subcfg"
    sub_cfg_dir.mkdir(parents=True, exist_ok=True)
    sub_cfg = sub_cfg_dir / "node.json"
    write_json(sub_cfg, {"version": 1, "tokens": s3_tokens(),
                         "tls": {"cert": str(ctx.cert1), "key": str(ctx.key1)}})
    env = dict(os.environ)
    env["LOCALAPPDATA"] = str(ctx.tmp / "localappdata")
    try:
        proc = subprocess.run(
            [sys.executable, str(sub_py), "--elevate-task-install", "xd_s3_probe",
             "--config", str(sub_cfg), "--port", str(free_port())],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=90, env=env, cwd=str(ctx.tmp))
        rc = proc.returncode
        sub_out = ((proc.stdout or "") + (proc.stderr or ""))[-200:]
    except subprocess.TimeoutExpired:
        rc, sub_out = None, "子命令 90s 超时（被杀）"
    if is_admin:
        subprocess.run(["schtasks", "/delete", "/tn", "xd_s3_probe", "/f"],
                       capture_output=True, timeout=30)
        ok_sub = rc == 0
        notes.append("当前环境恰好提权：--elevate-task-install 退出码=%s，"
                     "真实创建后已 schtasks /delete /tn xd_s3_probe /f 清理" % rc)
    else:
        ok_sub = rc is not None and rc != 0
        notes.append("非提权直调 --elevate-task-install → 退出码=%s（预期失败非零，"
                     "不弹 UAC）尾部=%s" % (rc, sub_out.replace("\n", " ")[:80]))

    # ④ /v1/elevate/remove 幂等：显式给不存在的 task_name → 任务不存在视为已清理
    # （node 侧口径：空体且节点无 elevated 标记时无可删任务名 → 400，属契约未定义
    # 场景的合理实现；幂等语义用显式 task_name 验证）
    st, _, body = raw2(HOST, ctx.port_main, "POST", "/v1/elevate/remove",
                       token=TOKEN_DEFAULT,
                       payload={"task_name": "xd_s3_no_such_task"}, timeout=20)
    ok_idem = st == 200 and (jdata(body) or {}).get("removed") is True
    notes.append("remove 幂等（显式不存在任务名）→ HTTP %s removed=%s"
                 % (st, (jdata(body) or {}).get("removed")))

    # ⑤ 预置 elevated 标记实例：info.elevated_resident=true + 横幅"驻留"行；remove 后 false
    cfg_dir = ctx.tmp / "c7e"
    cfg_e = cfg_dir / "node.json"
    write_json(cfg_e, {"version": 1, "tokens": s3_tokens(),
                       "tls": {"cert": str(ctx.cert1), "key": str(ctx.key1)},
                       "audit": {"retention_days": 180},
                       "elevated": {"task_name": "xd_s3_probe"}})
    port_e = free_port()
    # PYTHONUNBUFFERED：横幅走 stdout 块缓冲，进程被 terminate 时缓冲丢失会导致
    # 日志里没有"驻留"行；强制无缓冲使横幅实时落日志
    os.environ["PYTHONUNBUFFERED"] = "1"
    node_e = None
    try:
        node_e = NodeProc("c7e", port_e, [], cfg_e, ctx.tmp,
                          cert=ctx.cert1, key=ctx.key1)
    finally:
        os.environ.pop("PYTHONUNBUFFERED", None)
    ctx.nodes.append(node_e)
    ok_marker = False
    try:
        node_e.ready(TOKEN_DEFAULT)
        dev_e = dev_dict(port_e, ctx.fp1)
        info1 = xd.request(dev_e, "GET", "/v1/info", timeout=10) or {}
        resident1 = info1.get("elevated_resident")
        banner = "驻留" in Path(node_e.log_path).read_text(
            encoding="utf-8", errors="replace") and "xd_s3_probe" in Path(
            node_e.log_path).read_text(encoding="utf-8", errors="replace")
        st, _, body = raw2(HOST, port_e, "POST", "/v1/elevate/remove",
                           token=TOKEN_DEFAULT, payload={}, timeout=30)
        removed = (jdata(body) or {}).get("removed") is True
        info2 = xd.request(dev_e, "GET", "/v1/info", timeout=10) or {}
        cfg_now = json.loads(cfg_e.read_text(encoding="utf-8"))
        marker_cleared = not (cfg_now.get("elevated") or {}).get("task_name")
        ok_marker = (resident1 is True and banner and removed
                     and info2.get("elevated_resident") is False and marker_cleared)
        notes.append("预置标记实例：elevated_resident 预置=%s 横幅驻留行=%s；"
                     "remove → removed=%s remove 后 resident=%s node.json 标记清除=%s"
                     % (resident1, banner, removed,
                        info2.get("elevated_resident"), marker_cleared))
    except Exception as exc:
        notes.append("预置标记实例异常（node 侧）：%r" % (exc,))

    ok = ok_args and ok_runexe and ok_sub and ok_idem and ok_marker
    return ok, "；".join(notes)


def c8_regression(ctx, opts):
    """C8 回归：子进程跑 tests/smoke_s1.py（8/8）与 tests/smoke_s2.py（默认档 10/10），
    解析汇总行。--skip-s1/--skip-s2 跳过（调试模式不计入失败）。"""
    notes = []
    ok_s1 = True
    if opts.skip_s1:
        notes.append("smoke_s1 回归已跳过（--skip-s1，调试模式不计入失败）")
    else:
        print("  [C8] 子进程运行 tests/smoke_s1.py …")
        try:
            proc = subprocess.run([sys.executable, str(HERE / "smoke_s1.py")],
                                  capture_output=True, text=True, encoding="utf-8",
                                  errors="replace", timeout=1200, cwd=str(ROOT))
            out = (proc.stdout or "") + (proc.stderr or "")
            match = re.search(r"S1 自测：(\d+)/8 通过", out)
            ok_s1 = proc.returncode == 0 and match and match.group(1) == "8"
            notes.append("smoke_s1 子进程 → rc=%s %s"
                         % (proc.returncode, match.group(0) if match else "未找到汇总行"))
        except Exception as exc:
            ok_s1 = False
            notes.append("smoke_s1 子进程异常：%r" % (exc,))

    ok_s2 = True
    if opts.skip_s2:
        notes.append("smoke_s2 回归已跳过（--skip-s2，调试模式不计入失败）")
    else:
        print("  [C8] 子进程运行 tests/smoke_s2.py（默认档，含 256MB 大文件，耗时数分钟）…")
        try:
            proc = subprocess.run([sys.executable, str(HERE / "smoke_s2.py")],
                                  capture_output=True, text=True, encoding="utf-8",
                                  errors="replace", timeout=3600, cwd=str(ROOT))
            out = (proc.stdout or "") + (proc.stderr or "")
            match = re.search(r"S2 自测：(\d+)/10 通过", out)
            ok_s2 = proc.returncode == 0 and match and match.group(1) == "10"
            notes.append("smoke_s2 子进程 → rc=%s %s"
                         % (proc.returncode, match.group(0) if match else "未找到汇总行"))
        except Exception as exc:
            ok_s2 = False
            notes.append("smoke_s2 子进程异常：%r" % (exc,))
    return ok_s1 and ok_s2, "；".join(notes)


def c9_audit_security(ctx, opts):
    """C9 审计与安全：/v1/audit（汇总各实例审计文件）含 enroll/pin/elevate/
    UPDATE_REJECTED/INPUT_LEASE_TAKEN 记录；全审计条目与 node 日志中不出现
    hmac_key 值；新端点缺防重放头 → 400、同 nonce → 409（guard 链不回退）。"""
    notes = []
    jsonl = sorted(ctx.tmp.rglob("audit-*.jsonl"))
    text = "".join(p.read_text(encoding="utf-8", errors="replace") for p in jsonl)
    markers = ["POST /v1/update/enroll", "POST /v1/update/pin", "UPDATE_REJECTED",
               "INPUT_LEASE_TAKEN", "POST /v1/elevate/remove"]
    missing = [m for m in markers if m not in text]
    ok_audit = not missing
    notes.append("审计文件 %d 个；缺失标记=%s（前置用例未跑到的端点计入缺失；"
                 "node 未升级时全部缺失属待集成）" % (len(jsonl), missing or "无"))

    # hmac_key 泄漏扫描：全部 node 配置（S3 起自动生成 update.hmac_key）+ 注册表条目
    # → 不得出现在任何审计文件或 node 日志中（注册表本身按契约存放 hmac_key，不在扫描面）
    keys = set()
    for p in ctx.tmp.rglob("node*.json"):
        try:
            cfg = json.loads(p.read_text(encoding="utf-8"))
            k = str((cfg.get("update") or {}).get("hmac_key") or "")
            if k:
                keys.add(k)
        except Exception:
            pass
    for entry in (xd.load_registry().get("devices") or {}).values():
        k = str(entry.get("hmac_key") or "")
        if k:
            keys.add(k)
    log_text = ""
    for p in ctx.tmp.glob("node_*.log"):
        log_text += p.read_text(encoding="utf-8", errors="replace")
    leaks = sorted(k[:8] for k in keys
                   if k in text or k in log_text)
    ok_leak = not leaks
    notes.append("hmac_key 值共 %d 个（配置自动生成 + enroll 轮换），审计/日志泄漏=%s"
                 "（回滚后 detached 进程 stdout 未捕获，但其审计/配置已覆盖扫描）"
                 % (len(keys), leaks or "无"))

    # 新端点防重放：缺头 400 / 同 nonce 409（用 /v1/update/enroll——可区分 400 与 200；
    # 轮换主实例密钥无副作用，主实例不被推送更新）
    ok_missing = ok_replay = False
    if not ctx.s3_ready:
        notes.append("新端点防重放验证：node 侧待集成（node_version=%s）"
                     % ctx.node_version)
    else:
        st, body = bare_request(HOST, ctx.port_main, "POST", "/v1/update/enroll",
                                token=TOKEN_DEFAULT, payload={}, timeout=8)
        ok_missing = st == 400 and err_code(body) == "BAD_REQUEST"
        nonce = uuid.uuid4().hex
        hdrs = {"X-Timestamp": str(int(time.time())), "X-Nonce": nonce}
        st1, b1 = bare_request(HOST, ctx.port_main, "POST", "/v1/update/enroll",
                               token=TOKEN_DEFAULT, headers=dict(hdrs), timeout=8)
        st2, b2 = bare_request(HOST, ctx.port_main, "POST", "/v1/update/enroll",
                               token=TOKEN_DEFAULT, headers=dict(hdrs), timeout=8)
        ok_replay = st1 == 200 and st2 == 409 and err_code(b2) == "REPLAY_DETECTED"
        notes.append("新端点缺防重放头 → %s/%s；同 nonce：首次 %s → 重放 %s/%s"
                     % (st, err_code(body) or "-", st1, st2, err_code(b2) or "-"))
    return ok_audit and ok_leak and ok_missing and ok_replay, "；".join(notes)


def c10_cli(ctx, opts):
    """C10 CLI：push-node 输出语义（回滚提示路径用 C2 实例复验——rollback.flag 常驻，
    推送触发"检测到 rollback.flag"提示）；pool 表格与离线标注（离线标注见 C3 证据）；
    release；--take（详见 C6）。"""
    notes = []
    # ① push-node 回滚提示（C2 实例复验）
    ok_push = False
    if not ctx.s3_ready:
        notes.append("push-node 回滚提示：node 侧待集成（node_version=%s）"
                     % ctx.node_version)
    elif not ctx.c2_flag_ok:
        notes.append("push-node 回滚提示：C2 未产生 rollback.flag（前置 C2 未通过），"
                     "路径复验跳过")
    else:
        out, err, error = run_xd(["push-node", "c2dev", "--file", str(ctx.c2_node_py)],
                                 xd.load_registry())
        msgs = out + err + str(error or "")
        ok_push = ("已推送" in msgs
                   and "检测到 rollback.flag（历史回滚未处置，请人工确认）" in msgs
                   and "重启完成" in msgs)
        notes.append("push-node（C2 实例，rollback.flag 常驻）→ 已推送=%s "
                     "检测到 rollback.flag 提示=%s 重启完成=%s err=%s"
                     % ("已推送" in msgs,
                        "检测到 rollback.flag" in msgs, "重启完成" in msgs,
                        (error or "无")[:60]))
        ctx.detached_ports.add(ctx.c2_port)

    # ② pool 表格（表头 + 在线/离线列；离线标注的端到端证据见 C3）
    rc, out_p, _ = run_pool(ctx, 4, as_json=False)
    ok_table = (rc == 0 and "状态" in out_p and "device_id" in out_p
                and ("在线" in out_p or "共 0 台" in out_p))
    notes.append("pool 表格 rc=%s 含表头=%s（在线标注=%s）"
                 % (rc, "device_id" in out_p and "状态" in out_p,
                    "在线" in out_p))

    # ③ release / --take CLI（语义断言在 C6，此处复验可用性）
    ok_rel = ok_take = None
    if not ctx.s3_ready:
        notes.append("release/--take CLI：node 侧待集成（node_version=%s）"
                     % ctx.node_version)
    else:
        out2, err2, error2 = run_xd(["move", "self", "1", "1", "--take"],
                                    xd.load_registry())
        ok_take = (error2 is None and "已发送" in out2) or "未生效" in str(error2 or "")
        out3, err3, error3 = run_xd(["release", "self"], xd.load_registry())
        ok_rel = error3 is None and "已释放输入租约" in out3
        notes.append("CLI --take=%s；CLI release=%s（%s）"
                     % (ok_take, ok_rel, (error3 or "已释放输入租约")[:30]))

    ok = ok_table and (ok_push is not False) and ok_take is not False \
        and ok_rel is not False
    return ok, "；".join(notes)


# --------------------------------------------------------------------------
# 主流程
# --------------------------------------------------------------------------

class Ctx:
    pass


def main():
    ap = argparse.ArgumentParser(description="CrossDevice S3 一键自测（C1–C10）")
    ap.add_argument("--skip-s1", action="store_true",
                    help="跳过 C8 中的 smoke_s1 回归（调试用）")
    ap.add_argument("--skip-s2", action="store_true",
                    help="跳过 C8 中的 smoke_s2 回归（调试用）")
    ap.add_argument("--keep", action="store_true", help="保留临时目录便于排障")
    opts = ap.parse_args()

    tmp = Path(tempfile.mkdtemp(prefix="xd_s3_smoke_"))
    ctx = Ctx()
    ctx.tmp = tmp
    ctx.nodes = []
    ctx.node_main = None
    ctx.detached_ports = set()          # self-update 后 detached 重启的副本端口（收尾清理）
    ctx.s3_ready = False
    ctx.node_version = "?"
    ctx.main_device_id = None
    ctx.c1_nodeobj = None
    ctx.c2_nodeobj = None
    ctx.c2_flag_ok = False
    ctx.c2_watchdog_copied = False
    ctx.c2_orig_version = "0.4.0"
    print("临时目录：%s" % tmp)
    print("node.py：%s" % smoke_s1.NODE_PY)
    print("-" * 76)

    exit_code = 1
    try:
        # 证书与配置（全部临时目录；三身份 default/tester/third）
        tls1 = tmp / "tls1"
        ctx.cert1, ctx.key1 = tls1 / "cert.pem", tls1 / "key.pem"
        ctx.fp1 = gen_cert(tls1)
        print("证书指纹：%s" % ctx.fp1)

        ctx.port_main = free_port()
        ctx.work = tmp / "work"
        ctx.work.mkdir(parents=True, exist_ok=True)
        ctx.cfg = tmp / "config" / "node.json"
        write_json(ctx.cfg, {
            "version": 1, "tokens": s3_tokens(),
            "tls": {"cert": str(ctx.cert1), "key": str(ctx.key1)},
            "audit": {"retention_days": 180},
            "workspace": [str(ctx.work)],
        })

        # xd 注册表打补丁到临时目录（绝不触碰仓库 data/）
        xd.REGISTRY = tmp / "registry" / "devices.json"
        xd.DATA = xd.REGISTRY.parent
        xd.save_registry({"devices": {}})

        def seed_self(reg):
            reg["devices"]["self"] = {
                "name": "self", "ip": HOST, "port": ctx.port_main,
                "token": TOKEN_DEFAULT, "identity": "default",
                "cert_fingerprint": "", "mac": "", "ips": [], "hmac_key": "",
                "added_at": time.time(), "last_seen": None, "info": {},
            }

        xd.registry_update(seed_self)
        ctx.dev = xd.load_registry()["devices"]["self"]
        ctx.runner = make_xd_runner(tmp)

        # node 主实例（C3 广播 / C6 租约 / C7 remove / C9 防重放 / C10 表格）
        ctx.node_main = NodeProc("main", ctx.port_main, [], ctx.cfg, ctx.tmp,
                                 cert=ctx.cert1, key=ctx.key1)
        ctx.nodes.append(ctx.node_main)
        try:
            ctx.node_main.ready(TOKEN_DEFAULT)
            health = health_of(ctx.port_main)
            ctx.node_version = str(health.get("node_version") or "?")
            ctx.s3_ready = s3_ready(health)
            print("node 主实例就绪，node_version=%s，S3 端点就绪=%s"
                  % (ctx.node_version, ctx.s3_ready))
            if ctx.s3_ready:
                info = xd.request(ctx.dev, "GET", "/v1/info", timeout=10) or {}
                ctx.main_device_id = str(info.get("device_id") or "")
                if ctx.main_device_id:
                    # 条目 info 记录 device_id（§19.3/§19.4：device_id 精确匹配，
                    # 防同机多 node 的 hostname 回退误匹配）
                    def set_info(reg):
                        reg["devices"]["self"]["info"] = {
                            "device_id": ctx.main_device_id}

                    xd.registry_update(set_info)
                    ctx.dev = xd.load_registry()["devices"]["self"]
        except NodeNotReady as exc:
            ctx.node_version = "?"
            print("!! node 主实例未就绪（node 侧）：%s" % exc)
        print("-" * 76)

        # C1/C2 专用实例：node.py 临时副本（推送目标为副本，绝不更新仓库 node/node.py），
        # watchdog.py 复制到副本同目录（若仓库已交付）；两实例相互独立，防白名单/回滚交叉污染
        ctx.c1_node_py, _ = make_node_copy(tmp, "c1")
        ctx.c2_node_py, ctx.c2_watchdog_copied = make_node_copy(tmp, "c2")
        ctx.c1_cfg = tmp / "c1cfg" / "node.json"
        ctx.c2_cfg = tmp / "c2cfg" / "node.json"
        for cfg in (ctx.c1_cfg, ctx.c2_cfg):
            write_json(cfg, {
                "version": 1, "tokens": s3_tokens(),
                "tls": {"cert": str(ctx.cert1), "key": str(ctx.key1)},
                "audit": {"retention_days": 180},
            })

        def seed_entry(name, port):
            def fn(reg):
                reg["devices"][name] = {
                    "name": name, "ip": HOST, "port": port,
                    "token": TOKEN_DEFAULT, "identity": "default",
                    "cert_fingerprint": "", "mac": "", "ips": [], "hmac_key": "",
                    "added_at": time.time(), "last_seen": None, "info": {},
                }
            xd.registry_update(fn)

        ctx.c1_port = free_port()
        seed_entry("c1dev", ctx.c1_port)
        ctx.c2_port = free_port()
        seed_entry("c2dev", ctx.c2_port)
        ctx.c1_dev = xd.load_registry()["devices"]["c1dev"]
        ctx.c2_dev = xd.load_registry()["devices"]["c2dev"]

        ctx.c1_nodeobj = s3_copy_node("c1copy", tmp, ctx.c1_node_py,
                                      ["--host", HOST, "--port", str(ctx.c1_port),
                                       "--config", str(ctx.c1_cfg), "--verbose"])
        ctx.nodes.append(ctx.c1_nodeobj)
        ctx.c2_nodeobj = s3_copy_node("c2copy", tmp, ctx.c2_node_py,
                                      ["--host", HOST, "--port", str(ctx.c2_port),
                                       "--config", str(ctx.c2_cfg), "--verbose"])
        ctx.nodes.append(ctx.c2_nodeobj)
        for tag, obj, port in (("c1", ctx.c1_nodeobj, ctx.c1_port),
                               ("c2", ctx.c2_nodeobj, ctx.c2_port)):
            try:
                obj.ready(TOKEN_DEFAULT, port, timeout=40)
            except NodeNotReady as exc:
                print("!! %s 副本实例未就绪（node 侧）：%s" % (tag, str(exc)[:150]))
        ctx.c2_orig_version = str(health_of(ctx.c2_port).get("node_version")
                                  or ctx.node_version)
        print("-" * 76)

        for code, title, fn in [
            ("C1", "签名更新", c1_signed_update),
            ("C2", "看门狗回滚", c2_watchdog_rollback),
            ("C3", "广播上线", c3_broadcast),
            ("C4", "限频与不信任", c4_flood_no_trust),
            ("C5", "端口同步", c5_port_sync),
            ("C6", "输入租约", c6_input_lease),
            ("C7", "高权限驻留", c7_elevate),
            ("C8", "回归", c8_regression),
            ("C9", "审计与安全", c9_audit_security),
            ("C10", "CLI", c10_cli),
        ]:
            try:
                ok, evidence = fn(ctx, opts)
            except Exception as exc:
                ok, evidence = False, "测试框架异常：%r" % (exc,)
            record(code, title, ok, evidence)

        passed = sum(1 for _, _, ok in RESULTS if ok)
        print("-" * 76)
        print("S3 自测：%d/%d 通过" % (passed, len(RESULTS)))
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
        # self-update/看门狗重启产生的 detached node 副本进程：
        # 先按端口清理（netstat → taskkill），再按临时副本路径命令行兜底清扫
        for port in sorted(ctx.detached_ports):
            try:
                kill_port_listener(port)
            except Exception:
                pass
        try:
            kill_by_cmdline(str(tmp / "nodes"))
        except Exception:
            pass
        if opts.keep:
            print("临时目录保留：%s" % tmp)
        else:
            time.sleep(1)
            shutil.rmtree(tmp, ignore_errors=True)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
