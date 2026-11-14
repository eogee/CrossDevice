#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""CrossDevice 看门狗（watchdog.py）—— 契约 §20.4 一次性验证模式（--once）。

定位（接口契约 §20 开篇，评审硬伤 D13 的修复主体）：
  回滚主体是"永不参与热更新的独立看门狗"。本文件位于仓库根、与 xd.py 平级，
  绝不入 push-node / self-update 的被更新路径（push-node 只替换 node/node.py），
  因此它自身永远不会被热更新覆盖，可在 node 新包崩溃后独立完成回滚。

--once 流程（S3 唯一模式，契约 §20.4 接口冻结）：
    python watchdog.py --node <node.py 路径> --python <解释器> --args "<node 启动参数串>"
                       --bak <bak 路径> --once [--grace <秒，默认 60>] [--port <探活端口>]

  1. 失败预检（--bak 缺失 / 无法确定探活端口 / 参数错误 → 写日志非零退出，不盲目回滚）；
  2. 判定规则①：启动静默 2 秒（跳过旧进程残存监听）；
  3. 判定规则②：启动等待窗 = min(grace, 15) 秒，窗内从未探活成功 → 回滚；
  4. 判定规则③：首次探活成功后进入稳定观察至 grace 到期，连续 4 次探活失败 → 回滚；
  5. 判定规则④：grace 到期且最近一次探活成功 → 验证通过正常退出（不回滚、不写 rollback.flag）；
  6. 回滚动作：os.replace(bak, node)（10×0.1s 短重试）→ 以 --args 解析参数 detached
     重启 node（启动输出追加重定向至 watchdog-restart-out.log 便于定位启动失败）
     → 写 rollback.flag（node.py 同目录，常驻不自动删）→ watchdog.log 追加日志
     → 恢复探活（至多 10 秒，记录恢复状态）。

退出码：0 = 正常结束（验证通过或成功回滚）；2 = 参数错误；3 = --bak 缺失；
        4 = 无法确定探活端口；5 = 回滚替换失败；6 = node 重启拉起失败；
        7 = rollback.flag 写入失败；8 = 未预期异常；130 = 键盘中断。

仅标准库，无第三方依赖（契约 Q-01）。
"""

import argparse
import hashlib
import json
import os
import shlex
import socket
import ssl
import subprocess
import sys
import tempfile
import time

# --------------------------------------------------------------------------
# 常量（契约 §20.4 冻结口径，不得偏离）
# --------------------------------------------------------------------------

SILENCE_SECONDS = 2.0          # 判定规则①：启动静默（跳过旧进程残存监听）
STARTUP_WINDOW_CAP = 15.0      # 判定规则②：启动等待窗上限（min(grace, 15)）
CONSECUTIVE_FAIL_LIMIT = 4     # 判定规则③：稳定观察期连续失败阈值
PROBE_INTERVAL = 1.0           # 探活间隔 1 秒
RECOVERY_WAIT_SECONDS = 10.0   # 回滚重启后恢复探活等待上限（契约 §20.4）
REPLACE_RETRIES = 10           # os.replace 短重试次数（同 node/xd 原子写 10×0.1s 风格）
REPLACE_RETRY_INTERVAL = 0.1   # os.replace 短重试间隔
PROBE_TIMEOUT = 2.0            # 单次探活连接/读取超时

DETACHED_PROCESS = 0x00000008  # 与 node.py 同款：detached 启动
CREATE_NO_WINDOW = 0x08000000  # 与 node.py 同款：不弹窗口

EXIT_OK = 0                    # 正常结束（验证通过或成功回滚）
EXIT_ARG_ERROR = 2             # 参数错误
EXIT_BAK_MISSING = 3           # --bak 缺失
EXIT_PORT_UNKNOWN = 4          # 无法确定探活端口
EXIT_REPLACE_FAILED = 5        # 回滚替换失败
EXIT_RESTART_FAILED = 6        # node 重启拉起失败
EXIT_FLAG_FAILED = 7           # rollback.flag 写入失败
EXIT_UNEXPECTED = 8            # 未预期异常

WATCHDOG_LOG_NAME = "watchdog.log"      # node.py 同目录（契约 §20.4）
ROLLBACK_FLAG_NAME = "rollback.flag"    # node.py 同目录（契约 §20.4/§6.1）
RESTART_OUTPUT_NAME = "watchdog-restart-out.log"  # 重启 node 的启动输出（可观测性）


# --------------------------------------------------------------------------
# 日志（watchdog.log 追加写，node.py 同目录，契约 §20.4）
# --------------------------------------------------------------------------

class Logger(object):
    """watchdog.log 追加写；同时回显 stderr 便于人工/测试观察（detached 下 stderr
    可能为 None，需判空防护）。"""

    def __init__(self, path):
        self.path = path

    def write(self, message):
        line = "[%s] %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), message)
        try:
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        except OSError:
            # 日志不可写（磁盘/权限）：仅 stderr 告警，不阻断主流程
            if sys.stderr:
                try:
                    sys.stderr.write("[watchdog] 日志写入失败: %s\n" % line)
                except OSError:
                    pass
        if sys.stderr:
            try:
                sys.stderr.write(line + "\n")
            except OSError:
                pass


# --------------------------------------------------------------------------
# 通用辅助
# --------------------------------------------------------------------------

def _short_err(exc):
    """异常摘要（单行、截断，避免日志行失控）。"""
    text = str(exc).replace("\r", " ").replace("\n", " ").strip()
    return text[:80] if text else exc.__class__.__name__


def sha256_file(path):
    """文件 SHA-256（64 位小写十六进制，分块读取）。"""
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def parse_args_string(raw):
    """解析 --args（契约 §20.4 冻结口径）：shlex.split(s, posix=False) 后去除各
    token 首尾成对引号（引号内空格保留；Windows 反斜杠路径原样保留）。"""
    tokens = shlex.split(raw, posix=False)
    out = []
    for tok in tokens:
        if len(tok) >= 2 and tok[0] == tok[-1] and tok[0] in ('"', "'"):
            tok = tok[1:-1]
        out.append(tok)
    return out


def extract_port_from_tokens(tokens):
    """从 node 启动参数 token 中解析 --port <N> / --port=<N>（后备口径，仅当未
    显式传 --port 时使用）。解析不到返回 None。"""
    for i, tok in enumerate(tokens):
        candidate = None
        if tok == "--port" and i + 1 < len(tokens):
            candidate = tokens[i + 1]
        elif tok.startswith("--port="):
            candidate = tok[len("--port="):]
        if candidate is not None:
            candidate = candidate.strip().strip('"').strip("'")
            if candidate.isdigit() and 1 <= int(candidate) <= 65535:
                return int(candidate)
    return None


def mask_secret_tokens(tokens):
    """日志脱敏（契约 §2.1：令牌永不写入任何日志）：遮蔽 --token 的值。
    --args 沿自 node 启动参数串，正常不含令牌（令牌在 node.json），防御性遮蔽。"""
    out = []
    skip_next = False
    for tok in tokens:
        if skip_next:
            out.append("***")
            skip_next = False
            continue
        if tok == "--token":
            out.append(tok)
            skip_next = True
            continue
        if tok.startswith("--token="):
            out.append("--token=***")
            continue
        out.append(tok)
    if skip_next:
        out.append("***")
    return out


def replace_file_with_retry(src, dst):
    """os.replace 带 10×0.1s 短重试（与 xd.py/_atomic_write_text、node.py 原子写
    同款风格，防 Windows 实时扫描等瞬时占用目标的 WinError 5）。"""
    last_exc = None
    for _ in range(REPLACE_RETRIES):
        try:
            os.replace(src, dst)
            return
        except OSError as exc:
            last_exc = exc
            transient = isinstance(exc, PermissionError) \
                or "WinError 5" in str(exc) or "拒绝访问" in str(exc)
            if not transient:
                raise
            time.sleep(REPLACE_RETRY_INTERVAL)
    raise last_exc


def write_json_atomic(path, data):
    """原子写 JSON：同目录临时文件 + os.replace 短重试（node.py atomic_write_json
    同款风格）。用于 rollback.flag（契约 §9.1 原子写要求同理适用）。"""
    directory = os.path.dirname(os.path.abspath(path)) or "."
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".tmp-watchdog-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=2)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        replace_file_with_retry(tmp, path)
    except BaseException:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise


def _sleep_cadence(probe_started):
    """维持探活节奏：距上次探活开始不足 1 秒则补足间隔（契约：探活间隔 1 秒）。"""
    elapsed = time.time() - probe_started
    time.sleep(max(0.05, PROBE_INTERVAL - elapsed))


# --------------------------------------------------------------------------
# 探活（契约 §20.4 冻结口径）
# --------------------------------------------------------------------------

def _http_status_line(sock):
    """发送 GET / 并读响应首行；读到 HTTP/ 前缀返回状态行文本，否则 None。"""
    sock.sendall(b"GET / HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
    deadline = time.time() + PROBE_TIMEOUT
    buf = b""
    while time.time() < deadline:
        try:
            chunk = sock.recv(256)
        except OSError:
            break
        if not chunk:
            break
        buf += chunk
        if b"\r\n" in buf or len(buf) >= 512:
            break
    if buf[:5] == b"HTTP/":
        return buf.split(b"\r\n", 1)[0].decode("latin-1", "replace").strip()
    return None


def probe_once(port):
    """单次探活（契约 §20.4 冻结口径）：
      - 目标 127.0.0.1:<port>；
      - 先 TLS：ssl.SSLContext(PROTOCOL_TLS_CLIENT)，check_hostname=False、
        verify_mode=CERT_NONE（仅探活不信任），完成握手并发送 GET / 读响应首行，
        收到任意 HTTP 状态码响应（含 401——看门狗无令牌，401 即"存活"口径）即算存活；
      - TLS 失败再试明文：TCP 连接 + 任意 HTTP 响应（兼容 --debug-plaintext）。
    返回 (是否存活, 结果摘要文本)。"""
    errors = []
    # ---- TLS 模式（默认）----
    sock = None
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False          # 先关主机名校验，再放开证书校验
        ctx.verify_mode = ssl.CERT_NONE
        sock = socket.create_connection(("127.0.0.1", port), timeout=PROBE_TIMEOUT)
        sock = ctx.wrap_socket(sock, server_hostname="127.0.0.1")
        line = _http_status_line(sock)
        if line:
            return True, "TLS %s" % line
        errors.append("TLS握手成功但无HTTP响应")
    except Exception as exc:                # noqa: BLE001 探活对一切失败都要兜住
        errors.append("TLS:%s" % _short_err(exc))
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
    # ---- 明文兜底（--debug-plaintext 场景）----
    sock = None
    try:
        sock = socket.create_connection(("127.0.0.1", port), timeout=PROBE_TIMEOUT)
        line = _http_status_line(sock)
        if line:
            return True, "明文 %s" % line
        errors.append("明文连接成功但无HTTP响应")
    except Exception as exc:                # noqa: BLE001
        errors.append("明文:%s" % _short_err(exc))
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
    return False, "；".join(errors)


def port_has_listener(port, timeout=0.3):
    """端口是否仍有监听者（快速 TCP connect 探测）。
    一期口径：回滚重启前发现端口被残留坏进程占用时仅在日志注明，不杀进程。"""
    try:
        sock = socket.create_connection(("127.0.0.1", port), timeout=timeout)
        sock.close()
        return True
    except OSError:
        return False


def probe_and_log(log, counter, port, tag="探活"):
    """探活一次并写日志（契约 §20.4：日志含每次探活结果摘要）。"""
    counter[0] += 1
    ok, detail = probe_once(port)
    if ok:
        log.write("%s#%d 成功（%s）" % (tag, counter[0], detail))
    else:
        log.write("%s#%d 失败（%s）" % (tag, counter[0], detail))
    return ok


# --------------------------------------------------------------------------
# 回滚（契约 §20.4 冻结动作序列）
# --------------------------------------------------------------------------

def do_rollback(log, node_path, node_dir, bak_path, python_exe, tokens, port,
                reason, counter):
    """回滚动作：os.replace(bak, node) 短重试 → detached 重启 node → 写
    rollback.flag（常驻）→ 恢复探活（≤10 秒记录恢复状态）。返回退出码。"""
    flag_path = os.path.join(node_dir, ROLLBACK_FLAG_NAME)

    # ---- sha256 口径（契约 §20.4）：old = .bak 内容；new = 被回滚 node.py 内容 ----
    try:
        old_sha = sha256_file(bak_path)
    except OSError as exc:
        log.write("[失败] 读取 .bak 失败：%s；不写 rollback.flag。" % _short_err(exc))
        return EXIT_REPLACE_FAILED
    new_sha = ""
    try:
        new_sha = sha256_file(node_path)
    except OSError:
        log.write("[警告] 被回滚的 node.py 读取失败（可能已被外部删除），new_sha256 置空。")

    # ---- ① 回滚替换（10×0.1s 短重试）----
    try:
        replace_file_with_retry(bak_path, node_path)
    except OSError as exc:
        log.write("[失败] 回滚替换失败（os.replace %s → %s）：%s；不写 rollback.flag。"
                  % (bak_path, node_path, _short_err(exc)))
        log.write("===== 看门狗结束：回滚替换失败，退出码 %d =====" % EXIT_REPLACE_FAILED)
        return EXIT_REPLACE_FAILED
    log.write("回滚替换完成：os.replace(%s → %s)，已恢复旧包（old_sha256=%s…）"
              % (bak_path, node_path, old_sha[:16]))

    # ---- 一期口径：端口被残留坏进程占用仅注明（不杀进程）----
    if port_has_listener(port):
        log.write("注意：重启前端口 %d 仍有监听者（疑似坏包残留进程占用）。一期口径不杀进程，"
                  "仅注明：重启的 node 可能因端口占用顺延（契约 §16.1），恢复探活按配置端口进行。"
                  % port)

    # ---- ② detached 重启 node（契约 §20.4；启动输出追加重定向到
    #      watchdog-restart-out.log——回滚重启失败时运维可据此定位，冻结接口
    #      未规定 std 句柄去向，属实现自由项）----
    launched = False
    restart_out_path = os.path.join(node_dir, RESTART_OUTPUT_NAME)
    try:
        restart_out = open(restart_out_path, "ab")
        try:
            subprocess.Popen(
                [python_exe, node_path] + tokens,
                creationflags=DETACHED_PROCESS | CREATE_NO_WINDOW,
                close_fds=True,
                cwd=node_dir,
                stdin=subprocess.DEVNULL,
                stdout=restart_out,
                stderr=subprocess.STDOUT)
        finally:
            restart_out.close()   # 子进程已继承句柄副本，父进程可立即关闭
        launched = True
        log.write("已以 detached 方式重启 node（python=%s，参数 %d 个，cwd=%s；"
                  "启动输出追加至 %s）" % (python_exe, len(tokens), node_dir,
                                          RESTART_OUTPUT_NAME))
    except OSError as exc:
        log.write("[失败] node 重启拉起失败：%s（rollback.flag 仍照常写入）" % _short_err(exc))

    # ---- ③ rollback.flag（常驻不自动删，供 /v1/health 的 rollback_flag 与
    #      控制端 push-node 识别"更新曾被看门狗回滚、需人工处置"）----
    flag = {
        "ts": time.time(),
        "reason": reason,
        "old_sha256": old_sha,
        "new_sha256": new_sha,
        "restored": True,
    }
    try:
        write_json_atomic(flag_path, flag)
        log.write("rollback.flag 已写入：%s" % json.dumps(flag, ensure_ascii=False))
    except OSError as exc:
        log.write("[失败] rollback.flag 写入失败：%s" % _short_err(exc))
        log.write("===== 看门狗结束：退出码 %d =====" % EXIT_FLAG_FAILED)
        return EXIT_FLAG_FAILED

    # ---- ④ 恢复探活（契约 §20.4：回滚后等待至多 10 秒记录恢复状态）----
    if not launched:
        log.write("恢复状态：跳过（node 重启拉起失败，需人工介入）")
        log.write("===== 看门狗结束：回滚完成但重启失败，退出码 %d =====" % EXIT_RESTART_FAILED)
        return EXIT_RESTART_FAILED

    rec_deadline = time.time() + RECOVERY_WAIT_SECONDS
    rec_started = time.time()
    rec_ok = False
    while time.time() < rec_deadline:
        started = time.time()
        if probe_and_log(log, counter, port, tag="恢复探活"):
            rec_ok = True
            break
        _sleep_cadence(started)
    if rec_ok:
        log.write("恢复状态：node 已恢复探活成功（重启后 %.1f 秒）" % (time.time() - rec_started))
    else:
        log.write("恢复状态：%g 秒内未探活成功（node 可能仍在启动，或端口被残留进程占用已顺延）"
                  % RECOVERY_WAIT_SECONDS)
    log.write("===== 看门狗结束：回滚完成，退出码 %d =====" % EXIT_OK)
    return EXIT_OK


# --------------------------------------------------------------------------
# --once 验证主流程（契约 §20.4 判定规则①②③④）
# --------------------------------------------------------------------------

def verify_once(args, log, node_path, node_dir, bak_path, python_exe, tokens,
                port, counter):
    run_start = time.time()

    # ---- 判定规则①：启动静默 2 秒（跳过旧进程残存监听，防替换过渡期误判）----
    log.write("① 启动静默 %g 秒（跳过旧进程残存监听）……" % SILENCE_SECONDS)
    time.sleep(SILENCE_SECONDS)

    window = min(args.grace, STARTUP_WINDOW_CAP)
    window_deadline = run_start + SILENCE_SECONDS + window
    overall_deadline = run_start + args.grace
    log.write("② 启动等待窗 %g 秒（min(grace=%g, %g)），窗内从未探活成功则回滚"
              % (window, args.grace, STARTUP_WINDOW_CAP))

    ever_ok = False
    last_ok = False
    consec_fail = 0
    reason = None

    # ---- 判定规则②：启动等待窗，窗内从未探活成功 → 回滚 ----
    while time.time() < window_deadline:
        started = time.time()
        ok = probe_and_log(log, counter, port)
        last_ok = ok
        if ok:
            ever_ok = True
            consec_fail = 0
            log.write("首次探活成功 → 进入稳定观察，至 grace 到期（剩余 %g 秒）"
                      % max(0.0, overall_deadline - time.time()))
            break
        _sleep_cadence(started)

    if not ever_ok:
        reason = "启动等待窗 %g 秒内探活从未成功（新包疑似无法启动）" % window
    else:
        # ---- 判定规则③：稳定观察至 grace 到期，连续 4 次探活失败 → 回滚 ----
        log.write("③ 稳定观察期：期间连续 %d 次探活失败则回滚" % CONSECUTIVE_FAIL_LIMIT)
        while time.time() < overall_deadline:
            started = time.time()
            ok = probe_and_log(log, counter, port)
            last_ok = ok
            if ok:
                consec_fail = 0
            else:
                consec_fail += 1
                if consec_fail >= CONSECUTIVE_FAIL_LIMIT:
                    reason = ("稳定观察期连续 %d 次探活失败（新包疑似运行后崩溃）"
                              % CONSECUTIVE_FAIL_LIMIT)
                    break
            _sleep_cadence(started)
        if reason is None:
            # ---- 判定规则④：grace 到期且最近一次探活成功 → 验证通过 ----
            if last_ok:
                log.write("④ grace 到期且最近一次探活成功 → 验证通过"
                          "（不回滚、不写 rollback.flag）")
                log.write("===== 看门狗结束：验证通过，退出码 %d =====" % EXIT_OK)
                return EXIT_OK
            # 规则④通过条件要求最近一次探活成功；到期时仍失败（未达连续 4 次）按未通过回滚
            reason = ("grace 到期时最近一次探活失败（连续失败 %d 次，不满足验证通过条件）"
                      % consec_fail)

    log.write("[判定] 触发回滚：%s" % reason)
    return do_rollback(log, node_path, node_dir, bak_path, python_exe, tokens,
                       port, reason, counter)


def run(args, log):
    """--once 主入口：失败预检 → 参数摘要 → verify_once。返回退出码。"""
    node_path = os.path.abspath(args.node)
    node_dir = os.path.dirname(node_path)
    bak_path = os.path.abspath(args.bak)
    python_exe = args.python
    counter = [0]

    log.write("===== 看门狗启动（--once，PID %d，契约 §20.4）=====" % os.getpid())
    log.write("开始时间：%s" % time.strftime("%Y-%m-%d %H:%M:%S"))

    # ---- 预留常驻模式（契约 §20.4：可预留参数但本阶段不必实现）----
    if args.daemon:
        log.write("[失败] 常驻模式（--daemon）一期未实现，当前仅支持 --once。")
        return EXIT_ARG_ERROR

    if not (args.grace > 0):
        log.write("[失败] --grace 必须为正数，收到 %r。" % args.grace)
        return EXIT_ARG_ERROR

    if bak_path == node_path:
        log.write("[失败] --bak 与 --node 指向同一文件，回滚无意义。")
        return EXIT_ARG_ERROR

    # ---- 失败路径：--bak 缺失（写日志非零退出，不产生 rollback.flag）----
    if not os.path.isfile(bak_path):
        log.write("[失败] --bak 不存在：%s（无法回滚，不写 rollback.flag，不探活）。"
                  % bak_path)
        return EXIT_BAK_MISSING

    # ---- --args 解析（冻结口径：shlex.split(posix=False) + 去首尾成对引号）----
    try:
        tokens = parse_args_string(args.args)
    except ValueError as exc:
        log.write("[失败] --args 解析失败：%s" % _short_err(exc))
        return EXIT_ARG_ERROR
    if not tokens:
        log.write("[警告] --args 解析结果为空 token 列表，重启 node 时将不携带参数。")

    # ---- 探活端口：显式 --port > --args 解析；两者皆无 → 写日志非零退出（不盲目回滚）----
    if args.port is not None:
        if not 1 <= args.port <= 65535:
            log.write("[失败] --port 非法（1-65535）：%d。" % args.port)
            return EXIT_ARG_ERROR
        port, port_source = args.port, "显式 --port"
    else:
        parsed = extract_port_from_tokens(tokens)
        if parsed is None:
            log.write("[失败] 无法确定探活端口：未显式传 --port，且 --args 中解析不到 --port。"
                      "按契约 §20.4 不盲目回滚，以非零码退出。")
            return EXIT_PORT_UNKNOWN
        port, port_source = parsed, "--args 解析"

    # ---- 参数摘要（--token 值脱敏，契约 §2.1）----
    log.write("参数摘要：node=%s；bak=%s；python=%s；grace=%g 秒；探活端口=%d（来源：%s）"
              % (node_path, bak_path, python_exe, args.grace, port, port_source))
    log.write("node 启动参数（--args 解析，%d 个 token，已脱敏）：%s"
              % (len(tokens), " ".join(mask_secret_tokens(tokens)) or "（空）"))

    return verify_once(args, log, node_path, node_dir, bak_path, python_exe,
                       tokens, port, counter)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def build_parser():
    parser = argparse.ArgumentParser(
        prog="watchdog.py",
        description="CrossDevice 看门狗（契约 §20.4，--once 一次性验证模式；"
                    "永不参与热更新）")
    parser.add_argument("--node", required=True,
                        help="node.py 路径（被验证/被回滚对象）")
    parser.add_argument("--python", required=True,
                        help="用于重启 node 的解释器")
    parser.add_argument("--args", required=True,
                        help='node 启动参数串，如 "--host 127.0.0.1 --port 51888 '
                             '--config <node.json>"')
    parser.add_argument("--bak", required=True,
                        help="更新前备份（node.py.bak）路径")
    parser.add_argument("--once", action="store_true", required=True,
                        help="一次性验证模式（S3 唯一模式）")
    parser.add_argument("--grace", type=float, default=60.0,
                        help="验证观察窗秒数（默认 60）")
    parser.add_argument("--port", type=int, default=None,
                        help="探活端口（缺省从 --args 解析 --port；两者皆无则失败退出）")
    parser.add_argument("--daemon", action="store_true",
                        help=argparse.SUPPRESS)   # 预留常驻模式，一期未实现
    return parser


def _emergency_arg_failure_log(argv):
    """argparse 参数错误时的兜底日志：尽力从原始 argv 定位 --node，把失败写入
    其目录下 watchdog.log（契约 §20.4：参数错误也要写日志并以非零码退出）。"""
    try:
        for i, item in enumerate(argv):
            value = None
            if item == "--node" and i + 1 < len(argv):
                value = argv[i + 1]
            elif item.startswith("--node="):
                value = item[len("--node="):]
            if value:
                node_dir = os.path.dirname(
                    os.path.abspath(value.strip().strip('"').strip("'")))
                if os.path.isdir(node_dir):
                    Logger(os.path.join(node_dir, WATCHDOG_LOG_NAME)).write(
                        "[失败] 参数错误（argparse 校验未通过），以非零码退出。")
                break
    except Exception:                       # noqa: BLE001 兜底日志自身不再抛错
        pass


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else EXIT_ARG_ERROR
        if code != 0:
            _emergency_arg_failure_log(argv)
        return code

    node_dir = os.path.dirname(os.path.abspath(args.node))
    if not os.path.isdir(node_dir):
        message = ("[失败] --node 所在目录不存在，无法写 watchdog.log / "
                   "rollback.flag：%s" % node_dir)
        if sys.stderr:
            try:
                sys.stderr.write(message + "\n")
            except OSError:
                pass
        return EXIT_ARG_ERROR

    log = Logger(os.path.join(node_dir, WATCHDOG_LOG_NAME))
    try:
        return run(args, log)
    except KeyboardInterrupt:
        log.write("[中断] 收到键盘中断，未回滚、未写 rollback.flag。")
        return 130
    except Exception as exc:                # noqa: BLE001 看门狗自身不允许裸崩
        try:
            log.write("[失败] 未预期异常：%s: %s"
                      % (exc.__class__.__name__, _short_err(exc)))
        except Exception:                   # noqa: BLE001
            pass
        return EXIT_UNEXPECTED


if __name__ == "__main__":
    sys.exit(main())
