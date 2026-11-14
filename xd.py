#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CrossDevice CLI —— 本机侧入口，不监听任何端口。

S1 安全基线改造（唯一行为依据 docs/接口契约.md V1.0）：
  - 传输层 HTTPS（TLS 1.3，自签证书 + TOFU 指纹固定，契约第 4 章）；
  - 每个请求携带防重放头 X-Timestamp / X-Nonce，每次请求独立 nonce（契约第 3 章）；
  - 注册表加固：msvcrt 文件锁 + 原子写，修改统一走 registry_update（契约 9.2）；
  - `add` 新增可选 --identity 身份名；设备类子命令新增可选 --trust 确认指纹变更；
  - 新增 `audit ls` / `audit export` 子命令（契约 8.4）。
既有子命令的输出格式与语义保持不变（E-02，兼容清单第 11 章）。
"""

import argparse
import base64
import hashlib
import http.client
import json
import msvcrt
import os
import re
import ssl
import sys
import time
import urllib.parse
import uuid
from pathlib import Path

import discover

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data"                 # 模块级常量保留可替换性；实际读写一律以 REGISTRY 为准
REGISTRY = DATA / "devices.json"
NODE_SOURCE = ROOT / "node" / "node.py"

LOCK_TIMEOUT = 5.0                   # 注册表文件锁等待上限（秒），契约 9.2
TRUST_HELP = "确认并接受服务器证书指纹变更（TOFU）"


# --------------------------------------------------------------------------
# 注册表（契约 9.2：原子写 + 文件锁，读改写整体持锁）
# --------------------------------------------------------------------------

def _atomic_write_text(path, text):
    """同目录临时文件（随机后缀防并发同名）+ os.replace 原子写。"""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.parent / ("%s.tmp-%d-%s" % (path.name, os.getpid(), uuid.uuid4().hex[:8]))
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        for attempt in range(20):
            try:
                os.replace(tmp, path)
                break
            except PermissionError:
                # 目标文件瞬时被其他进程打开（读）导致替换失败：短重试
                if attempt == 19:
                    raise
                time.sleep(0.05)
    finally:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass


def _normalize_registry(registry):
    """写回前补齐 S1 新增键（契约 9.2：旧条目任何写回操作补齐 identity / cert_fingerprint）。"""
    devices = registry.get("devices")
    if not isinstance(devices, dict):
        registry["devices"] = {}
        return registry
    for name, device in devices.items():
        if isinstance(device, dict):
            device.setdefault("name", name)
            device.setdefault("identity", "default")
            device.setdefault("cert_fingerprint", "")
    return registry


def load_registry():
    if REGISTRY.exists():
        try:
            return json.loads(REGISTRY.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {"devices": {}}


def save_registry(registry):
    """无锁保存入口（仅限初始化等单进程场景）；并发修改请走 registry_update。"""
    _normalize_registry(registry)
    _atomic_write_text(REGISTRY, json.dumps(registry, ensure_ascii=False, indent=2))


class _RegistryLock:
    """<registry>.lock 文件独占锁（msvcrt.locking，超时约 5 秒报错）。"""

    def __init__(self, timeout=LOCK_TIMEOUT):
        self.path = Path(str(REGISTRY) + ".lock")
        self.timeout = timeout
        self.fh = None

    def acquire(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            size = self.path.stat().st_size
        except OSError:
            size = 0
        self.fh = open(self.path, "a+b")          # 不存在则创建
        fh = self.fh
        if size == 0:
            # 空文件补一个占位字节，使锁字节 0 落在文件内；
            # 追加写走 EOF，不会触碰其他句柄正锁定的字节区域
            try:
                fh.write(b"0")
                fh.flush()
            except OSError:
                pass
        fh.seek(0)
        deadline = time.time() + self.timeout
        while True:
            try:
                msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
                return self
            except OSError:
                if time.time() >= deadline:
                    fh.close()
                    self.fh = None
                    raise RuntimeError("注册表文件锁获取超时（%s），可能有其他进程正在写注册表"
                                       % self.path)
                time.sleep(0.05)

    def release(self):
        if self.fh is not None:
            try:
                self.fh.seek(0)
                msvcrt.locking(self.fh.fileno(), msvcrt.LK_UNLCK, 1)
            except OSError:
                pass
            try:
                self.fh.close()
            except OSError:
                pass
            self.fh = None

    def __enter__(self):
        return self.acquire()

    def __exit__(self, exc_type, exc, tb):
        self.release()


def registry_update(fn):
    """注册表统一修改入口（契约 9.2）：加锁 → 读磁盘最新 → fn(reg) → 原子写 → 解锁。

    fn 在锁内对“磁盘最新内容”做读改写，返回值透传；fn 抛异常时不写盘、锁照常释放。
    """
    with _RegistryLock():
        registry = load_registry()
        result = fn(registry)
        _normalize_registry(registry)
        _atomic_write_text(REGISTRY, json.dumps(registry, ensure_ascii=False, indent=2))
        return result


def _persist_device(name, mutate):
    """按设备名把一次修改合并进注册表（不影响其他设备的并发修改）。"""
    if not name:
        return
    def fn(reg):
        entry = reg["devices"].get(name)
        if isinstance(entry, dict):
            mutate(entry)
    registry_update(fn)


# --------------------------------------------------------------------------
# HTTP 调用（HTTPS + TOFU 指纹固定 + 防重放头，契约 3.1 / 4.3）
# --------------------------------------------------------------------------

def _tls_context():
    """自签证书 + TOFU：不校验证书链与主机名，以指纹固定替代 CA 校验（契约 4.3）。"""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def _connect_tls(device, timeout, trust=False):
    """建立 TLS 连接并完成 TOFU 指纹校验（在发送任何业务数据之前）。"""
    conn = http.client.HTTPSConnection(device["ip"], device["port"],
                                       context=_tls_context(), timeout=timeout)
    try:
        conn.connect()
        der = conn.sock.getpeercert(binary_form=True)
        if not der:
            raise RuntimeError("TOFU: 未取得对端证书，无法完成指纹校验（%s:%d）"
                               % (device["ip"], device["port"]))
        actual = hashlib.sha256(der).hexdigest()
        expected = (device.get("cert_fingerprint") or "").strip().lower()
        if not expected:
            # 首次连接：TOFU 信任当前证书，指纹记录入注册表
            device["cert_fingerprint"] = actual
            _persist_device(device.get("name") or "",
                            lambda e: e.__setitem__("cert_fingerprint", actual))
        elif expected != actual:
            if not trust:
                raise RuntimeError(
                    "TOFU: 证书指纹变更，已本地拒绝（未发送任何业务数据）\n"
                    "  设备     : %s（%s:%d）\n"
                    "  期望指纹 : %s\n"
                    "  实际指纹 : %s\n"
                    "若确认服务器证书是正常更新，请加 --trust 重试"
                    % (device.get("name") or "?", device["ip"], device["port"],
                       expected, actual))
            # --trust：显式确认新指纹，更新注册表后继续
            device["cert_fingerprint"] = actual
            _persist_device(device.get("name") or "",
                            lambda e: e.__setitem__("cert_fingerprint", actual))
        return conn
    except Exception:
        try:
            conn.close()
        except Exception:
            pass
        raise


def request(device, method, path, payload=None, timeout=30, raw=False, trust=False):
    try:
        conn = _connect_tls(device, timeout, trust=trust)
    except TimeoutError as exc:
        raise RuntimeError("请求超时 %s:%d" % (device["ip"], device["port"])) from exc
    except (http.client.HTTPException, OSError) as exc:
        raise RuntimeError("无法连接 %s:%d（%s）" % (device["ip"], device["port"], exc)) from exc

    try:
        # 防重放头（契约 3.1）：每个请求独立的 nonce 与当前时间戳
        headers = {
            "X-Auth-Token": device["token"],
            "X-Timestamp": str(int(time.time())),
            "X-Nonce": uuid.uuid4().hex,
        }
        data = None
        if payload is not None:
            data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            headers["Content-Type"] = "application/json"
        conn.request(method, path, body=data, headers=headers)
        resp = conn.getresponse()
        body = resp.read()
        status = resp.status
    except TimeoutError as exc:
        raise RuntimeError("请求超时 %s:%d" % (device["ip"], device["port"])) from exc
    except (http.client.HTTPException, OSError) as exc:
        raise RuntimeError("无法连接 %s:%d（%s）" % (device["ip"], device["port"], exc)) from exc
    finally:
        try:
            conn.close()
        except Exception:
            pass

    if status >= 400:
        try:
            err = json.loads(body.decode("utf-8")).get("error", {})
        except Exception:
            err = {}
        if err:
            raise RuntimeError("%s: %s" % (err.get("code"), err.get("message")))
        raise RuntimeError("HTTP %d %s" % (status, body[:200]))

    if raw:
        return body
    parsed = json.loads(body.decode("utf-8"))
    if not parsed.get("ok"):
        err = parsed.get("error", {})
        raise RuntimeError("%s: %s" % (err.get("code"), err.get("message")))
    return parsed["data"]


def probe(device, timeout=2.0, trust=False):
    try:
        request(device, "GET", "/v1/health", timeout=timeout, trust=trust)
        return True
    except RuntimeError as exc:
        if str(exc).startswith("TOFU"):
            raise            # 指纹校验失败必须显式暴露，不能伪装成“离线”
        return False
    except Exception:
        return False


def rediscover(device):
    """地址漂移时按主机名重新定位。"""
    hostname = (device.get("info") or {}).get("hostname")
    if not hostname:
        return None
    result = discover.scan()
    for found in result["devices"]:
        if found.get("hostname") and found["hostname"].lower() == hostname.lower():
            return found["ip"]
    return None


def resolve(registry, name, trust=False):
    devices = registry["devices"]
    if name in devices:
        device = devices[name]
        if probe(device, trust=trust):
            device["last_seen"] = time.time()
            return device
        new_ip = rediscover(device)
        if new_ip and new_ip != device["ip"]:
            print("地址漂移：%s %s -> %s" % (name, device["ip"], new_ip))
            device["ip"] = new_ip
            device["last_seen"] = time.time()

            def apply_drift(entry):
                entry["ip"] = new_ip
                entry["last_seen"] = device["last_seen"]

            _persist_device(name, apply_drift)
            if probe(device, trust=trust):
                return device
        raise SystemExit("设备 %s 离线（%s）" % (name, device["ip"]))

    for device in devices.values():
        if device["ip"] == name:
            return device
    raise SystemExit("未注册的设备：%s\n先执行：python xd.py add <IP> --token <令牌>" % name)


# --------------------------------------------------------------------------
# 输出
# --------------------------------------------------------------------------

def dump(data):
    print(json.dumps(data, ensure_ascii=False, indent=2))


def human_size(size):
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return "%.0f%s" % (size, unit) if unit == "B" else "%.1f%s" % (size, unit)
        size /= 1024.0
    return str(size)


def _trust(args):
    return bool(getattr(args, "trust", False))


def _truncate(text, width):
    return text if len(text) <= width else text[:width - 1] + "…"


# --------------------------------------------------------------------------
# 审计辅助（契约 8.4）
# --------------------------------------------------------------------------

TIME_FORMATS = ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d")


def parse_time_arg(value):
    """--since/--until：Unix 秒或本地时间字符串 → Unix 秒。"""
    text = str(value).strip()
    if re.fullmatch(r"[+-]?\d+(\.\d+)?", text):
        return float(text)
    for fmt in TIME_FORMATS:
        try:
            return time.mktime(time.strptime(text, fmt))
        except ValueError:
            continue
    raise SystemExit("无法解析时间参数：%s（支持 Unix 秒或 YYYY-MM-DD[ HH:MM[:SS]]）" % value)


def _entry_time(entry):
    try:
        return time.strftime("%m-%d %H:%M:%S", time.localtime(float(entry.get("ts"))))
    except Exception:
        return str(entry.get("time") or "-")


def cmd_audit(args, registry):
    device = resolve(registry, args.name, trust=_trust(args))
    params = {}
    if getattr(args, "identity", None):
        params["identity"] = args.identity
    if getattr(args, "since", None):
        params["since"] = parse_time_arg(args.since)
    if getattr(args, "until", None):
        params["until"] = parse_time_arg(args.until)
    if getattr(args, "limit", None) is not None:
        params["limit"] = int(args.limit)
    query = urllib.parse.urlencode(params)
    data = request(device, "GET", "/v1/audit" + ("?" + query if query else ""),
                   timeout=30, trust=_trust(args))
    entries = data.get("entries", []) if isinstance(data, dict) else []

    if args.action == "export":
        out = args.out or ("audit_%s_%s.json" % (args.name, time.strftime("%H%M%S")))
        Path(out).write_text(json.dumps(entries, ensure_ascii=False, indent=2),
                             encoding="utf-8")
        print("已导出 %d 条审计 -> %s" % (len(entries), out))
        return

    if args.json:
        dump(data)
        return
    print("%-17s %-10s %-26s %-40s %s" % ("时间", "身份", "动作", "目标", "结果"))
    print("-" * 104)
    for entry in entries:
        result_text = "%s" % entry.get("result")
        if entry.get("code"):
            result_text += " %s" % entry.get("code")
        print("%-17s %-10s %-26s %-40s %s" % (
            _entry_time(entry),
            _truncate(str(entry.get("identity") or "-"), 10),
            _truncate(str(entry.get("action") or "-"), 26),
            _truncate(str(entry.get("target") or "-"), 40),
            result_text))
    print("-" * 104)
    print("共 %d 条" % len(entries))


# --------------------------------------------------------------------------
# 命令实现
# --------------------------------------------------------------------------

def cmd_discover(args, registry):
    result = discover.scan(args.cidr, args.timeout)
    if args.json:
        dump(result)
        return
    known = {(d["ip"], d["port"]) for d in registry["devices"].values()}
    print("本机 %s    网段 %s" % (result["self_ip"], result["network"]))
    print("-" * 74)
    print("%-16s %-18s %-18s %s" % ("IP", "MAC", "主机名", "状态"))
    print("-" * 74)
    for device in result["devices"]:
        state = "已注册" if (device["ip"], 8788) in known else ""
        print("%-16s %-18s %-18s %s" % (
            device["ip"], device["mac"] or "-", device["hostname"] or "-", state))
    print("-" * 74)
    print("共 %d 台在线" % len(result["devices"]))


def cmd_add(args, registry):
    device = {
        "name": args.name or "",
        "ip": args.ip,
        "port": args.port,
        "token": args.token,
        "identity": args.identity or "default",
        "cert_fingerprint": "",
        "added_at": time.time(),
        "last_seen": None,
        "info": {},
    }
    # add 属显式注册：总是写入（或覆盖）当次连接的指纹（契约 4.3.4），等价 trust
    info = request(device, "GET", "/v1/info", timeout=8, trust=True)
    device["info"] = info
    device["last_seen"] = time.time()
    name = args.name or info["hostname"]
    device["name"] = name
    registry["devices"][name] = device

    def fn(reg):
        reg["devices"][name] = device

    registry_update(fn)

    print("已注册 %s -> %s:%d" % (name, device["ip"], device["port"]))
    print("  主机名 : %s" % info["hostname"])
    print("  系统   : %s" % info["os"])
    print("  交互   : %s    锁屏: %s    提权: %s" % (
        "是" if info["interactive"] else "否",
        "是" if info["locked"] else "否",
        "是" if info["elevated"] else "否"))
    print("  身份   : %s    指纹: %s" % (device.get("identity") or "default",
                                       device.get("cert_fingerprint") or "-"))


def cmd_list(args, registry):
    devices = registry["devices"]
    if not devices:
        print("还没有注册任何设备。执行 python xd.py discover 查看局域网。")
        return
    if args.json:
        dump(devices)
        return
    print("%-16s %-16s %-6s %-20s %s" % ("名称", "地址", "端口", "主机名", "最近在线"))
    print("-" * 82)
    for device in devices.values():
        seen = device.get("last_seen")
        seen_text = time.strftime("%m-%d %H:%M", time.localtime(seen)) if seen else "-"
        print("%-16s %-16s %-6d %-20s %s" % (
            device["name"], device["ip"], device["port"],
            (device.get("info") or {}).get("hostname", "-"), seen_text))


def cmd_rm(args, registry):
    if args.name not in registry["devices"]:
        raise SystemExit("没有这个设备：%s" % args.name)
    registry["devices"].pop(args.name)

    def fn(reg):
        reg["devices"].pop(args.name, None)

    registry_update(fn)
    print("已移除 %s" % args.name)


def cmd_ping(args, registry):
    device = resolve(registry, args.name, trust=_trust(args))
    started = time.time()
    request(device, "GET", "/v1/health", timeout=5, trust=_trust(args))
    print("在线  往返 %.0f ms" % ((time.time() - started) * 1000))


def cmd_info(args, registry):
    device = resolve(registry, args.name, trust=_trust(args))
    info = request(device, "GET", "/v1/info", trust=_trust(args))
    device["info"] = info
    name = device.get("name") or ""
    seen = device.get("last_seen")

    def fn(entry):
        entry["info"] = info
        if seen:
            entry["last_seen"] = seen

    _persist_device(name, fn)
    if args.json:
        dump(info)
        return
    print("主机      : %s" % info["hostname"])
    print("用户      : %s" % info["user"])
    print("系统      : %s" % info["os"])
    print("Python    : %s (%s)" % (info["python"], info["arch"]))
    print("执行器    : v%s  已运行 %ss" % (info["node_version"], info["uptime"]))
    print("交互会话  : %s" % ("是" if info["interactive"] else "否"))
    print("锁屏      : %s" % ("是" if info["locked"] else "否"))
    print("提权      : %s" % ("是" if info["elevated"] else "否"))
    print("DPI       : %s  系统 %d" % (info["dpi_awareness"], info["system_dpi"]))
    screen = info["virtual_screen"]
    print("虚拟桌面  : %dx%d @ (%d,%d)" % (
        screen["width"], screen["height"], screen["left"], screen["top"]))
    for index, monitor in enumerate(info["monitors"]):
        print("显示器 %d  : %dx%d @ (%d,%d)%s" % (
            index, monitor["width"], monitor["height"], monitor["left"], monitor["top"],
            "  主屏" if monitor["primary"] else ""))
    if info["locked"]:
        print("\n注意：目标机处于锁屏状态，截屏和键鼠注入都不可用。")
    if not info["interactive"]:
        print("\n注意：目标机不在交互式桌面会话，GUI 能力不可用。")


def cmd_exec(args, registry):
    device = resolve(registry, args.name, trust=_trust(args))
    command = " ".join(args.command)
    if args.detach:
        data = request(device, "POST", "/v1/exec",
                       {"cmd": command, "shell": args.shell, "cwd": args.cwd,
                        "detach": True}, timeout=30, trust=_trust(args))
        print("已在后台启动，PID %s" % data.get("pid"))
        return
    data = request(device, "POST", "/v1/exec",
                   {"cmd": command, "shell": args.shell, "cwd": args.cwd,
                    "timeout": args.timeout},
                   timeout=args.timeout + 15, trust=_trust(args))
    job = request(device, "GET",
                  "/v1/job/%s?wait=%d" % (data["job_id"], args.timeout + 5),
                  timeout=args.timeout + 20, trust=_trust(args))
    if args.json:
        dump(job)
        return
    if job.get("stdout"):
        sys.stdout.write(job["stdout"])
        if not job["stdout"].endswith("\n"):
            sys.stdout.write("\n")
    if job.get("stderr"):
        sys.stderr.write(job["stderr"])
        if not job["stderr"].endswith("\n"):
            sys.stderr.write("\n")
    print("-- 退出码 %s  耗时 %ss  状态 %s" % (
        job.get("exit_code"), job.get("duration"), job.get("status")))


def cmd_shot(args, registry):
    device = resolve(registry, args.name, trust=_trust(args))
    query = urllib.parse.urlencode({"monitor": args.monitor,
                                    "max_width": args.max_width})
    png = request(device, "GET", "/v1/screen?" + query, timeout=90, raw=True,
                  trust=_trust(args))
    output = args.output or "shot_%s_%s.png" % (
        args.name, time.strftime("%H%M%S"))
    Path(output).write_bytes(png)
    print("已保存 %s（%s）" % (output, human_size(len(png))))


def send_input(args, registry, actions):
    device = resolve(registry, args.name, trust=_trust(args))
    data = request(device, "POST", "/v1/input", {"actions": actions},
                   trust=_trust(args))
    if args.json:
        dump(data)
        return
    if data.get("locked"):
        raise SystemExit("目标机锁屏，输入未生效")
    if not data.get("interactive"):
        raise SystemExit("目标机不在交互式桌面会话，输入未生效")
    print("已发送 %d 个动作" % len(actions))


def cmd_click(args, registry):
    send_input(args, registry, [{
        "type": "doubleclick" if args.double else "click",
        "x": args.x, "y": args.y, "button": args.button,
    }])


def cmd_move(args, registry):
    send_input(args, registry, [{"type": "move", "x": args.x, "y": args.y}])


def cmd_type(args, registry):
    send_input(args, registry, [{"type": "type", "text": args.text}])


def cmd_key(args, registry):
    send_input(args, registry, [{"type": "key", "key": args.combo}])


def cmd_ls(args, registry):
    device = resolve(registry, args.name, trust=_trust(args))
    data = request(device, "GET",
                   "/v1/fs/list?" + urllib.parse.urlencode({"path": args.path}),
                   trust=_trust(args))
    if args.json:
        dump(data)
        return
    for entry in data["entries"]:
        if entry["dir"]:
            print("%-12s %-8s %s" % ("<目录>", "-", entry["name"]))
        else:
            print("%-12s %-8s %s" % ("", human_size(entry["size"]), entry["name"]))
    print("-- 共 %d 项" % len(data["entries"]))


def cmd_cat(args, registry):
    device = resolve(registry, args.name, trust=_trust(args))
    data = request(device, "GET",
                   "/v1/fs/read?" + urllib.parse.urlencode({"path": args.path}),
                   trust=_trust(args))
    if data.get("encoding") is None:
        raise SystemExit("二进制文件，请用 get 下载：%s" % data["path"])
    sys.stdout.write(data["text"])
    if data["truncated"]:
        sys.stderr.write("\n...[文件超过读取上限，已截断]\n")


def cmd_put(args, registry):
    device = resolve(registry, args.name, trust=_trust(args))
    payload = Path(args.local).read_bytes()
    result = request(device, "POST", "/v1/fs/write", {
        "path": args.remote,
        "data_b64": base64.b64encode(payload).decode("ascii"),
    }, timeout=120, trust=_trust(args))
    print("已上传 %s -> %s（%s）" % (
        args.local, result["path"], human_size(result["written"])))


def cmd_get(args, registry):
    device = resolve(registry, args.name, trust=_trust(args))
    data = request(device, "GET", "/v1/fs/read?" + urllib.parse.urlencode(
        {"path": args.remote, "max": args.max}), timeout=180, trust=_trust(args))
    if "data_b64" in data:
        payload = base64.b64decode(data["data_b64"])
    else:
        payload = data["text"].encode("utf-8")
    Path(args.local).write_bytes(payload)
    print("已下载 %s -> %s（%s）" % (
        args.remote, args.local, human_size(len(payload))))


def cmd_push_node(args, registry):
    source = Path(args.file) if args.file else NODE_SOURCE
    if not source.exists():
        raise SystemExit("找不到执行器源码：%s" % source)
    payload = source.read_bytes()
    device = resolve(registry, args.name, trust=_trust(args))
    request(device, "POST", "/v1/self-update", {
        "source_b64": base64.b64encode(payload).decode("ascii"),
    }, timeout=30, trust=_trust(args))
    print("已推送 %s（%s），执行器正在重启..." % (source, human_size(len(payload))))
    for _ in range(15):
        time.sleep(1)
        if probe(device, trust=_trust(args)):
            version = request(device, "GET", "/v1/info", trust=_trust(args))["node_version"]
            print("重启完成，当前版本 v%s" % version)
            return
    raise SystemExit("执行器重启后无响应，请到目标机查看窗口输出")


# --------------------------------------------------------------------------
# 入口
# --------------------------------------------------------------------------

def build_parser():
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--json", action="store_true", help="输出 JSON")

    parser = argparse.ArgumentParser(prog="xd", description="CrossDevice 跨设备控制")
    parser.add_argument("--json", action="store_true", help=argparse.SUPPRESS)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("discover", parents=[common], help="扫描局域网")
    p.add_argument("--cidr", default=None)
    p.add_argument("--timeout", type=int, default=400)
    p.set_defaults(func=cmd_discover)

    p = sub.add_parser("add", parents=[common], help="注册设备")
    p.add_argument("ip")
    p.add_argument("--name", default=None)
    p.add_argument("--port", type=int, default=8788)
    p.add_argument("--token", required=True)
    p.add_argument("--identity", default="default", help="node 侧身份名（默认 default）")
    p.set_defaults(func=cmd_add)

    p = sub.add_parser("list", parents=[common], help="列出已注册设备")
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("rm", parents=[common], help="移除设备")
    p.add_argument("name")
    p.set_defaults(func=cmd_rm)

    p = sub.add_parser("ping", parents=[common], help="检测设备是否在线")
    p.add_argument("name")
    p.add_argument("--trust", action="store_true", help=TRUST_HELP)
    p.set_defaults(func=cmd_ping)

    p = sub.add_parser("info", parents=[common], help="查看设备环境")
    p.add_argument("name")
    p.add_argument("--trust", action="store_true", help=TRUST_HELP)
    p.set_defaults(func=cmd_info)

    p = sub.add_parser("exec", parents=[common], help="执行命令")
    p.add_argument("name")
    p.add_argument("command", nargs=argparse.REMAINDER)
    p.add_argument("--shell", default="cmd", choices=["cmd", "powershell", "none"])
    p.add_argument("--cwd", default=None)
    p.add_argument("--timeout", type=float, default=60)
    p.add_argument("--detach", action="store_true", help="启动 GUI 程序后立即返回")
    p.add_argument("--trust", action="store_true", help=TRUST_HELP)
    p.set_defaults(func=cmd_exec)

    p = sub.add_parser("shot", parents=[common], help="截屏")
    p.add_argument("name")
    p.add_argument("-o", "--output", default=None)
    p.add_argument("--monitor", type=int, default=-1)
    p.add_argument("--max-width", type=int, default=1600)
    p.add_argument("--trust", action="store_true", help=TRUST_HELP)
    p.set_defaults(func=cmd_shot)

    p = sub.add_parser("click", parents=[common], help="点击坐标")
    p.add_argument("name")
    p.add_argument("x", type=int)
    p.add_argument("y", type=int)
    p.add_argument("--button", default="left", choices=["left", "right", "middle"])
    p.add_argument("--double", action="store_true")
    p.add_argument("--trust", action="store_true", help=TRUST_HELP)
    p.set_defaults(func=cmd_click)

    p = sub.add_parser("move", parents=[common], help="移动鼠标")
    p.add_argument("name")
    p.add_argument("x", type=int)
    p.add_argument("y", type=int)
    p.add_argument("--trust", action="store_true", help=TRUST_HELP)
    p.set_defaults(func=cmd_move)

    p = sub.add_parser("type", parents=[common], help="输入文本")
    p.add_argument("name")
    p.add_argument("text")
    p.add_argument("--trust", action="store_true", help=TRUST_HELP)
    p.set_defaults(func=cmd_type)

    p = sub.add_parser("key", parents=[common], help="按键，如 enter / ctrl+a")
    p.add_argument("name")
    p.add_argument("combo")
    p.add_argument("--trust", action="store_true", help=TRUST_HELP)
    p.set_defaults(func=cmd_key)

    p = sub.add_parser("ls", parents=[common], help="列目录")
    p.add_argument("name")
    p.add_argument("path", nargs="?", default=".")
    p.add_argument("--trust", action="store_true", help=TRUST_HELP)
    p.set_defaults(func=cmd_ls)

    p = sub.add_parser("cat", parents=[common], help="查看文本文件")
    p.add_argument("name")
    p.add_argument("path")
    p.add_argument("--trust", action="store_true", help=TRUST_HELP)
    p.set_defaults(func=cmd_cat)

    p = sub.add_parser("put", parents=[common], help="上传文件")
    p.add_argument("name")
    p.add_argument("local")
    p.add_argument("remote")
    p.add_argument("--trust", action="store_true", help=TRUST_HELP)
    p.set_defaults(func=cmd_put)

    p = sub.add_parser("get", parents=[common], help="下载文件")
    p.add_argument("name")
    p.add_argument("remote")
    p.add_argument("local")
    p.add_argument("--max", type=int, default=64 * 1024 * 1024)
    p.add_argument("--trust", action="store_true", help=TRUST_HELP)
    p.set_defaults(func=cmd_get)

    p = sub.add_parser("push-node", parents=[common], help="推送并重启执行器")
    p.add_argument("name")
    p.add_argument("--file", default=None)
    p.add_argument("--trust", action="store_true", help=TRUST_HELP)
    p.set_defaults(func=cmd_push_node)

    p = sub.add_parser("audit", parents=[common], help="查询/导出节点审计日志")
    p.add_argument("action", choices=["ls", "export"], help="ls=表格查看；export=导出 JSON 文件")
    p.add_argument("name")
    p.add_argument("--identity", default=None, help="按身份名精确过滤")
    p.add_argument("--since", default=None, help="起始时间：Unix 秒或 YYYY-MM-DD[ HH:MM[:SS]]")
    p.add_argument("--until", default=None, help="结束时间：同上")
    p.add_argument("--limit", type=int, default=None, help="返回条数（1-1000，节点默认 200）")
    p.add_argument("--out", default=None, help="export 输出文件（默认 audit_<设备>_<HHMMSS>.json）")
    p.add_argument("--trust", action="store_true", help=TRUST_HELP)
    p.set_defaults(func=cmd_audit)

    return parser


def main():
    args = build_parser().parse_args()
    registry = load_registry()
    try:
        args.func(args, registry)
    except RuntimeError as exc:
        raise SystemExit(str(exc))


if __name__ == "__main__":
    main()
