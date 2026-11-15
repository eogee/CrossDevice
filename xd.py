#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CrossDevice CLI —— 本机侧入口，不监听任何端口。

S1 安全基线改造（唯一行为依据 docs/接口契约.md）：
  - 传输层 HTTPS（TLS 1.3，自签证书 + TOFU 指纹固定，契约第 4 章）；
  - 每个请求携带防重放头 X-Timestamp / X-Nonce，每次请求独立 nonce（契约第 3 章）；
  - 注册表加固：msvcrt 文件锁 + 原子写，修改统一走 registry_update（契约 9.2）；
  - `add` 新增可选 --identity 身份名；设备类子命令新增可选 --trust 确认指纹变更；
  - 新增 `audit ls` / `audit export` 子命令（契约 8.4）。
S2 能力扩展（契约 V1.2，§13/§14/§17/§18）：
  - `put`/`get` 升级为流式协议：4MB 分块 begin/chunk/commit 上传（断点续传）与
    /v1/fs/download 分块下载（本地断点文件 <local>.crosspart，Range 续拉），
    取消 64MB 上限；专用流式传输层（复用 _connect_tls 的 TOFU 校验，不走 request()）；
  - 新增子命令：`wheel` / `task ls` / `task show` / `del`（文件删除，需 --yes，
    偏差 6）/ `mkdir` / `mv`；
  - `add` 增强：--port 默认 51888（偏差 7）、条目记录 mac/ips、命名冲突自动后缀
    （未指定 --name 时）或报错（显式 --name 时）；
  - `resolve` 两级漂移兜底：条目 ips 逐试 → 主机名重扫 → MAC 兜底（共用一次扫描，
    契约 17.4），一切注册表写路径经 registry_update。
S3 韧性与并发（契约 V1.3，§19/§20/§21/§22）：
  - `push-node` 升级为签名推送：条目无 hmac_key 时先调 /v1/update/enroll 获取密钥
    （经 registry_update 写入条目），本地计算 sha256 + HMAC-SHA256 后推
    /v1/self-update {"source_b64","sha256","hmac"}；探活发现版本回退或
    rollback.flag 存在时输出回滚提示（契约 20.5）。对旧 node（< V1.3）：enroll
    端点不存在 → 404 报错退出；契约 §11 既定：V1.3 起 self-update 缺签名参数
    → 400 UPDATE_REJECTED（E-02 唯一兼容例外，偏差 9）。
  - 新增 `pool`：绑定 UDP 51889 接收发现广播（限频去重、30 秒离线判定），
    接收路径执行端口同步（完整 probe 信任链 + 60 秒冷却，绝不自动 add，
    契约 19.2/19.4）；
  - 新增 `release`（释放输入租约）与输入类子命令可选 `--take`（显式抢占，
    契约 21.3）；
  - 新增 `elevate`（高权限驻留计划任务安装/移除，契约 22）；
  - 注册表条目写回补齐 `hmac_key`（S3 第五键，契约 9.2）；
  - request() 新增可选 extra_headers 参数（既有调用不受影响）。
M6 攒批（B17 宏录制与回放，D9/D30，契约 V1.7 §11 兼容清单增量，协议零变更）：
  - 新增 `macro rec` / `macro run` 子命令：宏 = 白名单动作序列 JSON（与 /v1/input
    actions 同构），仅在控制端本地解析与严格校验（D30 红线：不支持循环/条件/
    变量/表达式/外部命令，不允许任意脚本；加载校验失败即整体拒绝）；宏文件格式
    规范正文见 README"宏（macro rec/run）"节；
  - 回放：按 delay 分段经既有 /v1/input 发送，全程持输入租约（首段 acquire、
    其后无头=隐式续期，§21.2），Ctrl+C 或异常中断即 best-effort release
    （FR-06），正常结束亦释放；不新增端点、不改 node、不改包络；
  - 录制：Windows 低级键鼠钩子（WH_MOUSE_LL/WH_KEYBOARD_LL，纯标准库 ctypes）
    捕获控制端本机操作（纯本地命令，不触网络、不写被控端），移动去抖/双击与
    打字聚合/间隔写 delay_ms，产物经同一套加载校验后写盘。
既有子命令的输出格式与语义保持不变（E-02，兼容清单第 11 章）。
"""

import argparse
import base64
import ctypes
import hashlib
import hmac
import http.client
import json
import msvcrt
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import time
import urllib.parse
import uuid
from ctypes import wintypes
from pathlib import Path

import discover

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data"                 # 模块级常量保留可替换性；实际读写一律以 REGISTRY 为准
REGISTRY = DATA / "devices.json"
NODE_SOURCE = ROOT / "node" / "node.py"

LOCK_TIMEOUT = 5.0                   # 注册表文件锁等待上限（秒），契约 9.2
TRUST_HELP = "确认并接受服务器证书指纹变更（TOFU）"

# 流式传输参数（契约 §13：4MB 分块上传；本地读写/MD5 计算缓冲 1MB，不整载文件）
CHUNK_SIZE = 4 * 1024 * 1024
IO_BUFFER = 1024 * 1024


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
    """写回前补齐新增键（契约 9.2 / 17.2 / 20.1：旧条目任何写回操作补齐
    identity / cert_fingerprint（S1）与 mac / ips（S2）与 hmac_key（S3））。"""
    devices = registry.get("devices")
    if not isinstance(devices, dict):
        registry["devices"] = {}
        return registry
    for name, device in devices.items():
        if isinstance(device, dict):
            device.setdefault("name", name)
            device.setdefault("identity", "default")
            device.setdefault("cert_fingerprint", "")
            device.setdefault("mac", "")          # S2：MAC，缺省空（契约 9.2）
            device.setdefault("ips", [])          # S2：全部私网 IPv4 列表
            device.setdefault("hmac_key", "")     # S3：更新签名密钥，缺省空（契约 9.2/§20.1）
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


def request(device, method, path, payload=None, timeout=30, raw=False, trust=False,
            extra_headers=None):
    """业务请求（HTTPS + TOFU + 防重放，契约 3.1/4.3）。

    extra_headers：可选的额外请求头（S3 输入租约 X-Input-Lease 等），
    与基础头合并后发送（可覆盖同名基础头）；缺省 None 时行为与既有调用完全一致。
    """
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
        if extra_headers:
            headers.update(extra_headers)
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


# --------------------------------------------------------------------------
# 流式传输层（契约 §13 / §18.1：put/get 大文件分块读写，不得走 request() 全量读响应体）
# --------------------------------------------------------------------------

def _stream_open(device, method, path, body=None, headers=None, timeout=60, trust=False):
    """流式传输底层：建立 TLS 连接（复用 _connect_tls 的 TOFU 指纹校验，规则不变），
    发送请求（body 为调用方按分块构造的请求体字节，不整载文件）。

    返回 (conn, resp)：调用方负责分块读 resp（可取 X-File-Size / X-File-MD5 /
    Content-Range 等响应头）并 finally 关闭 conn。
    每个请求独立生成 nonce 与当前时间戳（契约 3.3）。
    """
    try:
        conn = _connect_tls(device, timeout, trust=trust)
    except TimeoutError as exc:
        raise RuntimeError("请求超时 %s:%d" % (device["ip"], device["port"])) from exc
    except (http.client.HTTPException, OSError) as exc:
        raise RuntimeError("无法连接 %s:%d（%s）" % (device["ip"], device["port"], exc)) from exc
    try:
        hdrs = {
            "X-Auth-Token": device["token"],
            "X-Timestamp": str(int(time.time())),
            "X-Nonce": uuid.uuid4().hex,
        }
        if body is not None:
            hdrs["Content-Type"] = "application/json"
        if headers:
            hdrs.update(headers)
        conn.request(method, path, body=body, headers=hdrs)
        resp = conn.getresponse()
        return conn, resp
    except TimeoutError as exc:
        try:
            conn.close()
        except Exception:
            pass
        raise RuntimeError("请求超时 %s:%d" % (device["ip"], device["port"])) from exc
    except (http.client.HTTPException, OSError) as exc:
        try:
            conn.close()
        except Exception:
            pass
        raise RuntimeError("无法连接 %s:%d（%s）" % (device["ip"], device["port"], exc)) from exc
    except Exception:
        try:
            conn.close()
        except Exception:
            pass
        raise


def _stream_error(resp, body):
    """流式响应失败时按包络解出错误码（契约 1.3：失败一律 JSON 包络）。"""
    try:
        err = json.loads(body.decode("utf-8")).get("error", {})
    except Exception:
        err = {}
    if err:
        raise RuntimeError("%s: %s" % (err.get("code"), err.get("message")))
    raise RuntimeError("HTTP %d %s" % (resp.status, body[:200]))


def _stream_json(device, method, path, payload=None, timeout=60, trust=False):
    """流式传输族的 JSON 端点调用（upload begin/chunk/commit/abort 等）：
    走 _stream_open 建连，响应体较小整体读入后按包络解包。"""
    body = None
    if payload is not None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    conn, resp = _stream_open(device, method, path, body=body, timeout=timeout, trust=trust)
    try:
        data = resp.read()
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
        _stream_error(resp, data)
    parsed = json.loads(data.decode("utf-8"))
    if not parsed.get("ok"):
        err = parsed.get("error", {})
        raise RuntimeError("%s: %s" % (err.get("code"), err.get("message")))
    return parsed["data"]


def _file_md5_and_size(path):
    """分块流式计算文件 MD5 与大小（1MB 缓冲，不整载，契约 §13.1 同口径）。"""
    digest = hashlib.md5()
    size = 0
    with open(path, "rb") as fh:
        while True:
            block = fh.read(IO_BUFFER)
            if not block:
                break
            digest.update(block)
            size += len(block)
    return digest.hexdigest(), size


def _download_url(remote):
    return "/v1/fs/download?" + urllib.parse.urlencode({"path": remote})


def _download_probe(device, remote, trust=False):
    """下载前探测远端总长与 MD5（断点续传判定用）。

    契约 §13.2 仅支持闭区间 Range，故以 bytes=0-0 取 206 响应头
    X-File-Size / X-File-MD5；服务端忽略 Range 回 200 时丢弃响应体后同样返回头信息。
    """
    conn, resp = _stream_open(device, "GET", _download_url(remote),
                              headers={"Range": "bytes=0-0"}, timeout=30, trust=trust)
    try:
        if resp.status >= 400:
            body = resp.read()
            _stream_error(resp, body)
        size_text = resp.getheader("X-File-Size")
        md5 = resp.getheader("X-File-MD5") or None
        total = int(size_text) if size_text and size_text.isdigit() else None
        if resp.status != 206:
            # 服务端不支持 Range（200 全量）：丢弃响应体，头信息仍有效
            while True:
                block = resp.read(IO_BUFFER)
                if not block:
                    break
        return total, md5
    finally:
        try:
            conn.close()
        except Exception:
            pass


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


def _switch_device_ip(name, device, new_ip):
    """漂移命中：切换内存地址并经 registry_update 落盘（契约 17.4，
    一切注册表写路径必须经由 registry_update，禁止绕过）。"""
    device["ip"] = new_ip
    device["last_seen"] = time.time()

    def apply_drift(entry):
        entry["ip"] = new_ip
        entry["last_seen"] = device["last_seen"]

    _persist_device(name, apply_drift)
    return device


def resolve(registry, name, trust=False):
    """解析设备并确保可达（契约 17.4 两级漂移兜底）：

    ① 现地址（ip:port）探测成功 → 返回（行为同现状，不写盘）；
    ② 失败 → 逐个尝试条目 ips 中其余地址，首个成功者经 registry_update 落盘切换；
    ③ 仍失败 → 主机名重扫（discover.scan，大小写不敏感匹配 info.hostname）；
    ④ 仍失败 → MAC 兜底（条目 mac 非空时在同一扫描结果中匹配）；
       主机名与 MAC 兜底共用同一次扫描结果；全部失败维持现有离线报错。
    """
    devices = registry["devices"]
    if name in devices:
        device = devices[name]
        if probe(device, trust=trust):
            device["last_seen"] = time.time()
            return device

        # ② 条目 ips 中其余地址逐个尝试
        for ip in device.get("ips") or []:
            if not ip or ip == device["ip"]:
                continue
            trial = dict(device, ip=ip)
            if probe(trial, trust=trust):
                print("地址漂移：%s %s -> %s" % (name, device["ip"], ip))
                return _switch_device_ip(name, device, ip)

        # ③④ 主机名重扫 + MAC 兜底共用一次扫描（扫描失败视为无候选）
        scan_result = {"devices": []}
        scanned = False
        hostname = (device.get("info") or {}).get("hostname")
        if hostname:
            try:
                scan_result = discover.scan()
            except Exception:
                scan_result = {"devices": []}
            scanned = True
            for found in scan_result.get("devices", []):
                found_ip = found.get("ip")
                if (found.get("hostname") or "").lower() == hostname.lower() \
                        and found_ip and found_ip != device["ip"]:
                    trial = dict(device, ip=found_ip)
                    if probe(trial, trust=trust):
                        print("地址漂移：%s %s -> %s" % (name, device["ip"], found_ip))
                        return _switch_device_ip(name, device, found_ip)

        mac = (device.get("mac") or "").strip().upper()
        if mac:
            if not scanned:
                try:
                    scan_result = discover.scan()
                except Exception:
                    scan_result = {"devices": []}
            for found in scan_result.get("devices", []):
                found_ip = found.get("ip")
                if ((found.get("mac") or "").strip().upper() == mac
                        and found_ip and found_ip != device["ip"]):
                    trial = dict(device, ip=found_ip)
                    if probe(trial, trust=trust):
                        print("地址漂移：%s %s -> %s" % (name, device["ip"], found_ip))
                        return _switch_device_ip(name, device, found_ip)

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


def _transient_replace_error(exc):
    """识别 Windows os.replace 的瞬时拒绝访问（目标文件被实时扫描等短暂占用）。

    服务端 commit 落盘与本地断点转正都可能遇到 WinError 5；与"MD5 不一致"
    等永久错误区分开，瞬时错误允许短重试。
    """
    text = str(exc)
    return "拒绝访问" in text or "WinError 5" in text or "落盘失败" in text


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
    # 显式 --name 冲突 → 报错退出（契约 17.3：显式意图优先，不静默改名）
    if args.name and args.name in registry["devices"]:
        raise SystemExit("设备名称已存在：%s（显式命名的冲突不做自动改名，"
                         "请换名或先 rm 旧条目）" % args.name)
    device = {
        "name": args.name or "",
        "ip": args.ip,
        "port": args.port,
        "token": args.token,
        "identity": args.identity or "default",
        "cert_fingerprint": "",
        "mac": discover.arp_table().get(args.ip, ""),   # S2：ARP 表采集 MAC（只读，契约 17.3）
        "ips": [],
        "added_at": time.time(),
        "last_seen": None,
        "info": {},
    }
    # add 属显式注册：总是写入（或覆盖）当次连接的指纹（契约 4.3.4），等价 trust
    info = request(device, "GET", "/v1/info", timeout=8, trust=True)
    device["info"] = info
    device["last_seen"] = time.time()
    # S2：条目记录 ips（取 /v1/info 的 addresses，契约 17.3；旧 node 无该字段则留空）
    device["ips"] = [a for a in (info.get("addresses") or [])
                     if isinstance(a, str) and a]
    base = args.name or info.get("hostname") or args.ip
    # 未指定 --name（取 hostname）且名称已存在 → 自动后缀 -2、-3…（契约 17.3）
    name = base
    if not args.name:
        suffix = 2
        while name in registry["devices"]:
            name = "%s-%d" % (base, suffix)
            suffix += 1
    device["name"] = name

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
    # S3 输入租约（契约 §21.3）：输入类子命令可选 --take → 显式抢占头
    extra = None
    if getattr(args, "take", False):
        extra = {"X-Input-Lease": "take"}
    data = request(device, "POST", "/v1/input", {"actions": actions},
                   trust=_trust(args), extra_headers=extra)
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
    """流式上传（契约 §18.1 / §13.3）：begin → 4MB 分块 chunk → commit。

    - begin 返回 resume_offset > 0 时跳过已接收块续传（不重传，断点续传）；
    - --fresh：先 begin 拿到既有会话 id（若复用）→ abort 它 → 重新 begin 全新上传；
    - commit 返回的 md5 与本地不一致 → 报错；
    - commit 落盘遇到 Windows 瞬时占用（WinError 5）→ 重新 begin 后重试
      （服务端若已清理会话则按 resume_offset=0 重传，断点续传语义天然兼容）。
    """
    device = resolve(registry, args.name, trust=_trust(args))
    local = Path(args.local)
    if not local.is_file():
        raise SystemExit("本地文件不存在：%s" % local)
    md5, size = _file_md5_and_size(local)

    begin_payload = {"path": args.remote, "size": size, "md5": md5}
    fresh_pending = args.fresh            # 仅首轮执行 abort（重试轮不再 abort）
    attempt = 0
    while True:
        attempt += 1
        data = _stream_json(device, "POST", "/v1/fs/upload/begin", begin_payload,
                            timeout=30, trust=_trust(args))
        if fresh_pending:
            fresh_pending = False
            # 全新上传：终止既有会话（含服务端临时文件清理）后重新 begin
            _stream_json(device, "POST", "/v1/fs/upload/abort",
                         {"upload_id": data["upload_id"]}, timeout=30, trust=_trust(args))
            data = _stream_json(device, "POST", "/v1/fs/upload/begin", begin_payload,
                                timeout=30, trust=_trust(args))
        upload_id = data["upload_id"]
        chunk_size = int(data.get("chunk_size") or CHUNK_SIZE)
        offset = int(data.get("resume_offset") or 0)

        with open(local, "rb") as fh:
            fh.seek(offset)               # 跳过已接收部分（断点续传）
            while offset < size:
                block = fh.read(chunk_size)
                if not block:
                    break
                result = _stream_json(device, "POST", "/v1/fs/upload/chunk",
                                      {"upload_id": upload_id, "offset": offset,
                                       "data_b64": base64.b64encode(block).decode("ascii")},
                                      timeout=120, trust=_trust(args))
                offset = int(result.get("next_offset") or (offset + len(block)))

        try:
            result = _stream_json(device, "POST", "/v1/fs/upload/commit",
                                  {"upload_id": upload_id}, timeout=60, trust=_trust(args))
            break
        except RuntimeError as exc:
            if attempt >= 3 or not _transient_replace_error(exc):
                raise
            print("服务端落盘被瞬时占用，重新 begin 后重试（%d/3）..." % attempt)
            time.sleep(0.5)
    if (result.get("md5") or "").lower() != md5:
        raise RuntimeError("上传校验失败：服务端 MD5 与本地不一致（本地 %s / 远端 %s）"
                           % (md5, result.get("md5")))
    print("已上传 %s -> %s（%s）" % (
        args.local, result["path"], human_size(result.get("size") or size)))


def cmd_get(args, registry):
    """流式下载（契约 §18.1 / §13.2）：改用 /v1/fs/download 分块拉取。

    - 本地断点文件 <local>.crosspart：存在且 < 总长 → 以 Range 续拉并追加；
      ≥ 总长（异常残留）→ 丢弃重来；
    - 完成且 MD5 校验一致后 os.replace 为目标文件；校验不一致报错并保留断点文件；
    - --fresh 删除断点重新下载；--max 参数保留但不再使用（静默忽略）；取消 64MB 上限。
    """
    device = resolve(registry, args.name, trust=_trust(args))
    local = Path(args.local)
    if local.parent and not local.parent.exists():
        raise SystemExit("目标目录不存在：%s" % local.parent)
    part = Path(str(local) + ".crosspart")      # 本地断点文件
    if args.fresh and part.exists():
        try:
            part.unlink()
        except OSError:
            pass

    total = None                                # 远端文件总字节数（来自 X-File-Size）
    remote_md5 = None
    offset = 0
    if part.exists():
        offset = part.stat().st_size
        # 先探测总长，判定断点是否可用（契约 §13.2 仅支持闭区间 Range）
        probed_total, probed_md5 = _download_probe(device, args.remote, trust=_trust(args))
        if probed_total is None:
            offset = 0                          # 无法确定总长：断点不可靠，全量重来
        elif offset >= probed_total:
            offset = 0                          # 断点 ≥ 总长（异常残留）→ 丢弃重来
        else:
            total, remote_md5 = probed_total, probed_md5

    headers = None
    if offset > 0:
        # 断点续拉：闭区间 Range（bytes=<已收>-<总长-1>），追加写入
        headers = {"Range": "bytes=%d-%d" % (offset, total - 1)}
    conn, resp = _stream_open(device, "GET", _download_url(args.remote),
                              headers=headers, timeout=60, trust=_trust(args))
    try:
        if resp.status >= 400:
            body = resp.read()
            _stream_error(resp, body)
        if resp.status == 200:
            # 全量响应（无断点或服务端忽略 Range）→ 断点作废，从头写
            offset = 0
        elif resp.status == 206:
            match = re.match(r"bytes\s+(\d+)-(\d+)/(\d+)",
                             resp.getheader("Content-Range") or "")
            if not match or int(match.group(1)) != offset:
                raise RuntimeError("下载续传失败：Content-Range 与断点不符（%s）"
                                   % (resp.getheader("Content-Range") or "无"))
        else:
            body = resp.read()
            raise RuntimeError("HTTP %d（下载被拒绝）" % resp.status)
        size_text = resp.getheader("X-File-Size")
        if size_text and size_text.isdigit():
            total = int(size_text)
        remote_md5 = resp.getheader("X-File-MD5") or remote_md5
        received = offset
        with open(part, "ab" if offset else "wb") as fh:
            while True:
                block = resp.read(IO_BUFFER)
                if not block:
                    break
                fh.write(block)
                received += len(block)
    finally:
        try:
            conn.close()
        except Exception:
            pass

    if total is None:
        total = received                        # 服务端未带 X-File-Size（异常 node）→ 以实收为准
    if received != total:
        raise RuntimeError("下载不完整：%d/%d 字节（断点文件已保留，重新执行 get 可续传）"
                           % (received, total))
    actual_md5, _ = _file_md5_and_size(part)
    if remote_md5 and actual_md5.lower() != remote_md5.lower():
        raise RuntimeError("下载校验失败：MD5 与服务端不一致（断点文件已保留，"
                           "可加 --fresh 重新下载）")
    for attempt in range(3):
        try:
            os.replace(part, local)         # 断点文件转正为目标文件（同目录原子替换）
            break
        except PermissionError as exc:
            # 目标文件被实时扫描等短暂占用（WinError 5）→ 短重试
            if attempt == 2 or not _transient_replace_error(exc):
                raise
            time.sleep(0.5)
    print("已下载 %s -> %s（%s）" % (
        args.remote, args.local, human_size(total)))


def _version_tuple(text):
    """版本字符串 → 可比较整数元组（"0.4.1-c1" → (0, 4, 1, 1)），供回退判定。"""
    parts = re.findall(r"\d+", str(text or ""))
    return tuple(int(p) for p in parts) if parts else (0,)


def cmd_push_node(args, registry):
    """签名推送（契约 §20.5 / §6.8，V1.3 起 self-update 签名必填，偏差 9）：

    - 条目无 hmac_key → 先 POST /v1/update/enroll 获取密钥并经 registry_update
      写入条目（hmac_key 永不落审计/日志，契约 §20.1）；
    - 本地计算 sha256（64hex 小写）与 HMAC-SHA256(hmac_key, sha256) 后推
      /v1/self-update {"source_b64","sha256","hmac"}；
    - 推送后既有 15×1s 探活循环：新版本低于推送前 → 输出看门狗回滚提示；
      /v1/health 的 rollback_flag == true → 输出 rollback.flag 处置提示。
    - 对旧 node（< V1.3）既定行为：enroll 端点不存在 → 404 报错退出（契约 §11）。
    """
    source = Path(args.file) if args.file else NODE_SOURCE
    if not source.exists():
        raise SystemExit("找不到执行器源码：%s" % source)
    payload = source.read_bytes()
    device = resolve(registry, args.name, trust=_trust(args))
    name = device.get("name") or ""

    # §20.5：条目无 hmac_key → 先 enroll（重复调用 = 轮换，旧密钥随即失效）
    hmac_key = str(device.get("hmac_key") or "").strip()
    if not hmac_key:
        data = request(device, "POST", "/v1/update/enroll", {},
                       timeout=30, trust=_trust(args))
        hmac_key = str((data or {}).get("hmac_key") or "").strip()
        if not hmac_key:
            raise SystemExit("enroll 未返回更新签名密钥，无法签名推送")
        device["hmac_key"] = hmac_key

        def set_key(entry):
            entry["hmac_key"] = hmac_key

        _persist_device(name, set_key)      # 注册表写唯一入口（契约 9.2）
        print("已获取更新签名密钥（/v1/update/enroll）")

    sha256_hex = hashlib.sha256(payload).hexdigest()
    signature = hmac.new(hmac_key.encode("utf-8"), sha256_hex.encode("utf-8"),
                         hashlib.sha256).hexdigest()

    # 记录推送前版本（看门狗回滚判定基准：回滚后版本号会低于推送前）
    pre_version = None
    try:
        info = request(device, "GET", "/v1/info", timeout=8, trust=_trust(args))
        pre_version = str((info or {}).get("node_version") or "") or None
    except Exception:
        pre_version = None                  # 推送前不可达：跳过版本回退判定

    request(device, "POST", "/v1/self-update", {
        "source_b64": base64.b64encode(payload).decode("ascii"),
        "sha256": sha256_hex,
        "hmac": signature,
    }, timeout=30, trust=_trust(args))
    print("已推送 %s（%s），执行器正在重启..." % (source, human_size(len(payload))))
    for _ in range(15):
        time.sleep(1)
        if probe(device, trust=_trust(args)):
            info = request(device, "GET", "/v1/info", timeout=10, trust=_trust(args))
            version = str((info or {}).get("node_version") or "")
            # §20.5：版本恢复后低于推送前版本 → 更新已被看门狗回滚
            if pre_version and version \
                    and _version_tuple(version) < _version_tuple(pre_version):
                print("更新已被看门狗回滚（rollback.flag 已写入，请人工处置）")
            try:
                health = request(device, "GET", "/v1/health", timeout=10,
                                 trust=_trust(args))
                if isinstance(health, dict) and health.get("rollback_flag") is True:
                    print("检测到 rollback.flag（历史回滚未处置，请人工确认）")
            except Exception:
                pass                        # 旧 node 无 rollback_flag 字段，忽略
            print("重启完成，当前版本 v%s" % version)
            return
    raise SystemExit("执行器重启后无响应，请到目标机查看窗口输出")


# --------------------------------------------------------------------------
# S3 新增命令（契约 §19 设备池 / §21 输入租约 / §22 高权限驻留）
# --------------------------------------------------------------------------

POOL_PORT = 51889           # 发现广播 UDP 端口（契约 §19.1/§19.2，D28）
POOL_OFFLINE_SECS = 30      # 30 秒无帧判离线（D25）
POOL_RATE_SECS = 1.0        # (源IP, device_id) 每秒最多接受 1 帧（B31/D38）
POOL_SYNC_COOLDOWN = 60.0   # 端口同步每 (条目名, 帧端口) 组合冷却（§19.4 防抖）


def _pool_frame_valid(data):
    """广播报文校验（契约 §19.2）：≤512B、UTF-8 单行 JSON、magic=="XDCAST"、
    proto==1、device_id 为 1–12 位十六进制；非法一律静默丢弃（广播来源不可信，
    防日志洪泛）。合法返回解析后的 dict。"""
    if not data or len(data) > 512:
        return None
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if "\n" in text or "\r" in text:
        return None
    try:
        msg = json.loads(text)
    except ValueError:
        return None
    if not isinstance(msg, dict):
        return None
    if msg.get("magic") != "XDCAST" or msg.get("proto") != 1:
        return None
    device_id = msg.get("device_id")
    if not isinstance(device_id, str) \
            or not re.fullmatch(r"[0-9a-fA-F]{1,12}", device_id):
        return None
    return msg


def _pool_port_sync(msg, src_ip, cooldown):
    """端口同步（契约 §19.4，B29 后半收口 / D35）：

    触发条件（全部满足）：帧匹配注册表条目（优先 帧 device_id == 条目
    info.device_id 精确匹配；条目 info 无 device_id 时回退 hostname 大小写
    不敏感精确匹配）→ 帧 port ≠ 条目 port → 条目现地址（ip:port）探测失败。
    动作：向广播源 ip:port 发完整 probe（直接复用 request()：TLS + TOFU 指纹 +
    条目令牌 + 防重放全链）→ 成功且指纹一致 → 经 registry_update 更新
    port + last_seen；失败（含 TOFU 指纹不一致）不动。
    每 (条目名, 帧端口) 组合 60 秒冷却（无论成败）。绝不自动 add、
    绝不写注册表其他字段（D38 发现与授权分离）。
    """
    try:
        registry = load_registry()
    except Exception:
        return
    devices = registry.get("devices") or {}
    device_id = str(msg.get("device_id") or "").lower()
    hostname = str(msg.get("hostname") or "")
    matched_name = None
    for name, entry in devices.items():
        if not isinstance(entry, dict):
            continue
        entry_id = str((entry.get("info") or {}).get("device_id") or "").lower()
        if entry_id and entry_id == device_id:
            matched_name = name
            break
    if matched_name is None and hostname:
        # 回退仅对 info 无 device_id 的条目生效（精确匹配防同机多 node 撞车）
        for name, entry in devices.items():
            if not isinstance(entry, dict):
                continue
            info = entry.get("info") or {}
            if info.get("device_id"):
                continue
            entry_host = str(info.get("hostname") or "")
            if entry_host and entry_host.lower() == hostname.lower():
                matched_name = name
                break
    if matched_name is None:
        return
    entry = devices[matched_name]
    frame_port = msg.get("port")
    if not isinstance(frame_port, int) or isinstance(frame_port, bool) \
            or not 1 <= frame_port <= 65535:
        return
    if frame_port == entry.get("port"):
        return
    key = (matched_name, frame_port)
    now = time.time()
    if now - cooldown.get(key, 0.0) < POOL_SYNC_COOLDOWN:
        return
    cooldown[key] = now                       # 无论成败先记冷却（防抖，契约 §19.4）

    base = {
        "name": matched_name,
        "token": entry.get("token"),
        "identity": entry.get("identity") or "default",
        "cert_fingerprint": entry.get("cert_fingerprint") or "",
    }
    # 前置：条目现地址（ip:port）可达 → 不修改（避免同主机多 node 场景误写）
    current = dict(base, ip=entry.get("ip"), port=entry.get("port"))
    try:
        request(current, "GET", "/v1/health", timeout=3)
        return
    except Exception:
        pass
    # 向广播源 ip:帧端口 发完整 probe（TOFU 指纹不一致 → 异常 → 失败不动）
    trial = dict(base, ip=src_ip, port=frame_port)
    try:
        data = request(trial, "GET", "/v1/health", timeout=5)
        ok = isinstance(data, dict) and data.get("status") == "up"
    except Exception:
        ok = False
    if not ok:
        return

    def fn(reg):
        target = reg["devices"].get(matched_name)
        if isinstance(target, dict):
            target["port"] = frame_port
            target["last_seen"] = time.time()

    registry_update(fn)                       # 注册表写唯一入口（契约 9.2）
    print("端口同步：%s 端口 %s -> %d（经广播 probe 校正）"
          % (matched_name, entry.get("port"), frame_port))


def _pool_accept(pool, rate, cooldown, addr, data):
    """单帧处理：校验 → (源IP, device_id) 限频去重 → 刷新池 → 端口同步。"""
    msg = _pool_frame_valid(data)
    if msg is None:
        return
    src_ip = addr[0]
    device_id = msg["device_id"].lower()
    now = time.time()
    rate_key = (src_ip, device_id)
    if now - rate.get(rate_key, 0.0) < POOL_RATE_SECS:
        return                                # 限频：超出每秒 1 帧的部分丢弃（不计数）
    rate[rate_key] = now
    entry = pool.setdefault(device_id, {
        "ip": src_ip, "hostname": "", "port": 0, "version": "", "caps": [],
        "first_seen": now, "last_seen": now, "frames": 0,
    })
    entry["ip"] = src_ip                      # 池结构（契约 §19.2）：源 IP + 帧内容刷新
    entry["hostname"] = str(msg.get("hostname") or "")
    port = msg.get("port")
    if isinstance(port, int) and not isinstance(port, bool) and 1 <= port <= 65535:
        entry["port"] = port
    entry["version"] = str(msg.get("version") or "")
    caps = msg.get("caps")
    entry["caps"] = [str(c) for c in caps] if isinstance(caps, list) else []
    entry["last_seen"] = now
    entry["frames"] += 1                      # frames 计接受帧数
    _pool_port_sync(msg, src_ip, cooldown)


def _pool_online(entry):
    return (time.time() - entry.get("last_seen", 0)) <= POOL_OFFLINE_SECS


def _pool_hhmmss(value):
    try:
        return time.strftime("%H:%M:%S", time.localtime(float(value)))
    except Exception:
        return "-"


def _pool_render(pool, as_json):
    """设备池快照输出（契约 §19.2）：--json 输出快照 JSON（含在线状态字段）；
    否则打印表格（状态/device_id/源IP/端口/版本/主机名/帧数/首见/最近，
    now-last_seen > 30 秒标注"离线"）。不落盘、退出不改任何持久状态。"""
    now = time.time()
    snapshot = {}
    for device_id, entry in pool.items():
        item = dict(entry)
        item["online"] = (now - entry.get("last_seen", 0)) <= POOL_OFFLINE_SECS
        snapshot[device_id] = item
    if as_json:
        print(json.dumps({
            "ts": now,
            "count": len(snapshot),
            "online": sum(1 for v in snapshot.values() if v["online"]),
            "devices": snapshot,
        }, ensure_ascii=False, indent=2))
        return
    print("%-6s %-14s %-15s %-6s %-8s %-18s %-6s %-9s %-9s" % (
        "状态", "device_id", "源IP", "端口", "版本", "主机名", "帧数", "首见", "最近"))
    print("-" * 100)
    for device_id, item in sorted(snapshot.items()):
        print("%-6s %-14s %-15s %-6s %-8s %-18s %-6d %-9s %-9s" % (
            "在线" if item["online"] else "离线",
            _truncate(device_id, 14),
            _truncate(str(item["ip"] or "-"), 15),
            item["port"] or "-",
            _truncate(str(item["version"] or "-"), 8),
            _truncate(str(item["hostname"] or "-"), 18),
            item["frames"],
            _pool_hhmmss(item["first_seen"]),
            _pool_hhmmss(item["last_seen"])))
    print("-" * 100)
    print("共 %d 台（在线 %d）" % (
        len(snapshot), sum(1 for v in snapshot.values() if v["online"])))


def cmd_pool(args, registry):
    """设备池（契约 §19.2/§19.4）：仅本子命令期间绑定 UDP 51889 接收发现广播
    （SO_REUSEADDR；控制面仍零监听，D25）。设备池为内存结构（不落盘、不跨进程）；
    广播是未认证信息：不自动信任、不自动 add（唯一例外：§19.4 端口同步）。

    - 默认：持续监听并每 2 秒重印设备池表格（Ctrl+C 退出）；
    - --seconds N：采样 N 秒后输出一次快照退出（快照同样含离线标注）；
    - --json：输出快照 JSON（仅与 --seconds 搭配，持续模式忽略）。
    """
    seconds = getattr(args, "seconds", None)
    as_json = bool(getattr(args, "json", False)) and bool(seconds)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("", POOL_PORT))
    except OSError as exc:
        try:
            sock.close()
        except OSError:
            pass
        raise SystemExit("无法绑定 UDP %d（可能被其他程序占用）：%s" % (POOL_PORT, exc))
    sock.settimeout(0.4)
    pool, rate, cooldown = {}, {}, {}
    deadline = (time.time() + seconds) if seconds and seconds > 0 else None
    next_render = 0.0
    try:
        while True:
            if deadline is not None and time.time() >= deadline:
                break
            data = None
            try:
                data, addr = sock.recvfrom(2048)
            except socket.timeout:
                pass
            except OSError:
                pass
            if data:
                try:
                    _pool_accept(pool, rate, cooldown, addr, data)
                except Exception:
                    pass                      # 单帧处理异常不影响接收循环
            if deadline is None and time.time() >= next_render:
                _pool_render(pool, False)     # 持续模式每 2 秒重印表格
                next_render = time.time() + 2.0
    except KeyboardInterrupt:
        pass                                  # Ctrl+C 正常退出
    finally:
        try:
            sock.close()
        except OSError:
            pass
    _pool_render(pool, as_json)


def cmd_release(args, registry):
    """释放输入租约（契约 §21.3）：POST /v1/input 空 actions（空 actions 合法）
    + 头 X-Input-Lease: release；成功输出"已释放输入租约"；400/409 经既有错误路径。"""
    device = resolve(registry, args.name, trust=_trust(args))
    data = request(device, "POST", "/v1/input", {"actions": []},
                   trust=_trust(args),
                   extra_headers={"X-Input-Lease": "release"})
    if getattr(args, "json", False):
        dump(data)
        return
    print("已释放输入租约")


def cmd_elevate(args, registry):
    """高权限驻留引导（契约 §22）：默认 POST /v1/elevate/install（可选 --task-name）；
    --remove 调 POST /v1/elevate/remove（幂等，计划任务不存在也返回 removed）。
    install 会经 node 侧 ShellExecuteW("runas") 触发 UAC（用户确认后创建
    schtasks onlogon /rl highest 计划任务）；UAC 拒绝/超时 → node 明确报错。"""
    device = resolve(registry, args.name, trust=_trust(args))
    payload = {}
    if getattr(args, "task_name", None):
        payload["task_name"] = args.task_name
    if getattr(args, "remove", False):
        data = request(device, "POST", "/v1/elevate/remove", payload,
                       trust=_trust(args))
        if getattr(args, "json", False):
            dump(data)
            return
        print("已移除高权限驻留计划任务 %s" % (data.get("task_name") or "-"))
        return
    data = request(device, "POST", "/v1/elevate/install", payload,
                   trust=_trust(args))
    if getattr(args, "json", False):
        dump(data)
        return
    print("已安装高权限驻留计划任务 %s（开机登录后以最高权限自启）"
          % (data.get("task_name") or "-"))
    # B32 一期轻量形态（D40 / 契约 V1.4 变更记录）：安装成功后补一行白名单首次配置指引。
    # 文案为最终输出原文（README"首次配置"小节同款，勿偏离）；本行不用 % 格式化，
    # %LOCALAPPDATA% 按字面输出；仅新增文案不改既有语义（E-02）。
    # M5 攒批（V1.6 同步）：默认空口径由"拒绝一切"修正为"仅暂存目录可写"（B42/V1.6 §14.1）。
    print("白名单首次配置：编辑被控端 node.json（默认 %LOCALAPPDATA%\\CrossDevice\\node.json）"
          "的 \"workspace\" 键（字符串数组，默认空=仅默认暂存目录可写），"
          "如 \"workspace\": [\"D:\\\\Shared\"]；或启动 node 时加 --workspace \"D:\\\\Shared\"。")


# --------------------------------------------------------------------------
# S2 新增命令（契约 §18：wheel / task ls / task show / del / mkdir / mv）
# --------------------------------------------------------------------------

def cmd_wheel(args, registry):
    """滚轮（delta 可负，负值向上）：走 /v1/input 的 wheel 动作，输出沿用 send_input。"""
    send_input(args, registry, [{"type": "wheel", "delta": args.delta}])


def _task_time(value):
    """任务时间戳 → 本地时间文本（表格/详情用）。"""
    try:
        return time.strftime("%m-%d %H:%M:%S", time.localtime(float(value)))
    except Exception:
        return "-"


def cmd_task_list(args, registry):
    """任务历史列表（契约 §15.2 / §18）：表格含开始时间/任务ID/状态/退出码/命令摘要。"""
    device = resolve(registry, args.name, trust=_trust(args))
    params = {}
    if getattr(args, "status", None):
        params["status"] = args.status
    if getattr(args, "limit", None) is not None:
        params["limit"] = int(args.limit)
    query = urllib.parse.urlencode(params)
    data = request(device, "GET", "/v1/task/list" + ("?" + query if query else ""),
                   timeout=30, trust=_trust(args))
    entries = data.get("entries", []) if isinstance(data, dict) else []
    total = data.get("total", len(entries)) if isinstance(data, dict) else len(entries)
    if args.json:
        dump(data)
        return
    print("%-17s %-14s %-9s %-8s %s" % ("开始时间", "任务ID", "状态", "退出码", "命令"))
    print("-" * 96)
    for entry in entries:
        exit_code = entry.get("exit_code")
        print("%-17s %-14s %-9s %-8s %s" % (
            _task_time(entry.get("started_at")),
            _truncate(str(entry.get("id") or "-"), 14),
            _truncate(str(entry.get("status") or "-"), 9),
            "-" if exit_code is None else str(exit_code),
            _truncate(str(entry.get("cmd") or "-").replace("\n", " "), 42)))
    print("-" * 96)
    print("共 %d 条（总计 %s）" % (len(entries), total))


def cmd_task_show(args, registry):
    """任务详情（契约 §15.2 / §18）：含 stdout/stderr 的人类可读多行输出。"""
    device = resolve(registry, args.name, trust=_trust(args))
    data = request(device, "GET", "/v1/task/%s" % args.task_id,
                   timeout=30, trust=_trust(args))
    if args.json:
        dump(data)
        return
    cwd = data.get("cwd")
    print("任务ID    : %s" % data.get("id"))
    print("身份      : %s" % (data.get("identity") or "-"))
    print("状态      : %s    退出码: %s    耗时: %ss" % (
        data.get("status"), data.get("exit_code"), data.get("duration")))
    print("命令      : %s（shell=%s%s）" % (
        data.get("cmd"), data.get("shell"),
        "" if not cwd else "  cwd=%s" % cwd))
    print("开始      : %s    结束: %s" % (
        _task_time(data.get("started_at")), _task_time(data.get("ended_at"))))
    stdout_text = data.get("stdout") or ""
    stderr_text = data.get("stderr") or ""
    print("-- stdout " + "-" * 62)
    if stdout_text:
        sys.stdout.write(stdout_text if stdout_text.endswith("\n")
                         else stdout_text + "\n")
    print("-- stderr " + "-" * 62)
    if stderr_text:
        sys.stdout.write(stderr_text if stderr_text.endswith("\n")
                         else stderr_text + "\n")


def cmd_del(args, registry):
    """删除远程文件（契约 §14.4 / §18）：缺 --yes 控制端本地拒绝，不发任何请求（D24）。"""
    if not args.yes:
        raise SystemExit("拒绝执行：删除远程文件必须显式加 --yes 确认（未发送任何请求）")
    device = resolve(registry, args.name, trust=_trust(args))
    result = request(device, "POST", "/v1/fs/delete",
                     {"path": args.path, "confirm": True}, trust=_trust(args))
    if args.json:
        dump(result)
        return
    print("已删除 %s" % result.get("path", args.path))


def cmd_mkdir(args, registry):
    """创建远程目录（契约 §14.4 / §18）：递归创建，已存在视为成功。"""
    device = resolve(registry, args.name, trust=_trust(args))
    result = request(device, "POST", "/v1/fs/mkdir", {"path": args.path},
                     trust=_trust(args))
    if args.json:
        dump(result)
        return
    print("已创建目录 %s" % result.get("path", args.path))


def cmd_mv(args, registry):
    """移动/重命名远程文件或目录（契约 §14.4 / §18）：src 与 dst 均须在白名单内。"""
    device = resolve(registry, args.name, trust=_trust(args))
    result = request(device, "POST", "/v1/fs/move",
                     {"src": args.src, "dst": args.dst}, trust=_trust(args))
    if args.json:
        dump(result)
        return
    print("已移动 %s -> %s" % (args.src, result.get("dst", args.dst)))


# --------------------------------------------------------------------------
# S4 新增本地命令（契约 §11 兼容清单 V1.4：`xd cert init`，B26/D32 收口）。
# 纯本地命令：不新增端点、不碰 guard 链/防重放/注册表与设备连接，
# 不读不写 data/devices.json（registry 参数仅保持子命令签名一致）。
# --------------------------------------------------------------------------

def _cert_fingerprint(cert_path):
    """证书 PEM → DER 的 SHA-256 小写 64 hex（契约 §4.1 指纹口径，同
    tools/verify_cert.py 与 node 侧指纹计算）。"""
    text = Path(cert_path).read_bytes().decode("utf-8-sig")
    b64 = "".join(line.strip() for line in text.splitlines()
                  if line.strip() and not line.startswith("-----"))
    der = base64.b64decode(b64)
    return hashlib.sha256(der).hexdigest()


def _cert_manual_cmd(script, out_dir, days, force, host):
    """gen_cert.ps1 的完整手动命令行（PowerShell 缺失/失败时的恢复指引）。"""
    parts = ["powershell -NoProfile -ExecutionPolicy Bypass -File \"%s\"" % script,
             "-OutDir \"%s\"" % out_dir, "-Days %d" % days]
    if force:
        parts.append("-Force")
    if host:
        parts.append("-HostName \"%s\"" % host)
    return " ".join(parts)


def cmd_cert(args, registry):
    """自签证书生成壳命令（契约 §11 V1.4 行 / §4.1）：subprocess 调
    tools/gen_cert.ps1（-OutDir/-Days/-Force/-HostName 一一映射），默认输出目录
    %LOCALAPPDATA%\\CrossDevice\\tls\\ 即 node 默认 TLS 目录。目标目录已有
    cert.pem/key.pem 且未给 --force → 本地明确报错退出（防误覆盖，与
    gen_cert.ps1 覆盖检查一致，不必先跑 PowerShell）；PowerShell 缺失/失败 →
    明确报错并给出手动运行 gen_cert.ps1 的完整命令行。成功输出生成路径 +
    SHA-256 指纹（§4.1 口径，Python 侧解析 PEM 自行计算）+ 下一步提示。"""
    script = ROOT / "tools" / "gen_cert.ps1"
    if not script.is_file():
        raise SystemExit("找不到证书生成脚本：%s\n"
                         "cert init 依赖仓库内的 tools/gen_cert.ps1，"
                         "请在完整检出的仓库目录中运行" % script)

    # 默认输出目录 = node 默认 TLS 目录（契约 §4.1/§9.1）
    if args.out:
        out_dir = Path(args.out)
    else:
        lad = os.environ.get("LOCALAPPDATA")
        if not lad:
            raise SystemExit("无法确定默认输出目录（%LOCALAPPDATA% 未设置），"
                             "请用 --out 显式指定")
        out_dir = Path(lad) / "CrossDevice" / "tls"
    out_dir = Path(os.path.abspath(str(out_dir)))
    cert_path, key_path = out_dir / "cert.pem", out_dir / "key.pem"

    # Python 侧预检查：目标目录已有 cert.pem 或 key.pem 且未给 --force → 直接拒绝
    existing = [p.name for p in (cert_path, key_path) if p.exists()]
    if existing and not args.force:
        raise SystemExit(
            "拒绝覆盖：目标目录已存在 %s（%s）\n"
            "如确认轮换证书请加 --force；旧证书指纹若已被控制端登记（TOFU），"
            "轮换后需 xd add 重录或对既有设备加 --trust" % (" / ".join(existing), out_dir))

    manual = _cert_manual_cmd(script, out_dir, args.days, args.force, args.host)
    ps = shutil.which("powershell")
    if not ps:
        raise SystemExit("未找到 PowerShell（shutil.which(\"powershell\") 为空），"
                         "无法调用证书生成脚本。\n"
                         "请手动执行等价命令生成证书：\n  %s" % manual)

    cmd = [ps, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script),
           "-OutDir", str(out_dir), "-Days", str(args.days)]
    if args.force:
        cmd.append("-Force")
    if args.host:
        cmd += ["-HostName", args.host]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=180)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SystemExit("调用 PowerShell 失败：%r\n"
                         "请手动执行等价命令生成证书：\n  %s" % (exc, manual))

    if proc.returncode != 0 or not cert_path.is_file() or not key_path.is_file():
        tail = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()[-600:]
        raise SystemExit("证书生成失败（gen_cert.ps1 退出码 %s），输出尾部：\n%s\n"
                         "请手动执行等价命令重试：\n  %s"
                         % (proc.returncode, tail or "<无输出>", manual))

    fingerprint = _cert_fingerprint(cert_path)
    print("证书已生成：")
    print("  cert.pem : %s" % cert_path)
    print("  key.pem  : %s" % key_path)
    print("  SHA-256 指纹（契约 §4.1 口径，证书 DER，小写 64 hex）: %s" % fingerprint)
    if args.out:
        print("下一步：该目录不是 node 默认 TLS 目录，请以 node 启动参数 --cert/--key "
              "或 node.json 的 tls.cert/tls.key 显式指向上述文件后重启 node。")
    else:
        print("下一步：默认目录即 node 默认 TLS 目录（node.json 的 tls.cert/tls.key "
              "缺省即指向此处），重启 node 后生效。")


# --------------------------------------------------------------------------
# M6 新增：宏录制与回放（B17/D9/D30，契约 §11 V1.7 兼容清单行，协议零变更）。
# 宏 = 白名单动作序列 JSON（动作与 /v1/input actions 同构，契约 §6.7），只在
# 控制端本地解析与校验，不进入 node 执行面；加载校验失败即整体拒绝、不执行任何
# 动作。D30 红线：不支持循环/条件/变量/表达式/外部命令，不允许任意脚本。
# 回放：按 delay 分段经既有 /v1/input 发送，全程持输入租约（§21.2），中断即释放
# （FR-06）。录制：Windows 低级键鼠钩子（纯标准库 ctypes）捕获控制端本机操作，
# 纯本地命令，不触网络、不写被控端。宏文件格式规范正文见 README"宏（macro rec/run）"节。
# --------------------------------------------------------------------------

MACRO_VERSION = 1
MACRO_ACTION_TYPES = ("click", "doubleclick", "move", "wheel", "type", "key")
MACRO_BUTTONS = ("left", "right", "middle")
MACRO_XY_MAX = 100000            # x/y 宽松护栏（防误填超大值；非桌面物理边界）
MACRO_DELAY_MAX_MS = 600000      # 单个 delay_ms 上限（10 分钟）
MACRO_WHEEL_MAX = 100000         # wheel delta 绝对值护栏
MACRO_TEXT_MAX = 10000           # type text 字符数护栏
MACRO_KEY_MAX = 64               # key 组合串长度护栏
MACRO_ACTIONS_MAX = 10000        # 动作条数护栏
MACRO_SPEED_MIN = 0.01           # --speed 护栏下限
MACRO_SPEED_MAX = 100.0          # --speed 护栏上限

# 录制去抖与聚合阈值（README"宏（macro rec/run）"节如实登记）
MACRO_REC_MOVE_MIN_PX = 8        # 移动采样：距上次采样点位移阈值（像素）
MACRO_REC_MOVE_MAX_GAP_MS = 300  # 移动采样：距上次保留事件的时间阈值（缓慢拖动仍采样）
MACRO_REC_DOUBLE_MS = 500        # 双击聚合窗口（对齐 Windows 默认双击时长）
MACRO_REC_DOUBLE_PX = 8          # 双击聚合允许的最大位移（像素）
MACRO_REC_TEXT_SPLIT_MS = 1500   # 打字聚合：间隔超过即拆分为新的 type 动作

# Windows 低级钩子常量（录制专用，纯标准库 ctypes；回调签名 LRESULT(CALLBACK)(INT, WPARAM, LPARAM)）
_MACRO_WH_MOUSE_LL = 14
_MACRO_WH_KEYBOARD_LL = 13
_MACRO_WM_MOUSEMOVE = 0x0200
_MACRO_WM_LBUTTONDOWN = 0x0201
_MACRO_WM_RBUTTONDOWN = 0x0204
_MACRO_WM_MBUTTONDOWN = 0x0207
_MACRO_WM_MOUSEWHEEL = 0x020A
_MACRO_WM_KEYDOWN = 0x0100
_MACRO_WM_KEYUP = 0x0101
_MACRO_WM_SYSKEYDOWN = 0x0104
_MACRO_WM_SYSKEYUP = 0x0105
_MACRO_LLMHF_INJECTED = 0x00000001
_MACRO_LLKHF_INJECTED = 0x00000010
_MACRO_PM_REMOVE = 1
_MACRO_HOOKPROC = ctypes.WINFUNCTYPE(
    ctypes.c_ssize_t, ctypes.c_int, wintypes.WPARAM, wintypes.LPARAM)


class _MacroMSLLHOOKSTRUCT(ctypes.Structure):
    _fields_ = [("pt", wintypes.POINT), ("mouseData", wintypes.DWORD),
                ("flags", wintypes.DWORD), ("time", wintypes.DWORD),
                ("dwExtraInfo", ctypes.c_size_t)]


class _MacroKBDLLHOOKSTRUCT(ctypes.Structure):
    _fields_ = [("vkCode", wintypes.DWORD), ("scanCode", wintypes.DWORD),
                ("flags", wintypes.DWORD), ("time", wintypes.DWORD),
                ("dwExtraInfo", ctypes.c_size_t)]


# 修饰键（录制侧仅维护按下状态，聚合进后续组合键，不产出独立事件）
_MACRO_MOD_VKS = {0xA0: "shift", 0xA1: "shift", 0x10: "shift",
                  0xA2: "ctrl", 0xA3: "ctrl", 0x11: "ctrl",
                  0xA4: "alt", 0xA5: "alt", 0x12: "alt",
                  0x5B: "win", 0x5C: "win"}
_MACRO_MOD_ORDER = ("ctrl", "alt", "shift", "win")
# 可回放按键名表（与 node 侧 press_key 的 VK 名表对齐；单字符键按字符取名）
_MACRO_VK_NAMES = {0x08: "backspace", 0x09: "tab", 0x0D: "enter", 0x13: "pause",
                   0x14: "capslock", 0x1B: "esc", 0x20: "space", 0x21: "pageup",
                   0x22: "pagedown", 0x23: "end", 0x24: "home", 0x25: "left",
                   0x26: "up", 0x27: "right", 0x28: "down", 0x2C: "printscreen",
                   0x2D: "insert", 0x2E: "delete", 0x5D: "apps", 0x90: "numlock",
                   0x91: "scrolllock", 0xAD: "volumemute", 0xAE: "volumedown",
                   0xAF: "volumeup"}


def _macro_check_int(value, low, high, what):
    """宏数值字段校验：必须是整数（布尔不算）且落在 [low, high]。"""
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("宏校验失败：%s 必须是整数（得到 %r）" % (what, value))
    if value < low or value > high:
        raise ValueError("宏校验失败：%s 超出允许范围 %d–%d（得到 %d）"
                         % (what, low, high, value))


def validate_macro(data):
    """宏加载校验（B17/D30，纯函数、可独立调用/冒烟白盒）：严格校验、整体拒绝——
    任何一项不合法即抛 ValueError（message 明确指明问题与位置），绝不部分接受。
    通过则返回规范化宏 dict（补齐 button 默认值、剥离未知键），供分段与回放直接
    使用。校验规则（README"宏（macro rec/run）"节如实登记）：顶层对象、version==1、
    name 可选字符串、actions 数组（可为空）；动作类型白名单 click/doubleclick/move/
    wheel/type/key + 独立延迟步 {"delay_ms": N}；未知动作类型/缺必填字段/类型不对/
    数值越界/未知字段一律拒绝。D30：不支持循环/条件/变量/表达式/外部命令。"""
    if not isinstance(data, dict):
        raise ValueError("宏校验失败：顶层必须是 JSON 对象（得到 %s）"
                         % type(data).__name__)
    version = data.get("version")
    if isinstance(version, bool) or version != MACRO_VERSION:
        raise ValueError("宏校验失败：version 仅支持 %d（得到 %r）"
                         % (MACRO_VERSION, version))
    name = data.get("name", "")
    if not isinstance(name, str) or len(name) > 128:
        raise ValueError("宏校验失败：name 必须是不超过 128 字符的字符串"
                         "（仅展示用，可省略）")
    actions = data.get("actions")
    if not isinstance(actions, list):
        raise ValueError("宏校验失败：actions 必须是数组（可为空）")
    if len(actions) > MACRO_ACTIONS_MAX:
        raise ValueError("宏校验失败：动作条数 %d 超过上限 %d"
                         % (len(actions), MACRO_ACTIONS_MAX))
    spec = {
        "click": ({"x", "y"}, {"button"}),
        "doubleclick": ({"x", "y"}, {"button"}),
        "move": ({"x", "y"}, set()),
        "wheel": ({"delta"}, set()),
        "type": ({"text"}, set()),
        "key": ({"key"}, set()),
    }
    normalized = []
    for index, action in enumerate(actions, start=1):
        where = "第 %d 个动作" % index
        if not isinstance(action, dict):
            raise ValueError("宏校验失败：%s 必须是对象（得到 %s）"
                             % (where, type(action).__name__))
        keys = set(action)
        if "type" not in action:
            # 独立延迟步：仅允许 {"delay_ms": <毫秒>}
            if "delay_ms" not in keys:
                raise ValueError("宏校验失败：%s 缺少 type 字段（合法类型：%s；"
                                 "或写独立延迟步 {\"delay_ms\": <毫秒>}）"
                                 % (where, "/".join(MACRO_ACTION_TYPES)))
            if keys - {"delay_ms"}:
                raise ValueError("宏校验失败：%s（独立延迟步）包含未知字段：%s"
                                 % (where, "、".join(sorted(keys - {"delay_ms"}))))
            _macro_check_int(action["delay_ms"], 0, MACRO_DELAY_MAX_MS,
                             where + " 的 delay_ms")
            normalized.append({"delay_ms": action["delay_ms"]})
            continue
        kind = action["type"]
        if kind not in MACRO_ACTION_TYPES:
            raise ValueError("宏校验失败：%s 未知动作类型 %r（允许：%s；"
                             "D30：宏不支持循环/条件/变量/表达式/外部命令，"
                             "不允许任意脚本）"
                             % (where, kind, "/".join(MACRO_ACTION_TYPES)))
        required, optional = spec[kind]
        missing = required - keys
        if missing:
            raise ValueError("宏校验失败：%s（%s）缺少必填字段：%s"
                             % (where, kind, "、".join(sorted(missing))))
        unknown = keys - required - optional - {"type", "delay_ms"}
        if unknown:
            raise ValueError("宏校验失败：%s（%s）包含未知字段：%s"
                             % (where, kind, "、".join(sorted(unknown))))
        out = {"type": kind}
        if kind in ("click", "doubleclick", "move"):
            _macro_check_int(action["x"], 0, MACRO_XY_MAX, where + " 的 x")
            _macro_check_int(action["y"], 0, MACRO_XY_MAX, where + " 的 y")
            out["x"], out["y"] = action["x"], action["y"]
        if kind in ("click", "doubleclick"):
            button = action.get("button", "left")
            if button not in MACRO_BUTTONS:
                raise ValueError("宏校验失败：%s 的 button 只能是 %s（得到 %r）"
                                 % (where, "/".join(MACRO_BUTTONS), button))
            out["button"] = button
        if kind == "wheel":
            _macro_check_int(action["delta"], -MACRO_WHEEL_MAX, MACRO_WHEEL_MAX,
                             where + " 的 delta")
            out["delta"] = action["delta"]
        if kind == "type":
            text = action["text"]
            if not isinstance(text, str) or not 1 <= len(text) <= MACRO_TEXT_MAX:
                raise ValueError("宏校验失败：%s 的 text 必须是 1–%d 字符的字符串"
                                 % (where, MACRO_TEXT_MAX))
            out["text"] = text
        if kind == "key":
            key = action["key"]
            if not isinstance(key, str) or not 1 <= len(key) <= MACRO_KEY_MAX:
                raise ValueError("宏校验失败：%s 的 key 必须是 1–%d 字符的非空字符串"
                                 "（如 \"ctrl+a\"）" % (where, MACRO_KEY_MAX))
            out["key"] = key
        if "delay_ms" in keys:
            _macro_check_int(action["delay_ms"], 0, MACRO_DELAY_MAX_MS,
                             where + " 的 delay_ms")
            out["delay_ms"] = action["delay_ms"]
        normalized.append(out)
    return {"version": MACRO_VERSION, "name": name, "actions": normalized}


def load_macro(path):
    """读取并严格校验宏文件（B17/D30；纯控制端本地解析，不涉网络）。
    失败抛 ValueError（文件缺失/不可读/非合法 JSON/校验不通过，message 明确）。"""
    macro_path = Path(path)
    if not macro_path.is_file():
        raise ValueError("宏文件不存在：%s" % macro_path)
    try:
        text = macro_path.read_text(encoding="utf-8-sig")
    except OSError as exc:
        raise ValueError("宏文件无法读取：%s（%s）" % (macro_path, exc))
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise ValueError("宏文件不是合法 JSON：%s（%s）" % (macro_path, exc))
    return validate_macro(data)


def macro_plan(actions, speed=1.0):
    """宏动作序列 → 分段回放计划（B17，纯函数）：连续无延迟的动作合为一段一请求；
    独立延迟步与动作内 delay_ms 在请求之间由控制端 sleep（实际等待 = delay_ms /
    speed，speed 为 --speed 倍率）。返回 [{"wait": <该段发送前等待秒数 float>,
    "actions": [...]}]；末尾无后续动作的延迟不保留（回放收尾即释放租约，不空等）。
    仅接受已通过 validate_macro 的规范化动作。"""
    speed = float(speed)
    if not speed > 0:
        raise ValueError("宏回放失败：speed 必须为正数（得到 %r）" % speed)
    steps = []
    cur_wait_ms = 0                     # 当前段发送前的累计等待（毫秒）
    cur_actions = []
    for action in actions:
        wait = action.get("delay_ms", 0) or 0
        if wait:
            if cur_actions:
                steps.append({"wait": cur_wait_ms / speed / 1000.0,
                              "actions": cur_actions})
                cur_wait_ms, cur_actions = 0, []
            cur_wait_ms += wait
        if "type" in action:
            cur_actions.append(action)
    if cur_actions:
        steps.append({"wait": cur_wait_ms / speed / 1000.0, "actions": cur_actions})
    return steps


def macro_events_to_actions(events):
    """录制事件流 → 宏动作序列（B17，纯函数、供冒烟白盒以合成事件直接调用）。
    事件须按时间升序（录制钩子天然有序），格式：{"kind": "move|click|wheel|key|
    text", "t": <unix 秒>, ...各 kind 字段}。映射规则（README 如实登记）：
    - 移动去抖：位移 ≥ MACRO_REC_MOVE_MIN_PX 或距上次保留事件 ≥
      MACRO_REC_MOVE_MAX_GAP_MS 才采样成 move（连续微移不会塞满宏）；
    - 点击聚合：同键、间隔 ≤ MACRO_REC_DOUBLE_MS 且位移 ≤ MACRO_REC_DOUBLE_PX
      的相邻两次点击合并为 doubleclick（取第一次点击坐标与其 delay）；
    - 可打印字符聚合为 type（间隔 > MACRO_REC_TEXT_SPLIT_MS 拆分为新动作）；
    - 其余按键（修饰键组合串）为 key；滚轮为 wheel（原始 delta，120/格）；
    - 相邻保留事件的间隔写入 delay_ms（毫秒，0–MACRO_DELAY_MAX_MS，首个动作为 0）。"""
    actions = []
    last_t = None                       # 上一个保留事件的时间（delay 基准）
    last_event_t = None                 # 上一个保留事件的时间（移动时间阈值基准）
    last_pos = None                     # 上一个保留 move 的坐标（移动位移阈值基准）
    pending_text = None                 # 打字聚合缓冲
    pending_first_t = None
    pending_last_t = None
    last_click = None                   # (button, x, y, t, 动作下标)，供双击聚合

    def emit(action, t_event, t_advance=None):
        nonlocal last_t
        if t_advance is None:
            t_advance = t_event
        delay = 0 if last_t is None else int(round((t_event - last_t) * 1000))
        delay = max(0, min(MACRO_DELAY_MAX_MS, delay))
        if delay:
            action["delay_ms"] = delay
        actions.append(action)
        last_t = t_advance

    def flush_text():
        nonlocal pending_text, pending_first_t, pending_last_t
        if pending_text:
            emit({"type": "type", "text": pending_text},
                 pending_first_t, pending_last_t)
        pending_text, pending_first_t, pending_last_t = None, None, None

    for ev in events:
        kind = ev.get("kind")
        t = float(ev.get("t") or 0.0)
        if kind == "move":
            x, y = int(ev.get("x", 0)), int(ev.get("y", 0))
            keep = last_pos is None
            if not keep:
                dist = max(abs(x - last_pos[0]), abs(y - last_pos[1]))
                gap = (t - last_event_t) * 1000.0 if last_event_t is not None else 0.0
                keep = dist >= MACRO_REC_MOVE_MIN_PX \
                    or gap >= MACRO_REC_MOVE_MAX_GAP_MS
            if keep:
                flush_text()
                emit({"type": "move", "x": x, "y": y}, t)
                last_pos = (x, y)
                last_event_t = t
        elif kind == "click":
            x, y = int(ev.get("x", 0)), int(ev.get("y", 0))
            button = ev.get("button", "left")
            flush_text()
            if last_click and last_click[0] == button \
                    and (t - last_click[3]) * 1000 <= MACRO_REC_DOUBLE_MS \
                    and max(abs(x - last_click[1]), abs(y - last_click[2])) \
                    <= MACRO_REC_DOUBLE_PX:
                # 合并为双击：替换上一次 click 动作（保留其 delay 与第一次坐标）
                merged = dict(actions[last_click[4]])
                merged.update({"type": "doubleclick", "x": last_click[1],
                               "y": last_click[2], "button": button})
                actions[last_click[4]] = merged
                last_click = None
                last_t = t              # 后续间隔从第二次按下起算
            else:
                emit({"type": "click", "x": x, "y": y, "button": button}, t)
                last_click = (button, x, y, t, len(actions) - 1)
            last_event_t = t
        elif kind == "wheel":
            flush_text()
            emit({"type": "wheel", "delta": int(ev.get("delta", 0))}, t)
            last_click = None
            last_event_t = t
        elif kind == "key":
            flush_text()
            emit({"type": "key", "key": str(ev.get("key", ""))}, t)
            last_click = None
            last_event_t = t
        elif kind == "text":
            ch = str(ev.get("text", ""))
            if not ch:
                continue
            if pending_text is None:
                pending_text, pending_first_t = ch, t
            elif (t - pending_last_t) * 1000 > MACRO_REC_TEXT_SPLIT_MS:
                flush_text()
                pending_text, pending_first_t = ch, t
            else:
                pending_text += ch
            pending_last_t = t
            last_click = None
            last_event_t = t
        # 其他 kind（未知事件）忽略
    flush_text()
    return actions


def macro_run_segments(device, plan, trust=False, progress=None,
                       sleeper=time.sleep, sender=None):
    """宏分段执行（B17/契约 §21.2 全程持租约 + FR-06 中断即释放；供冒烟白盒注入
    sleeper/sender）：首段请求带 X-Input-Lease: acquire，其后各段无头（隐式
    acquire = 本人持有即续期，契约 §21.2）；每段发送前先 sleep 该段等待秒数
    （= delay_ms / speed）。任何异常（含 KeyboardInterrupt/SystemExit）→
    best-effort 发 release（空 actions，空 actions 合法）后原样抛出；正常结束
    同样发 release（避免占着租约等 60 秒过期）。目标机锁屏/非交互 → 中止并如实
    报错（release 后抛 SystemExit）。返回成功执行的段数。
    sender 缺省 xd.request；409 INPUT_LEASE_TAKEN 经既有错误路径抛 RuntimeError
    （首段被占则整单不执行；中途被抢占则中止剩余动作）。"""
    send_fn = sender or request
    executed = 0
    try:
        for index, step in enumerate(plan):
            if step["wait"] > 0:
                sleeper(step["wait"])
            headers = {"X-Input-Lease": "acquire"} if index == 0 else None
            data = send_fn(device, "POST", "/v1/input", {"actions": step["actions"]},
                           trust=trust, extra_headers=headers, timeout=30)
            executed += 1
            if isinstance(data, dict):
                if data.get("locked"):
                    raise SystemExit("目标机锁屏，输入未生效")
                if data.get("interactive") is False:
                    raise SystemExit("目标机不在交互式桌面会话，输入未生效")
            if progress is not None:
                progress(index, step, data)
    except BaseException:
        try:
            send_fn(device, "POST", "/v1/input", {"actions": []},
                    trust=trust, extra_headers={"X-Input-Lease": "release"},
                    timeout=10)
        except Exception:
            pass                        # 释放尽力而为，不掩盖原异常
        raise
    try:
        send_fn(device, "POST", "/v1/input", {"actions": []},
                trust=trust, extra_headers={"X-Input-Lease": "release"}, timeout=10)
    except Exception:
        pass
    return executed


def _macro_vk_char(user32, vk, scan, mods):
    """按键 → 可打印字符（ToUnicodeEx，手工构造 Shift/CapsLock 状态）；无字符
    返回 None。仅录制线程在钩子回调内调用。"""
    state = (ctypes.c_ubyte * 256)()
    if "shift" in mods:
        state[0x10] = 0x80
    if user32.GetKeyState(0x14) & 1:
        state[0x14] = 0x01
    buf = ctypes.create_unicode_buffer(4)
    hkl = user32.GetKeyboardLayout(0)
    n = user32.ToUnicodeEx(vk, scan, state, buf, 4, 0, hkl)
    if n > 0 and buf.value:
        return buf.value[0]
    return None


def _macro_key_name(user32, vk, mods):
    """按键 → node 侧 press_key 可回放的组合键串（修饰键序 ctrl/alt/shift/win）；
    node 按键白名单（VK 名表 + 单字符）之外的按键返回 None（录制时跳过并计数）。"""
    base = _MACRO_VK_NAMES.get(vk)
    if base is None:
        ch = _macro_vk_char(user32, vk, 0, set())
        if ch and ord(ch) >= 0x20 and ord(ch) != 0x7F:
            base = ch.lower()
        else:
            return None
    return "+".join([m for m in _MACRO_MOD_ORDER if m in mods] + [base])


def cmd_macro_rec(args, registry):
    """宏录制（B17/D9/D30，纯本地命令：不触网络、不写被控端、不读注册表，
    registry 参数仅保持子命令签名一致）：Windows 低级键鼠钩子（WH_MOUSE_LL/
    WH_KEYBOARD_LL，纯标准库 ctypes）捕获控制端本机操作 --seconds 秒（默认 10，
    Ctrl+C 提前结束）。移动去抖、双击/打字聚合、相邻事件间隔写 delay_ms；产物经
    与回放同一套严格校验（validate_macro）后原子写盘（写前校验，失败不写盘）。
    钩子安装失败明确报错不静默；所有退出路径必调 UnhookWindowsHookEx；忽略注入
    事件（防"回放本机时录制自录"回环）。录制不自动回放。"""
    out = Path(args.out)
    seconds = int(args.seconds)
    if not 1 <= seconds <= 3600:
        raise SystemExit("--seconds 取值 1–3600（得到 %d）" % seconds)

    user32 = ctypes.WinDLL("user32", use_last_error=True)
    user32.PeekMessageW.argtypes = [ctypes.POINTER(wintypes.MSG), ctypes.c_void_p,
                                    wintypes.UINT, wintypes.UINT, wintypes.UINT]
    user32.PeekMessageW.restype = wintypes.BOOL
    user32.TranslateMessage.argtypes = [ctypes.POINTER(wintypes.MSG)]
    user32.DispatchMessageW.argtypes = [ctypes.POINTER(wintypes.MSG)]
    user32.SetWindowsHookExW.argtypes = [ctypes.c_int, _MACRO_HOOKPROC,
                                         ctypes.c_void_p, wintypes.DWORD]
    user32.SetWindowsHookExW.restype = ctypes.c_void_p
    user32.UnhookWindowsHookEx.argtypes = [ctypes.c_void_p]
    user32.CallNextHookEx.argtypes = [ctypes.c_void_p, ctypes.c_int,
                                      wintypes.WPARAM, wintypes.LPARAM]
    user32.CallNextHookEx.restype = ctypes.c_ssize_t
    user32.ToUnicodeEx.argtypes = [wintypes.UINT, wintypes.UINT,
                                   ctypes.POINTER(ctypes.c_ubyte),
                                   ctypes.POINTER(ctypes.c_wchar),
                                   ctypes.c_int, wintypes.UINT, ctypes.c_void_p]
    user32.ToUnicodeEx.restype = ctypes.c_int
    user32.GetKeyboardLayout.argtypes = [wintypes.DWORD]
    user32.GetKeyboardLayout.restype = ctypes.c_void_p
    user32.GetKeyState.argtypes = [ctypes.c_int]
    user32.GetKeyState.restype = ctypes.c_short

    # DPI 感知（per-monitor v2，失败回退系统级）：让钩子坐标与物理像素一致
    # （node 侧按虚拟桌面物理像素归一化，契约 §6.7）
    try:
        user32.SetProcessDpiAwarenessContext.restype = wintypes.BOOL
        user32.SetProcessDpiAwarenessContext.argtypes = [ctypes.c_void_p]
        if not user32.SetProcessDpiAwarenessContext(ctypes.c_void_p(-4)):
            user32.SetProcessDPIAware()
    except AttributeError:
        try:
            user32.SetProcessDPIAware()
        except Exception:
            pass

    events = []
    counters = {"mouse": 0, "key": 0, "skipped": 0}
    held = set()                        # 当前按下的修饰键
    move_state = {"pos": None, "t": 0.0}

    def on_mouse(n_code, w_param, l_param):
        if n_code >= 0:
            info = ctypes.cast(l_param,
                               ctypes.POINTER(_MacroMSLLHOOKSTRUCT)).contents
            if not int(info.flags) & _MACRO_LLMHF_INJECTED:
                msg = int(w_param)
                t = time.time()
                if msg == _MACRO_WM_MOUSEMOVE:
                    x, y = int(info.pt.x), int(info.pt.y)
                    keep = move_state["pos"] is None
                    if not keep:
                        dist = max(abs(x - move_state["pos"][0]),
                                   abs(y - move_state["pos"][1]))
                        gap = (t - move_state["t"]) * 1000.0
                        keep = dist >= MACRO_REC_MOVE_MIN_PX \
                            or gap >= MACRO_REC_MOVE_MAX_GAP_MS
                    if keep:
                        events.append({"kind": "move", "x": x, "y": y, "t": t})
                        move_state["pos"], move_state["t"] = (x, y), t
                        counters["mouse"] += 1
                elif msg in (_MACRO_WM_LBUTTONDOWN, _MACRO_WM_RBUTTONDOWN,
                             _MACRO_WM_MBUTTONDOWN):
                    button = {0x0201: "left", 0x0204: "right",
                              0x0207: "middle"}[msg]
                    events.append({"kind": "click", "x": int(info.pt.x),
                                   "y": int(info.pt.y), "button": button, "t": t})
                    counters["mouse"] += 1
                elif msg == _MACRO_WM_MOUSEWHEEL:
                    delta = ctypes.c_short(
                        (int(info.mouseData) >> 16) & 0xFFFF).value
                    events.append({"kind": "wheel", "delta": int(delta), "t": t})
                    counters["mouse"] += 1
        return user32.CallNextHookEx(None, n_code, w_param, l_param)

    def on_key(n_code, w_param, l_param):
        if n_code >= 0:
            info = ctypes.cast(l_param,
                               ctypes.POINTER(_MacroKBDLLHOOKSTRUCT)).contents
            if not int(info.flags) & _MACRO_LLKHF_INJECTED:
                vk = int(info.vkCode)
                msg = int(w_param)
                if msg in (_MACRO_WM_KEYDOWN, _MACRO_WM_SYSKEYDOWN):
                    if vk in _MACRO_MOD_VKS:
                        held.add(_MACRO_MOD_VKS[vk])
                    else:
                        counters["key"] += 1
                        t = time.time()
                        mods = {m for m in _MACRO_MOD_ORDER if m in held}
                        ev = None
                        if {"ctrl", "alt", "win"} & mods:
                            name = _macro_key_name(user32, vk, mods)
                            if name:
                                ev = {"kind": "key", "key": name, "t": t}
                        else:
                            ch = _macro_vk_char(user32, vk,
                                                int(info.scanCode), mods)
                            if ch and ord(ch) >= 0x20 and ord(ch) != 0x7F:
                                ev = {"kind": "text", "text": ch, "t": t}
                            else:
                                name = _macro_key_name(user32, vk, mods)
                                if name:
                                    ev = {"kind": "key", "key": name, "t": t}
                        if ev is None:
                            counters["skipped"] += 1
                        else:
                            events.append(ev)
                elif msg in (_MACRO_WM_KEYUP, _MACRO_WM_SYSKEYUP):
                    if vk in _MACRO_MOD_VKS:
                        held.discard(_MACRO_MOD_VKS[vk])
        return user32.CallNextHookEx(None, n_code, w_param, l_param)

    mouse_proc = _MACRO_HOOKPROC(on_mouse)
    key_proc = _MACRO_HOOKPROC(on_key)
    mouse_hook = user32.SetWindowsHookExW(_MACRO_WH_MOUSE_LL, mouse_proc, None, 0)
    key_hook = None
    try:
        if not mouse_hook:
            raise SystemExit("低级鼠标钩子安装失败（Windows 错误码 %d）："
                             "可能被安全软件拦截或当前会话不允许全局钩子，录制未开始"
                             % ctypes.get_last_error())
        key_hook = user32.SetWindowsHookExW(_MACRO_WH_KEYBOARD_LL, key_proc, None, 0)
        if not key_hook:
            raise SystemExit("低级键盘钩子安装失败（Windows 错误码 %d）："
                             "可能被安全软件拦截或当前会话不允许全局钩子，录制未开始"
                             % ctypes.get_last_error())
        print("正在录制 %d 秒，Ctrl+C 结束；控制端本机键鼠操作将捕获到：%s"
              % (seconds, out))
        msg = wintypes.MSG()
        deadline = time.time() + seconds
        next_hint = time.time() + 2.0
        try:
            while time.time() < deadline:
                while user32.PeekMessageW(ctypes.byref(msg), None, 0, 0,
                                          _MACRO_PM_REMOVE):
                    user32.TranslateMessage(ctypes.byref(msg))
                    user32.DispatchMessageW(ctypes.byref(msg))
                if time.time() >= next_hint:
                    print("  已捕获 %d 个事件（鼠标 %d / 键盘 %d）"
                          % (counters["mouse"] + counters["key"],
                             counters["mouse"], counters["key"]))
                    next_hint = time.time() + 2.0
                time.sleep(0.05)
        except KeyboardInterrupt:
            pass                        # Ctrl+C 提前结束（正常产物路径）
    finally:
        if key_hook:
            user32.UnhookWindowsHookEx(key_hook)
        if mouse_hook:
            user32.UnhookWindowsHookEx(mouse_hook)

    actions = macro_events_to_actions(events)
    try:
        data = validate_macro({"version": MACRO_VERSION, "name": out.stem,
                               "actions": actions})
    except ValueError as exc:
        raise SystemExit("录制产物未通过加载校验（内部错误，未写盘）：%s" % exc)
    try:
        _atomic_write_text(out, json.dumps(data, ensure_ascii=False, indent=2))
    except OSError as exc:
        raise SystemExit("无法写入宏文件 %s（%s）" % (out, exc))
    if not data["actions"]:
        print("未捕获任何事件，已写入空宏（actions 为空）-> %s" % out)
        return
    skipped_text = ("，跳过 %d 个不可回放按键（如 F 功能键/输入法组字键，"
                    "被控端按键白名单不含它们）" % counters["skipped"]) \
        if counters["skipped"] else ""
    print("已录制 %d 个动作 -> %s（捕获鼠标 %d / 键盘 %d 个事件，已通过加载校验%s）"
          % (len(data["actions"]), out, counters["mouse"], counters["key"],
             skipped_text))


def cmd_macro_run(args, registry):
    """宏回放（B17/D9/D30）：加载校验失败即整体拒绝（不执行任何动作、不发任何
    请求）→ 按 delay 分段经既有 /v1/input 发送（连续无延迟动作合为一段一请求，
    段间控制端 sleep delay_ms/speed）→ 全程持输入租约（首段 X-Input-Lease:
    acquire、其后无头=隐式续期，契约 §21.2）→ 正常结束发 release（空 actions）；
    Ctrl+C 或异常中断即 best-effort release（FR-06"中断即释放"）。他人持有 →
    409 INPUT_LEASE_TAKEN 如实报错（首段被占则整单不执行；中途被抢占则中止剩余
    动作）。--speed 正浮点 0.01–100 等比缩放 delay_ms。"""
    speed = float(args.speed)
    if not MACRO_SPEED_MIN <= speed <= MACRO_SPEED_MAX:
        raise SystemExit("--speed 越界（允许 %.2f–%g）：%g"
                         % (MACRO_SPEED_MIN, MACRO_SPEED_MAX, speed))
    try:
        macro = load_macro(args.file)
    except ValueError as exc:
        raise SystemExit(str(exc))      # 整体拒绝（D30）：未发任何请求
    plan = macro_plan(macro["actions"], speed)
    total_actions = sum(len(step["actions"]) for step in plan)
    as_json = bool(getattr(args, "json", False))
    if not plan:
        if as_json:
            dump({"macro": macro.get("name") or "", "actions": 0, "segments": 0,
                  "executed": 0, "speed": speed, "released": False,
                  "note": "宏无动作，未发送任何请求"})
            return
        print("宏无动作（actions 为空或仅末尾延迟），未发送任何请求")
        return
    device = resolve(registry, args.name, trust=_trust(args))
    if as_json:
        progress = None
    else:
        def progress(index, step, _data):
            wait_text = ("等待 %.2fs 后" % step["wait"]) if step["wait"] > 0 else "立即"
            print("  第 %d/%d 段（%s）：已发送 %d 个动作"
                  % (index + 1, len(plan), wait_text, len(step["actions"])))
    print("已加载宏「%s」：%d 个动作，分 %d 段发送（speed=%g）"
          % (macro.get("name") or "(未命名)", total_actions, len(plan), speed))
    try:
        executed = macro_run_segments(device, plan, trust=_trust(args),
                                      progress=progress)
    except KeyboardInterrupt:
        print("回放已中断（Ctrl+C）：输入租约已释放")
        raise SystemExit(130)
    if as_json:
        dump({"macro": macro.get("name") or "", "actions": total_actions,
              "segments": len(plan), "executed": executed, "speed": speed,
              "released": True})
        return
    print("回放完成：共 %d 个动作 / %d 段，已释放输入租约" % (total_actions, len(plan)))


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
    p.add_argument("--port", type=int, default=51888,
                   help="端口（默认 51888，偏差 7）")
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
    p.add_argument("--max-width", type=int, default=0,
                   help="等比缩放宽度（0=原始分辨率不缩放，FR-05/D18 默认；"
                        "带宽受限场景显式指定，如 1600）")
    p.add_argument("--trust", action="store_true", help=TRUST_HELP)
    p.set_defaults(func=cmd_shot)

    p = sub.add_parser("click", parents=[common], help="点击坐标")
    p.add_argument("name")
    p.add_argument("x", type=int)
    p.add_argument("y", type=int)
    p.add_argument("--button", default="left", choices=["left", "right", "middle"])
    p.add_argument("--double", action="store_true")
    p.add_argument("--take", action="store_true",
                   help="显式抢占输入租约（S3，X-Input-Lease: take）")
    p.add_argument("--trust", action="store_true", help=TRUST_HELP)
    p.set_defaults(func=cmd_click)

    p = sub.add_parser("move", parents=[common], help="移动鼠标")
    p.add_argument("name")
    p.add_argument("x", type=int)
    p.add_argument("y", type=int)
    p.add_argument("--take", action="store_true",
                   help="显式抢占输入租约（S3，X-Input-Lease: take）")
    p.add_argument("--trust", action="store_true", help=TRUST_HELP)
    p.set_defaults(func=cmd_move)

    p = sub.add_parser("type", parents=[common], help="输入文本")
    p.add_argument("name")
    p.add_argument("text")
    p.add_argument("--take", action="store_true",
                   help="显式抢占输入租约（S3，X-Input-Lease: take）")
    p.add_argument("--trust", action="store_true", help=TRUST_HELP)
    p.set_defaults(func=cmd_type)

    p = sub.add_parser("key", parents=[common], help="按键，如 enter / ctrl+a")
    p.add_argument("name")
    p.add_argument("combo")
    p.add_argument("--take", action="store_true",
                   help="显式抢占输入租约（S3，X-Input-Lease: take）")
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

    p = sub.add_parser("put", parents=[common], help="上传文件（S2 流式分块，支持断点续传）")
    p.add_argument("name")
    p.add_argument("local")
    p.add_argument("remote")
    p.add_argument("--fresh", action="store_true",
                   help="终止服务端既有上传会话，丢弃断点全新上传")
    p.add_argument("--trust", action="store_true", help=TRUST_HELP)
    p.set_defaults(func=cmd_put)

    p = sub.add_parser("get", parents=[common], help="下载文件（S2 流式分块，支持断点续传）")
    p.add_argument("name")
    p.add_argument("remote")
    p.add_argument("local")
    p.add_argument("--max", type=int, default=64 * 1024 * 1024,
                   help="保留参数，S2 起不再使用（流式下载无上限，静默忽略）")
    p.add_argument("--fresh", action="store_true",
                   help="删除断点文件 <local>.crosspart，重新完整下载")
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

    p = sub.add_parser("wheel", parents=[common], help="滚轮滚动（负值向上）")
    p.add_argument("name")
    p.add_argument("delta", type=int, help="滚动量，可为负")
    p.add_argument("--take", action="store_true",
                   help="显式抢占输入租约（S3，X-Input-Lease: take）")
    p.add_argument("--trust", action="store_true", help=TRUST_HELP)
    p.set_defaults(func=cmd_wheel)

    p = sub.add_parser("task", parents=[common], help="任务历史（S2 持久化）")
    task_sub = p.add_subparsers(dest="task_action", required=True)
    tp = task_sub.add_parser("ls", parents=[common], help="列出任务历史")
    tp.add_argument("name")
    tp.add_argument("--status", default=None,
                    choices=["running", "done", "timeout", "failed"], help="按状态过滤")
    tp.add_argument("--limit", type=int, default=None, help="返回条数（1-200，节点默认 50）")
    tp.add_argument("--trust", action="store_true", help=TRUST_HELP)
    tp.set_defaults(func=cmd_task_list)
    tp = task_sub.add_parser("show", parents=[common], help="查看任务详情（含 stdout/stderr）")
    tp.add_argument("name")
    tp.add_argument("task_id")
    tp.add_argument("--trust", action="store_true", help=TRUST_HELP)
    tp.set_defaults(func=cmd_task_show)

    p = sub.add_parser("del", parents=[common], help="删除远程文件（必须显式 --yes）")
    p.add_argument("name")
    p.add_argument("path")
    p.add_argument("--yes", action="store_true",
                   help="显式确认删除（D24：缺省本地拒绝，不发请求）")
    p.add_argument("--trust", action="store_true", help=TRUST_HELP)
    p.set_defaults(func=cmd_del)

    p = sub.add_parser("mkdir", parents=[common], help="创建远程目录（递归）")
    p.add_argument("name")
    p.add_argument("path")
    p.add_argument("--trust", action="store_true", help=TRUST_HELP)
    p.set_defaults(func=cmd_mkdir)

    p = sub.add_parser("mv", parents=[common], help="移动/重命名远程文件或目录")
    p.add_argument("name")
    p.add_argument("src")
    p.add_argument("dst")
    p.add_argument("--trust", action="store_true", help=TRUST_HELP)
    p.set_defaults(func=cmd_mv)

    p = sub.add_parser("pool", parents=[common], help="监听发现广播并显示设备池（S3）")
    p.add_argument("--seconds", type=int, default=None,
                   help="采样 N 秒后输出一次快照退出（缺省持续模式，每 2 秒重印）")
    p.set_defaults(func=cmd_pool)

    p = sub.add_parser("release", parents=[common], help="释放设备输入租约（S3）")
    p.add_argument("name")
    p.add_argument("--trust", action="store_true", help=TRUST_HELP)
    p.set_defaults(func=cmd_release)

    p = sub.add_parser("elevate", parents=[common], help="高权限驻留计划任务安装/移除（S3）")
    p.add_argument("name")
    p.add_argument("--task-name", default=None,
                   help="计划任务名（缺省由 node 决定，默认 CrossDeviceNode）")
    p.add_argument("--remove", action="store_true", help="移除驻留计划任务（幂等）")
    p.add_argument("--trust", action="store_true", help=TRUST_HELP)
    p.set_defaults(func=cmd_elevate)

    # S4 新增本地命令（契约 §11 兼容清单 V1.4）：cert init 为纯本地命令，
    # 不挂 common 父解析器（非设备类，无 --trust/--json）。
    p = sub.add_parser("cert", help="本地证书工具（S4/B26，纯本地，不涉网络与设备注册表）")
    cert_sub = p.add_subparsers(dest="cert_action", required=True)
    cp = cert_sub.add_parser(
        "init", help="生成自签证书（TLS 1.3/TOFU 用，调 tools/gen_cert.ps1，契约 §4.1/§11）")
    cp.add_argument("--out", default=None,
                    help="输出目录（默认 %%LOCALAPPDATA%%\\CrossDevice\\tls\\，即 node 默认 TLS 目录）")
    cp.add_argument("--days", type=int, default=3650,
                    help="证书有效期天数（默认 3650，与 gen_cert.ps1 一致）")
    cp.add_argument("--force", action="store_true",
                    help="覆盖目标目录已有的 cert.pem / key.pem（轮换证书）")
    cp.add_argument("--host", default=None,
                    help="证书 CN（缺省用 %%COMPUTERNAME%%，由 gen_cert.ps1 处理）")
    cp.set_defaults(func=cmd_cert)

    # M6 新增（B17 宏录制与回放，契约 §11 V1.7）：macro 双子解析器注册模式同
    # task/cert。run 为设备类命令：挂 common 父解析器（--json）+ --trust；
    # rec 为纯本地命令：不挂 common（无 --json/--trust，不涉设备与网络，参照 cert）。
    p = sub.add_parser("macro",
                       help="宏录制与回放（B17，纯控制端本地功能，D30 白名单动作序列）")
    macro_sub = p.add_subparsers(dest="macro_action", required=True)
    mp = macro_sub.add_parser(
        "rec", help="录制控制端本机键鼠操作为宏文件（Windows 低级钩子，纯本地，不触网络）")
    mp.add_argument("out", help="输出宏文件路径（JSON，UTF-8；格式见 README\"宏（macro rec/run）\"节）")
    mp.add_argument("--seconds", type=int, default=10,
                    help="录制时长秒数（默认 10，Ctrl+C 可提前结束；1–3600）")
    mp.set_defaults(func=cmd_macro_rec)
    mp = macro_sub.add_parser(
        "run", parents=[common],
        help="回放宏文件（分段经 /v1/input 发送，全程持输入租约，中断即释放）")
    mp.add_argument("name")
    mp.add_argument("file", help="宏文件路径（JSON，UTF-8）")
    mp.add_argument("--speed", type=float, default=1.0,
                    help="回放倍率（0.01–100，默认 1.0；等比缩放宏内 delay_ms）")
    mp.add_argument("--trust", action="store_true", help=TRUST_HELP)
    mp.set_defaults(func=cmd_macro_run)

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
