#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CrossDevice 执行器（node）

被控端常驻进程：只做"手和眼"，不含任何 AI 逻辑。
零第三方依赖，仅使用 Python 标准库 + ctypes 调用 Win32 API。

提供能力：
    /v1/health        健康检查
    /v1/info          环境自检（交互会话 / 锁屏 / 提权 / DPI / 显示器）
    /v1/exec          启动命令任务，返回 job_id
    /v1/job/<id>      查询任务结果（支持 wait 长轮询）
    /v1/fs/list       列目录
    /v1/fs/read       读文件
    /v1/fs/write      写文件
    /v1/fs/stat       文件信息
    /v1/screen        截屏，返回 PNG
    /v1/input         鼠标键盘注入
    /v1/audit         审计日志查询（S1 新增）
    /v1/self-update   热更新自身源码并重启

安全基线（S1，唯一行为依据 docs/接口契约.md V1.0）：
    - 传输：默认 HTTPS（TLS 1.3，自签证书 + TOFU）；--debug-plaintext 才回退明文（D31）
    - 身份：node.json 多控制端身份（tokens 列表），令牌用 hmac.compare_digest 常量时间比较
    - 防重放：每个 /v1/* 请求必须带 X-Timestamp / X-Nonce，nonce 仅内存缓存（重启清空）
    - 审计：<config 目录>/audit/audit-YYYYMMDD.jsonl 追加写，默认留存 180 天

启动方式：
    python node.py [--port 8788] [--host 0.0.0.0] [--token <令牌>] [--verbose]
                   [--config <node.json 路径>] [--cert <cert.pem> --key <key.pem>]
                   [--debug-plaintext]
"""

import argparse
import base64
import ctypes
import hashlib
import hmac
import json
import math
import os
import platform
import re
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import uuid
import zlib
from ctypes import wintypes
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

NODE_VERSION = "0.2.0"
MAX_OUTPUT = 256 * 1024          # 单个任务输出上限
MAX_BODY = 64 * 1024 * 1024      # 请求体上限
VERBOSE = False
STARTED_AT = time.time()

# ---- S1 安全层全局状态（契约 V1.0）----
DEFAULT_IDENTITY_NAME = "default"   # 默认身份名（契约 §2.1）
MAX_IDENTITIES = 16                 # 身份列表上限（契约 §9.1）
REPLAY_WINDOW = 300                 # 防重放时间窗 ±300 秒（契约 §3.1）
NONCE_MAX_LEN = 128                 # X-Nonce 长度上限（契约 §3.1）
IDENTITIES = []                     # [{"name":..., "token":...}]，启动时加载（§2.1）
TOKEN = ""                          # default 身份令牌（兼容旧引用与横幅展示）
TLS_ENABLED = False                 # 主端口是否以 TLS 服务（§4.2）
TLS_PLAINTEXT_DEBUG = False         # --debug-plaintext 明文调试（D31）
CERT_FINGERPRINT = None             # 证书 DER 的 SHA-256，小写 64 hex（§4.1）
AUDIT_DIR = ""                      # 审计目录（§8.1）
AUDIT_RETENTION_DAYS = 180          # 审计留存天数（§8.1，D36）
AUDIT_LOCK = threading.Lock()       # 审计追加写锁
NONCES = {}                         # nonce -> 过期时刻，仅内存、重启清空（§3.2）
NONCES_LOCK = threading.Lock()      # nonce 查重/写入共用一把锁（§3.2）

if os.name != "nt":
    raise SystemExit("node.py 仅支持 Windows（当前系统：%s）" % os.name)

# --------------------------------------------------------------------------
# Win32 基础设施
# --------------------------------------------------------------------------

user32 = ctypes.WinDLL("user32", use_last_error=True)
gdi32 = ctypes.WinDLL("gdi32", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

HANDLE = wintypes.HANDLE
HDC = wintypes.HDC
ULONG_PTR = ctypes.c_size_t

SRCCOPY = 0x00CC0020
DIB_RGB_COLORS = 0
HALFTONE = 4

SM_XVIRTUALSCREEN = 76
SM_YVIRTUALSCREEN = 77
SM_CXVIRTUALSCREEN = 78
SM_CYVIRTUALSCREEN = 79
LOGPIXELSX = 88

DESKTOP_SWITCHDESKTOP = 0x0100
UOI_NAME = 2


class BITMAPINFOHEADER(ctypes.Structure):
    _fields_ = [
        ("biSize", wintypes.DWORD),
        ("biWidth", wintypes.LONG),
        ("biHeight", wintypes.LONG),
        ("biPlanes", wintypes.WORD),
        ("biBitCount", wintypes.WORD),
        ("biCompression", wintypes.DWORD),
        ("biSizeImage", wintypes.DWORD),
        ("biXPelsPerMeter", wintypes.LONG),
        ("biYPelsPerMeter", wintypes.LONG),
        ("biClrUsed", wintypes.DWORD),
        ("biClrImportant", wintypes.DWORD),
    ]


class BITMAPINFO(ctypes.Structure):
    _fields_ = [("bmiHeader", BITMAPINFOHEADER), ("bmiColors", wintypes.DWORD * 3)]


class MONITORINFO(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("rcMonitor", wintypes.RECT),
        ("rcWork", wintypes.RECT),
        ("dwFlags", wintypes.DWORD),
    ]


MONITORENUMPROC = ctypes.WINFUNCTYPE(
    wintypes.BOOL, HANDLE, HDC, ctypes.POINTER(wintypes.RECT), wintypes.LPARAM
)

user32.GetDC.argtypes = [HANDLE]
user32.GetDC.restype = HDC
user32.ReleaseDC.argtypes = [HANDLE, HDC]
user32.ReleaseDC.restype = ctypes.c_int
user32.GetSystemMetrics.argtypes = [ctypes.c_int]
user32.GetSystemMetrics.restype = ctypes.c_int

gdi32.CreateCompatibleDC.argtypes = [HDC]
gdi32.CreateCompatibleDC.restype = HDC
gdi32.CreateCompatibleBitmap.argtypes = [HDC, ctypes.c_int, ctypes.c_int]
gdi32.CreateCompatibleBitmap.restype = HANDLE
gdi32.SelectObject.argtypes = [HDC, HANDLE]
gdi32.SelectObject.restype = HANDLE
gdi32.BitBlt.argtypes = [HDC, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
                         HDC, ctypes.c_int, ctypes.c_int, wintypes.DWORD]
gdi32.BitBlt.restype = wintypes.BOOL
gdi32.StretchBlt.argtypes = [HDC, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
                             HDC, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
                             wintypes.DWORD]
gdi32.StretchBlt.restype = wintypes.BOOL
gdi32.SetStretchBltMode.argtypes = [HDC, ctypes.c_int]
gdi32.SetStretchBltMode.restype = ctypes.c_int
gdi32.SetBrushOrgEx.argtypes = [HDC, ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
gdi32.SetBrushOrgEx.restype = wintypes.BOOL
gdi32.GetDIBits.argtypes = [HDC, HANDLE, wintypes.UINT, wintypes.UINT, ctypes.c_void_p,
                            ctypes.POINTER(BITMAPINFO), wintypes.UINT]
gdi32.GetDIBits.restype = ctypes.c_int
gdi32.DeleteObject.argtypes = [HANDLE]
gdi32.DeleteObject.restype = wintypes.BOOL
gdi32.DeleteDC.argtypes = [HDC]
gdi32.DeleteDC.restype = wintypes.BOOL
gdi32.GetDeviceCaps.argtypes = [HDC, ctypes.c_int]
gdi32.GetDeviceCaps.restype = ctypes.c_int

user32.OpenInputDesktop.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
user32.OpenInputDesktop.restype = HANDLE
user32.CloseDesktop.argtypes = [HANDLE]
user32.CloseDesktop.restype = wintypes.BOOL
user32.GetUserObjectInformationW.argtypes = [
    HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)
]
user32.GetUserObjectInformationW.restype = wintypes.BOOL
user32.MapVirtualKeyW.argtypes = [wintypes.UINT, wintypes.UINT]
user32.MapVirtualKeyW.restype = wintypes.UINT
user32.EnumDisplayMonitors.argtypes = [HDC, ctypes.POINTER(wintypes.RECT),
                                       MONITORENUMPROC, wintypes.LPARAM]
user32.EnumDisplayMonitors.restype = wintypes.BOOL
user32.GetMonitorInfoW.argtypes = [HANDLE, ctypes.POINTER(MONITORINFO)]
user32.GetMonitorInfoW.restype = wintypes.BOOL
kernel32.ProcessIdToSessionId.argtypes = [wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
kernel32.ProcessIdToSessionId.restype = wintypes.BOOL
kernel32.WTSGetActiveConsoleSessionId.restype = wintypes.DWORD


def set_dpi_awareness():
    """必须在任何窗口/DC 操作之前调用，否则截屏尺寸和坐标都会错。"""
    try:
        user32.SetProcessDpiAwarenessContext.argtypes = [HANDLE]
        user32.SetProcessDpiAwarenessContext.restype = wintypes.BOOL
        if user32.SetProcessDpiAwarenessContext(HANDLE(-4)):  # PER_MONITOR_AWARE_V2
            return "per-monitor-v2"
    except Exception:
        pass
    try:
        ctypes.WinDLL("shcore").SetProcessDpiAwareness(2)
        return "per-monitor"
    except Exception:
        pass
    try:
        user32.SetProcessDPIAware()
        return "system"
    except Exception:
        return "none"


DPI_AWARENESS = set_dpi_awareness()


# --------------------------------------------------------------------------
# 输入注入
# --------------------------------------------------------------------------

INPUT_MOUSE = 0
INPUT_KEYBOARD = 1
MOUSEEVENTF_MOVE = 0x0001
MOUSEEVENTF_LEFTDOWN = 0x0002
MOUSEEVENTF_LEFTUP = 0x0004
MOUSEEVENTF_RIGHTDOWN = 0x0008
MOUSEEVENTF_RIGHTUP = 0x0010
MOUSEEVENTF_MIDDLEDOWN = 0x0020
MOUSEEVENTF_MIDDLEUP = 0x0040
MOUSEEVENTF_WHEEL = 0x0800
MOUSEEVENTF_ABSOLUTE = 0x8000
MOUSEEVENTF_VIRTUALDESK = 0x4000
KEYEVENTF_KEYUP = 0x0002
KEYEVENTF_UNICODE = 0x0004


class MOUSEINPUT(ctypes.Structure):
    _fields_ = [("dx", wintypes.LONG), ("dy", wintypes.LONG),
                ("mouseData", wintypes.DWORD), ("dwFlags", wintypes.DWORD),
                ("time", wintypes.DWORD), ("dwExtraInfo", ULONG_PTR)]


class KEYBDINPUT(ctypes.Structure):
    _fields_ = [("wVk", wintypes.WORD), ("wScan", wintypes.WORD),
                ("dwFlags", wintypes.DWORD), ("time", wintypes.DWORD),
                ("dwExtraInfo", ULONG_PTR)]


class HARDWAREINPUT(ctypes.Structure):
    _fields_ = [("uMsg", wintypes.DWORD), ("wParamL", wintypes.WORD),
                ("wParamH", wintypes.WORD)]


class _INPUTUNION(ctypes.Union):
    _fields_ = [("mi", MOUSEINPUT), ("ki", KEYBDINPUT), ("hi", HARDWAREINPUT)]


class INPUT(ctypes.Structure):
    _anonymous_ = ("u",)
    _fields_ = [("type", wintypes.DWORD), ("u", _INPUTUNION)]


user32.SendInput.argtypes = [wintypes.UINT, ctypes.POINTER(INPUT), ctypes.c_int]
user32.SendInput.restype = wintypes.UINT

VK = {
    "backspace": 0x08, "tab": 0x09, "enter": 0x0D, "return": 0x0D, "shift": 0x10,
    "ctrl": 0x11, "control": 0x11, "alt": 0x12, "pause": 0x13, "capslock": 0x14,
    "esc": 0x1B, "escape": 0x1B, "space": 0x20, "pageup": 0x21, "pagedown": 0x22,
    "end": 0x23, "home": 0x24, "left": 0x25, "up": 0x26, "right": 0x27, "down": 0x28,
    "printscreen": 0x2C, "insert": 0x2D, "delete": 0x2E, "win": 0x5B, "lwin": 0x5B,
    "rwin": 0x5C, "apps": 0x5D, "numlock": 0x90, "scrolllock": 0x91,
    "volumemute": 0xAD, "volumedown": 0xAE, "volumeup": 0xAF,
}
for _i in range(1, 25):
    VK["f%d" % _i] = 0x6F + _i


def _send(inputs):
    if not inputs:
        return 0
    arr = (INPUT * len(inputs))(*inputs)
    return user32.SendInput(len(inputs), arr, ctypes.sizeof(INPUT))


def _mouse(flags, dx=0, dy=0, data=0):
    item = INPUT()
    item.type = INPUT_MOUSE
    item.mi = MOUSEINPUT(dx, dy, data, flags, 0, 0)
    return item


def _vk_input(vk, up=False):
    # 带上扫描码：合成 Alt 等修饰键时若 wScan 为 0，系统会忽略组合键
    scan = user32.MapVirtualKeyW(vk, 0)
    item = INPUT()
    item.type = INPUT_KEYBOARD
    item.ki = KEYBDINPUT(vk, scan, KEYEVENTF_KEYUP if up else 0, 0, 0)
    return item


def _unicode_input(unit, up=False):
    item = INPUT()
    item.type = INPUT_KEYBOARD
    flags = KEYEVENTF_UNICODE | (KEYEVENTF_KEYUP if up else 0)
    item.ki = KEYBDINPUT(0, unit, flags, 0, 0)
    return item


def virtual_screen():
    return (
        user32.GetSystemMetrics(SM_XVIRTUALSCREEN),
        user32.GetSystemMetrics(SM_YVIRTUALSCREEN),
        user32.GetSystemMetrics(SM_CXVIRTUALSCREEN),
        user32.GetSystemMetrics(SM_CYVIRTUALSCREEN),
    )


def to_absolute(x, y):
    """把虚拟桌面像素坐标归一化到 0..65535，DPI 缩放与多屏偏移由系统自动处理。"""
    vx, vy, vw, vh = virtual_screen()
    ax = int(round((x - vx) * 65535.0 / max(1, vw - 1)))
    ay = int(round((y - vy) * 65535.0 / max(1, vh - 1)))
    return max(0, min(65535, ax)), max(0, min(65535, ay))


def mouse_move(x, y):
    ax, ay = to_absolute(x, y)
    return _send([_mouse(MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK, ax, ay)])


def mouse_click(x, y, button="left", double=False):
    ax, ay = to_absolute(x, y)
    base = MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK
    down, up = {
        "left": (MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP),
        "right": (MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP),
        "middle": (MOUSEEVENTF_MIDDLEDOWN, MOUSEEVENTF_MIDDLEUP),
    }[button]
    items = [_mouse(base, ax, ay)]
    for _ in range(2 if double else 1):
        items.append(_mouse(down))
        items.append(_mouse(up))
    return _send(items)


def mouse_wheel(delta):
    return _send([_mouse(MOUSEEVENTF_WHEEL, 0, 0, int(delta))])


def type_text(text):
    items = []
    for ch in text:
        code = ord(ch)
        if code > 0xFFFF:
            code -= 0x10000
            units = [0xD800 + (code >> 10), 0xDC00 + (code & 0x3FF)]
        else:
            units = [code]
        for unit in units:
            items.append(_unicode_input(unit))
            items.append(_unicode_input(unit, up=True))
    return _send(items)


def press_key(combo):
    """支持 'enter'、'ctrl+a'、'ctrl+shift+esc' 这类组合键。"""
    parts = [p.strip().lower() for p in combo.replace(" ", "").split("+") if p.strip()]
    if not parts:
        return 0
    vks = []
    for p in parts:
        if p in VK:
            vks.append(VK[p])
        elif len(p) == 1:
            vks.append(ord(p.upper()))
        else:
            raise ValueError("无法识别的按键：%s" % p)
    items_down = [_vk_input(v) for v in vks]
    # 修饰键和主键必须分两批发送：同一批内按下即抬起会被系统当成"菜单激活"而吞掉
    _send(items_down)
    time.sleep(0.03)
    return _send([_vk_input(v, up=True) for v in reversed(vks)])


# --------------------------------------------------------------------------
# 环境自检
# --------------------------------------------------------------------------

def desktop_state():
    handle = user32.OpenInputDesktop(0, False, DESKTOP_SWITCHDESKTOP)
    if not handle:
        return {"interactive": False, "locked": True, "desktop": None}
    try:
        buf = ctypes.create_unicode_buffer(256)
        need = wintypes.DWORD(0)
        ok = user32.GetUserObjectInformationW(
            handle, UOI_NAME, buf, ctypes.sizeof(buf), ctypes.byref(need)
        )
        name = buf.value if ok else ""
    finally:
        user32.CloseDesktop(handle)
    return {
        "interactive": True,
        "locked": name.lower() != "default",
        "desktop": name,
    }


def is_elevated():
    try:
        return bool(ctypes.WinDLL("shell32").IsUserAnAdmin())
    except Exception:
        return False


def monitors():
    found = []

    def callback(hmon, hdc, rect, lparam):
        info = MONITORINFO()
        info.cbSize = ctypes.sizeof(MONITORINFO)
        if user32.GetMonitorInfoW(hmon, ctypes.byref(info)):
            r = info.rcMonitor
            found.append({
                "left": r.left,
                "top": r.top,
                "width": r.right - r.left,
                "height": r.bottom - r.top,
                "primary": bool(info.dwFlags & 1),
            })
        return True

    user32.EnumDisplayMonitors(None, None, MONITORENUMPROC(callback), 0)
    return found


def system_dpi():
    hdc = user32.GetDC(None)
    if not hdc:
        return 96
    try:
        return gdi32.GetDeviceCaps(hdc, LOGPIXELSX) or 96
    finally:
        user32.ReleaseDC(None, hdc)


def collect_info():
    pid = kernel32.GetCurrentProcessId()
    session = wintypes.DWORD(0)
    kernel32.ProcessIdToSessionId(pid, ctypes.byref(session))
    console = kernel32.WTSGetActiveConsoleSessionId()
    state = desktop_state()
    vx, vy, vw, vh = virtual_screen()
    return {
        "node_version": NODE_VERSION,
        "hostname": socket.gethostname(),
        "user": os.environ.get("USERNAME", ""),
        "os": platform.platform(),
        "python": sys.version.split()[0],
        "arch": platform.machine(),
        "pid": pid,
        "interactive": state["interactive"],
        "locked": state["locked"],
        "desktop": state["desktop"],
        "elevated": is_elevated(),
        "dpi_awareness": DPI_AWARENESS,
        "system_dpi": system_dpi(),
        "monitors": monitors(),
        "virtual_screen": {"left": vx, "top": vy, "width": vw, "height": vh},
        "session_id": session.value,
        "active_console_session": console if console != 0xFFFFFFFF else -1,
        "on_console_session": session.value == console,
        "uptime": round(time.time() - STARTED_AT, 1),
        # S1 新增字段（契约 §6.2）
        "tls": {
            "enabled": TLS_ENABLED,
            "plaintext_debug": TLS_PLAINTEXT_DEBUG,
            "fingerprint": CERT_FINGERPRINT,
        },
        "identity_count": len(IDENTITIES),
    }


# --------------------------------------------------------------------------
# 截屏
# --------------------------------------------------------------------------

def _png_chunk(tag, data):
    return (struct.pack(">I", len(data)) + tag + data
            + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF))


def capture_png(monitor=-1, max_width=0, level=3):
    vx, vy, vw, vh = virtual_screen()
    x, y, w, h = vx, vy, vw, vh
    if monitor >= 0:
        ms = monitors()
        if monitor >= len(ms):
            raise ValueError("显示器索引超出范围：%d（共 %d 个）" % (monitor, len(ms)))
        m = ms[monitor]
        x, y, w, h = m["left"], m["top"], m["width"], m["height"]
    if w <= 0 or h <= 0:
        raise RuntimeError("无法获取屏幕尺寸")

    hdc_screen = user32.GetDC(None)
    if not hdc_screen:
        raise RuntimeError("GetDC 失败")
    hdc_mem = gdi32.CreateCompatibleDC(hdc_screen)
    hbmp = gdi32.CreateCompatibleBitmap(hdc_screen, w, h)
    old = gdi32.SelectObject(hdc_mem, hbmp)
    hdc_dst = None
    hbmp_dst = None
    try:
        if not gdi32.BitBlt(hdc_mem, 0, 0, w, h, hdc_screen, x, y, SRCCOPY):
            raise RuntimeError("BitBlt 失败，可能运行在无桌面的会话中")

        tw, th = w, h
        src_dc, src_bmp = hdc_mem, hbmp
        if max_width and w > max_width:
            ratio = float(max_width) / w
            tw, th = max(1, int(w * ratio)), max(1, int(h * ratio))
            hdc_dst = gdi32.CreateCompatibleDC(hdc_screen)
            hbmp_dst = gdi32.CreateCompatibleBitmap(hdc_screen, tw, th)
            gdi32.SelectObject(hdc_dst, hbmp_dst)
            gdi32.SetStretchBltMode(hdc_dst, HALFTONE)
            gdi32.SetBrushOrgEx(hdc_dst, 0, 0, None)
            if not gdi32.StretchBlt(hdc_dst, 0, 0, tw, th, hdc_mem, 0, 0, w, h, SRCCOPY):
                raise RuntimeError("缩放失败")
            src_dc, src_bmp = hdc_dst, hbmp_dst

        # 采集像素：负高度表示自上而下，32 位 BGRA
        info = BITMAPINFO()
        info.bmiHeader.biSize = ctypes.sizeof(BITMAPINFOHEADER)
        info.bmiHeader.biWidth = tw
        info.bmiHeader.biHeight = -th
        info.bmiHeader.biPlanes = 1
        info.bmiHeader.biBitCount = 32
        info.bmiHeader.biCompression = 0
        size = tw * th * 4
        buffer = ctypes.create_string_buffer(size)
        copied = gdi32.GetDIBits(src_dc, src_bmp, 0, th, buffer,
                                 ctypes.byref(info), DIB_RGB_COLORS)
        if copied != th:
            raise RuntimeError("GetDIBits 只返回 %d/%d 行" % (copied, th))

        pixels = bytearray(buffer.raw)
        del pixels[3::4]              # 去掉 alpha 通道
        stride = tw * 3
        for row in range(th):
            off = row * stride
            line = pixels[off:off + stride]
            line[0::3], line[2::3] = line[2::3], line[0::3]   # BGRA -> RGB
            pixels[off:off + stride] = line

        raw = bytearray()
        for row in range(th):
            raw += b"\x00"                                     # 每行过滤器类型 0
            raw += pixels[row * stride:(row + 1) * stride]

        ihdr = struct.pack(">IIBBBBB", tw, th, 8, 2, 0, 0, 0)
        return (b"\x89PNG\r\n\x1a\n"
                + _png_chunk(b"IHDR", ihdr)
                + _png_chunk(b"IDAT", zlib.compress(bytes(raw), level))
                + _png_chunk(b"IEND", b""))
    finally:
        if hbmp_dst:
            gdi32.DeleteObject(hbmp_dst)
        if hdc_dst:
            gdi32.DeleteDC(hdc_dst)
        gdi32.SelectObject(hdc_mem, old)
        gdi32.DeleteObject(hbmp)
        gdi32.DeleteDC(hdc_mem)
        user32.ReleaseDC(None, hdc_screen)


# --------------------------------------------------------------------------
# 命令任务
# --------------------------------------------------------------------------

JOBS = {}
JOBS_LOCK = threading.Lock()
CREATE_NO_WINDOW = 0x08000000


def _decode(raw):
    for enc in ("utf-8", "gbk"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", "replace")


def _trim(text):
    if text is None:
        return None
    if len(text) <= MAX_OUTPUT:
        return text
    return text[:MAX_OUTPUT] + "\n...[输出已截断]"


def build_argv(prompt, shell):
    if shell == "powershell":
        return ["powershell", "-NoProfile", "-NonInteractive",
                "-ExecutionPolicy", "Bypass", "-Command", prompt]
    if shell == "none":
        return prompt if isinstance(prompt, list) else prompt.split()
    return ["cmd", "/c", prompt]


def start_detached(prompt, shell="cmd", cwd=None):
    """启动 GUI 程序用：不等待、不接管输出，否则子进程会占住管道让任务一直挂着。"""
    DETACHED_PROCESS = 0x00000008
    proc = subprocess.Popen(
        build_argv(prompt, shell), cwd=cwd,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        stdin=subprocess.DEVNULL,
        creationflags=CREATE_NO_WINDOW | DETACHED_PROCESS,
    )
    return proc.pid


def _run_job(job_id, prompt, shell, cwd, timeout):
    argv = build_argv(prompt, shell)
    started = time.time()
    try:
        proc = subprocess.Popen(
            argv, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL, creationflags=CREATE_NO_WINDOW,
        )
        try:
            out, err = proc.communicate(timeout=timeout)
            status = "done"
        except subprocess.TimeoutExpired:
            proc.kill()
            out, err = proc.communicate()
            status = "timeout"
        with JOBS_LOCK:
            JOBS[job_id].update({
                "status": status,
                "exit_code": proc.returncode,
                "stdout": _trim(_decode(out)),
                "stderr": _trim(_decode(err)),
                "duration": round(time.time() - started, 3),
                "ended_at": time.time(),
            })
    except Exception as exc:
        with JOBS_LOCK:
            JOBS[job_id].update({
                "status": "failed",
                "exit_code": None,
                "stdout": "",
                "stderr": str(exc),
                "duration": round(time.time() - started, 3),
                "ended_at": time.time(),
            })


def start_job(prompt, shell="cmd", cwd=None, timeout=60):
    job_id = uuid.uuid4().hex[:12]
    with JOBS_LOCK:
        JOBS[job_id] = {
            "id": job_id, "status": "running", "cmd": prompt, "shell": shell,
            "cwd": cwd, "started_at": time.time(), "ended_at": None,
            "exit_code": None, "stdout": "", "stderr": "", "duration": None,
        }
    threading.Thread(target=_run_job, args=(job_id, prompt, shell, cwd, timeout),
                     daemon=True).start()
    return job_id


def get_job(job_id):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        return dict(job) if job else None


# --------------------------------------------------------------------------
# 文件操作
# --------------------------------------------------------------------------

def fs_list(path):
    entries = []
    with os.scandir(path) as it:
        for entry in it:
            try:
                stat = entry.stat(follow_symlinks=False)
                entries.append({
                    "name": entry.name,
                    "path": entry.path,
                    "dir": entry.is_dir(follow_symlinks=False),
                    "size": stat.st_size,
                    "mtime": round(stat.st_mtime, 3),
                })
            except OSError:
                continue
    entries.sort(key=lambda e: (not e["dir"], e["name"].lower()))
    return entries


def fs_read(path, max_bytes=2 * 1024 * 1024):
    with open(path, "rb") as fh:
        raw = fh.read(max_bytes + 1)
    truncated = len(raw) > max_bytes
    raw = raw[:max_bytes]
    result = {
        "path": os.path.abspath(path),
        "size": os.path.getsize(path),
        "truncated": truncated,
    }
    for enc in ("utf-8", "gbk"):
        try:
            result["encoding"] = enc
            result["text"] = raw.decode(enc)
            return result
        except UnicodeDecodeError:
            continue
    result["encoding"] = None
    result["data_b64"] = base64.b64encode(raw).decode("ascii")
    return result


def fs_write(path, text=None, data_b64=None, append=False):
    directory = os.path.dirname(os.path.abspath(path))
    if directory:
        os.makedirs(directory, exist_ok=True)
    if data_b64 is not None:
        payload = base64.b64decode(data_b64)
    else:
        payload = (text or "").encode("utf-8")
    with open(path, "wb" if not append else "ab") as fh:
        fh.write(payload)
    return {"path": os.path.abspath(path), "written": len(payload)}


def fs_stat(path):
    stat = os.stat(path)
    return {
        "path": os.path.abspath(path),
        "size": stat.st_size,
        "dir": os.path.isdir(path),
        "mtime": round(stat.st_mtime, 3),
        "ctime": round(stat.st_ctime, 3),
    }


# --------------------------------------------------------------------------
# 自更新
# --------------------------------------------------------------------------

def schedule_restart(delay=2):
    script = os.path.abspath(__file__)
    bat = os.path.join(tempfile.gettempdir(), "xd-node-restart.bat")
    args = " ".join('"%s"' % a for a in sys.argv[1:])
    content = (
        "@echo off\r\n"
        'cd /d "%s"\r\n'
        "ping -n %d 127.0.0.1 >nul\r\n"
        'start "" /min "%s" "%s" %s\r\n'
        % (os.getcwd(), int(delay) + 1, sys.executable, script, args)
    )
    with open(bat, "w", encoding="mbcs", errors="replace") as fh:
        fh.write(content)
    DETACHED_PROCESS = 0x00000008
    subprocess.Popen(["cmd", "/c", bat],
                     creationflags=DETACHED_PROCESS | CREATE_NO_WINDOW,
                     close_fds=True)


def self_update(source):
    target = os.path.abspath(__file__)
    temp = target + ".new"
    with open(temp, "wb") as fh:
        fh.write(source)
    try:
        compile(source, temp, "exec")
    except SyntaxError as exc:
        os.remove(temp)
        raise ValueError("源码语法错误：%s" % exc)
    os.replace(temp, target)
    schedule_restart()
    return {"path": target, "bytes": len(source)}


# --------------------------------------------------------------------------
# 配置与多身份（契约 §2 / §9.1）
# --------------------------------------------------------------------------

def default_config_path():
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    return os.path.join(base, "CrossDevice", "node.json")


def atomic_write_json(path, data):
    """原子写 JSON：同目录临时文件 + os.replace（契约 §9.1/§10.2）。"""
    directory = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".tmp-node-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=2)
            fh.write("\n")
        os.replace(tmp, path)
    except BaseException:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise


def normalize_identities(raw):
    """规范化身份列表（契约 §9.1）：同 name 冲突取靠后者并告警；上限 16。"""
    items = {}
    if isinstance(raw, list):
        for item in raw:
            if not isinstance(item, dict):
                sys.stderr.write("[警告] node.json 身份条目格式非法，已跳过\n")
                continue
            name = item.get("name")
            token = item.get("token")
            if (not isinstance(name, str) or not 1 <= len(name) <= 64
                    or not isinstance(token, str) or not token):
                sys.stderr.write("[警告] node.json 身份条目缺少有效 name/token，已跳过\n")
                continue
            if name in items:
                sys.stderr.write("[警告] 身份名重复：%s（以列表靠后者为准）\n" % name)
            items[name] = token
    identities = [{"name": n, "token": t} for n, t in items.items()]
    if len(identities) > MAX_IDENTITIES:
        sys.stderr.write("[警告] 身份数超过上限 %d，仅保留前 %d 个\n"
                         % (MAX_IDENTITIES, MAX_IDENTITIES))
        identities = identities[:MAX_IDENTITIES]
    return identities


def load_config(args):
    """加载 / 迁移 node.json（契约 §9.1），返回 (cfg, identities, 配置文件路径)。

    - 旧格式 {"token": X} 首次运行自动迁移为 tokens=[{"name":"default","token":X}]
      并原子写回；未知键（如 port）原样保留。
    - --token 覆盖 default 身份令牌，其余身份保留，结果写回配置。
    - 无任何令牌且未传 --token：生成 32 hex 新令牌作为 default。
    """
    path = args.config or default_config_path()
    cfg = {}
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                cfg = json.load(fh)
        except Exception as exc:
            # 配置损坏时拒绝静默重建令牌（安全相关，宁可失败退出）
            raise SystemExit("配置文件解析失败：%s（%s）\n请修复或删除该文件后重试。"
                             % (path, exc))
    if not isinstance(cfg, dict):
        raise SystemExit("配置文件格式非法（应为 JSON 对象）：%s" % path)

    changed = False
    if "tokens" in cfg:
        identities = normalize_identities(cfg.get("tokens"))
    elif isinstance(cfg.get("token"), str) and cfg.get("token"):
        # 旧格式迁移：单 token -> tokens 列表；未知键保留
        identities = [{"name": DEFAULT_IDENTITY_NAME, "token": cfg["token"]}]
        del cfg["token"]
        changed = True
    else:
        identities = []

    if not identities and not args.token:
        # 无任何令牌：生成 32 hex 新令牌作为 default（契约 §9.1，D38）
        identities = [{"name": DEFAULT_IDENTITY_NAME, "token": uuid.uuid4().hex}]
        changed = True

    if args.token:
        # --token：设置/覆盖 default 身份，其余身份保留（契约 §9.1）
        for item in identities:
            if item["name"] == DEFAULT_IDENTITY_NAME:
                if item["token"] != args.token:
                    item["token"] = args.token
                    changed = True
                break
        else:
            identities.insert(0, {"name": DEFAULT_IDENTITY_NAME, "token": args.token})
            changed = True

    if changed:
        base_dir = os.path.dirname(os.path.abspath(path))
        cfg.setdefault("version", 1)
        cfg["tokens"] = identities
        cfg.setdefault("tls", {
            "cert": os.path.join(base_dir, "tls", "cert.pem"),
            "key": os.path.join(base_dir, "tls", "key.pem"),
        })
        cfg.setdefault("audit", {"retention_days": 180})
        atomic_write_json(path, cfg)
    return cfg, identities, path


def match_identity(supplied):
    """令牌 -> 身份名；不匹配返回 None。一律常量时间比较（契约 §2.1，D38）。"""
    if not supplied:
        return None
    supplied_b = supplied.encode("utf-8", "replace")
    for item in IDENTITIES:
        if hmac.compare_digest(supplied_b, item["token"].encode("utf-8")):
            return item["name"]
    return None


# --------------------------------------------------------------------------
# TLS 传输（契约 §4）
# --------------------------------------------------------------------------

CERT_GUIDANCE = (
    "[错误] TLS 证书/私钥缺失或加载失败，node 无法以 HTTPS 启动。\n"
    "  证书路径：%(cert)s\n"
    "  私钥路径：%(key)s\n"
    "请先用证书工具生成自签证书（Windows PowerShell 5.1 即可，零第三方依赖）：\n"
    "  powershell -NoProfile -ExecutionPolicy Bypass -File tools\\gen_cert.ps1\n"
    "  默认生成到 %%LOCALAPPDATA%%\\CrossDevice\\tls\\cert.pem 与 key.pem；\n"
    "  可用 -OutDir 指定其他目录，再用 --cert/--key（或 node.json 的 tls.cert/tls.key）指向对应文件。"
)


def resolve_tls_paths(args, cfg, base_dir):
    """证书路径优先级（契约 §4.2）：CLI --cert/--key > node.json tls.* > <config 目录>/tls/。"""
    if bool(args.cert) != bool(args.key):
        raise SystemExit("--cert 与 --key 必须同时提供")
    tls_cfg = cfg.get("tls") if isinstance(cfg.get("tls"), dict) else {}
    cert_cfg = tls_cfg.get("cert") if isinstance(tls_cfg.get("cert"), str) else ""
    key_cfg = tls_cfg.get("key") if isinstance(tls_cfg.get("key"), str) else ""
    cert = args.cert or cert_cfg or os.path.join(base_dir, "tls", "cert.pem")
    key = args.key or key_cfg or os.path.join(base_dir, "tls", "key.pem")
    return cert, key


def build_ssl_context(cert, key):
    """构建仅接受 TLS 1.3 的服务端 SSLContext；失败打印指引并退出（契约 §4.2）。"""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    try:
        ctx.load_cert_chain(cert, key)
    except Exception as exc:
        raise SystemExit((CERT_GUIDANCE % {"cert": cert, "key": key})
                         + "\n失败原因：%s" % exc)
    return ctx


def cert_fingerprint_sha256(cert_path):
    """证书 DER 的 SHA-256 指纹，小写 64 hex（契约 §4.1）。失败返回 None。"""
    try:
        with open(cert_path, "rb") as fh:
            raw = fh.read()
        if b"-----BEGIN CERTIFICATE-----" in raw:
            start = raw.index(b"-----BEGIN CERTIFICATE-----") \
                + len(b"-----BEGIN CERTIFICATE-----")
            end = raw.index(b"-----END CERTIFICATE-----", start)
            der = base64.b64decode(b"".join(raw[start:end].split()))
        else:
            der = raw                      # 直接是 DER 编码
        return hashlib.sha256(der).hexdigest()
    except Exception as exc:
        sys.stderr.write("[警告] 计算证书指纹失败：%s\n" % exc)
        return None


class NodeHTTPServer(ThreadingHTTPServer):
    """带可选 TLS 的多线程 HTTP 服务。

    TLS 模式下在 accept 阶段完成握手：明文请求打到 TLS 端口产生的握手
    异常在这里捕获（verbose 记日志、关闭连接、继续服务），不使服务崩溃。
    """

    def __init__(self, address, handler, ssl_context=None):
        super().__init__(address, handler)
        self.ssl_context = ssl_context

    def get_request(self):
        sock, addr = self.socket.accept()
        if self.ssl_context is None:
            return sock, addr
        try:
            sock.settimeout(15)            # 握手限时，防空闲连接卡住 accept 循环
            tls_sock = self.ssl_context.wrap_socket(sock, server_side=True)
            tls_sock.settimeout(None)      # 握手完成后恢复阻塞模式
            return tls_sock, addr
        except (ssl.SSLError, OSError) as exc:
            # 典型场景：明文 HTTP 请求打到 TLS 端口。记录后抛出，
            # socketserver 主循环会按 OSError 吞掉，服务继续。
            if VERBOSE:
                sys.stderr.write("[%s] TLS 握手失败（%s）：%s\n"
                                 % (time.strftime("%H:%M:%S"), addr[0], exc))
            try:
                sock.close()
            except OSError:
                pass
            raise


# --------------------------------------------------------------------------
# 防重放（契约 §3）
# --------------------------------------------------------------------------

def nonce_check_and_store(nonce, ts):
    """nonce 查重与写入同一把锁内完成（§3.2）；顺带清理过期项。重复返回 False。"""
    now = time.time()
    with NONCES_LOCK:
        if NONCES:
            for key in [k for k, exp in NONCES.items() if exp <= now]:
                del NONCES[key]
        if nonce in NONCES:
            return False
        # 过期时刻 = 时间戳滑出窗口的时刻；此后重放会被时间窗检查拦截
        NONCES[nonce] = ts + REPLAY_WINDOW
        return True


# --------------------------------------------------------------------------
# 审计日志（契约 §8）
# --------------------------------------------------------------------------

_TOKEN_IN_TEXT = re.compile(r"(^|[?&])token=[^&\s]*")


def sanitize_secret(text):
    """查询串令牌脱敏：token=*** （契约 §8.2，B3）。令牌值永不落盘。"""
    if not text:
        return text
    return _TOKEN_IN_TEXT.sub(lambda m: m.group(1) + "token=***", text)


def set_audit_paths(base_dir, retention_days):
    global AUDIT_DIR, AUDIT_RETENTION_DAYS
    AUDIT_DIR = os.path.join(base_dir, "audit")
    try:
        retention_days = int(retention_days)
    except (TypeError, ValueError):
        retention_days = 180
    AUDIT_RETENTION_DAYS = max(1, retention_days)


def audit_file_path(date_obj):
    return os.path.join(AUDIT_DIR, "audit-%s.jsonl" % date_obj.strftime("%Y%m%d"))


def write_audit_entry(identity, action, target, result, code, client):
    """追加一条审计（§8.2 冻结 schema）；写失败仅 stderr 告警，不影响业务。"""
    entry = {
        "ts": round(time.time(), 3),
        "time": datetime.now().astimezone().isoformat(timespec="seconds"),
        "identity": identity,
        "action": action,
        "target": target,
        "result": result,
        "code": code,
        "client": client,
    }
    line = json.dumps(entry, ensure_ascii=False)
    with AUDIT_LOCK:
        try:
            os.makedirs(AUDIT_DIR, exist_ok=True)
            with open(audit_file_path(datetime.now()), "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        except Exception as exc:
            sys.stderr.write("[警告] 审计日志写入失败：%s\n" % exc)


def cleanup_audit_files():
    """启动时按文件名日期清理超过留存期的审计文件（§8.1，默认 180 天）。"""
    try:
        names = os.listdir(AUDIT_DIR)
    except OSError:
        return
    today = datetime.now().date()
    for name in names:
        m = re.fullmatch(r"audit-(\d{8})\.jsonl", name)
        if not m:
            continue
        try:
            file_date = datetime.strptime(m.group(1), "%Y%m%d").date()
        except ValueError:
            continue
        if (today - file_date).days > AUDIT_RETENTION_DAYS:
            try:
                os.remove(os.path.join(AUDIT_DIR, name))
                if VERBOSE:
                    sys.stderr.write("[信息] 已清理过期审计文件：%s\n" % name)
            except OSError as exc:
                sys.stderr.write("[警告] 审计文件清理失败：%s（%s）\n" % (name, exc))


def _list_audit_files():
    """列出审计目录中全部 audit-YYYYMMDD.jsonl，按日期升序。"""
    try:
        names = os.listdir(AUDIT_DIR)
    except OSError:
        return []
    out = []
    for name in names:
        m = re.fullmatch(r"audit-(\d{8})\.jsonl", name)
        if m:
            out.append((m.group(1), os.path.join(AUDIT_DIR, name)))
    out.sort()
    return out


def _read_audit_file(path):
    entries = []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line_no, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                except ValueError:
                    sys.stderr.write("[警告] 审计文件存在坏行，已跳过：%s:%d\n"
                                     % (path, line_no))
                    continue
                if isinstance(item, dict):
                    entries.append(item)
    except FileNotFoundError:
        pass
    except OSError as exc:
        sys.stderr.write("[警告] 审计文件读取失败：%s（%s）\n" % (path, exc))
    return entries


class ParamError(ValueError):
    """查询参数非法（/v1/audit 返回 400 BAD_REQUEST）。"""


def query_audit(query):
    """实现 GET /v1/audit（契约 §7.2）。"""
    since = until = None
    if "since" in query:
        try:
            since = float(query["since"])
        except (TypeError, ValueError):
            raise ParamError("since 参数必须是 Unix 时间戳（秒）")
    if "until" in query:
        try:
            until = float(query["until"])
        except (TypeError, ValueError):
            raise ParamError("until 参数必须是 Unix 时间戳（秒）")
    if since is not None and until is not None and since > until:
        since, until = until, since
    limit = 200
    if "limit" in query:
        try:
            limit = int(query["limit"])
        except (TypeError, ValueError):
            raise ParamError("limit 参数必须是整数")
        if not 1 <= limit <= 1000:
            raise ParamError("limit 参数超出范围（1–1000）")
    identity = query.get("identity")
    action_key = (query.get("action") or "").lower()

    # 选取要读取的审计文件（§7.2：默认仅当天；给定 since/until 时读覆盖的日期范围）
    if since is None and until is None:
        files = [audit_file_path(datetime.now().date())]
    elif since is not None:
        today = datetime.now().date()
        oldest = today - timedelta(days=AUDIT_RETENTION_DAYS)
        try:
            start = datetime.fromtimestamp(since).date()
            end = datetime.fromtimestamp(until).date() if until is not None else today
        except (OverflowError, OSError, ValueError):
            raise ParamError("since/until 超出可表示的时间范围")
        if start > end:
            start, end = end, start
        start, end = max(start, oldest), min(end, today)
        wanted = {start + timedelta(days=i) for i in range((end - start).days + 1)}
        files = [p for d, p in _list_audit_files()
                 if datetime.strptime(d, "%Y%m%d").date() in wanted]
    else:
        # 仅 until：扫描现存全部审计文件，ts 过滤兜底
        files = [p for _, p in _list_audit_files()]

    entries = []
    for path in files:
        for item in _read_audit_file(path):
            ts = item.get("ts")
            if not isinstance(ts, (int, float)):
                continue
            if since is not None and ts < since:
                continue
            if until is not None and ts > until:
                continue
            if identity is not None and item.get("identity") != identity:
                continue
            if action_key and action_key not in str(item.get("action", "")).lower():
                continue
            entries.append(item)
    entries.sort(key=lambda e: e["ts"])            # 时间升序（§7.2）
    if len(entries) > limit:
        entries = entries[-limit:]                 # 取过滤结果中最新的 limit 条
    return {"entries": entries, "count": len(entries)}


# --------------------------------------------------------------------------
# HTTP 服务
# --------------------------------------------------------------------------

def is_private(ip):
    if ip in ("127.0.0.1", "::1"):
        return True
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        a, b = int(parts[0]), int(parts[1])
    except ValueError:
        return False
    return (a == 10 or a == 127
            or (a == 172 and 16 <= b <= 31)
            or (a == 192 and b == 168)
            or (a == 169 and b == 254))


KNOWN_GET_PATHS = frozenset({
    "/", "/v1/health", "/v1/info", "/v1/fs/list", "/v1/fs/read",
    "/v1/fs/stat", "/v1/screen", "/v1/audit",
})
KNOWN_POST_PATHS = frozenset({"/v1/exec", "/v1/input", "/v1/fs/write", "/v1/self-update"})


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "xd-node/" + NODE_VERSION

    # 每请求重置的审计状态（见 dispatch）
    _resp_status = None
    _resp_code = None
    _audit_target = ""

    def log_message(self, fmt, *args):
        if VERBOSE:
            sys.stderr.write("[%s] %s\n" % (time.strftime("%H:%M:%S"), fmt % args))

    # ---- 响应helper ----
    def send_json(self, payload, code=200):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self._resp_status = code
        self._resp_code = None if code < 400 else (payload.get("error") or {}).get("code")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def ok(self, data):
        self.send_json({"ok": True, "data": data})

    def fail(self, code, message, status=400):
        self.send_json({"ok": False, "error": {"code": code, "message": message}}, status)

    def read_body(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        if length > MAX_BODY:
            raise ValueError("请求体过大")
        return json.loads(self.rfile.read(length).decode("utf-8"))

    # ---- 审计辅助 ----
    def set_target(self, text):
        """设置本请求的审计目标摘要（§8.3）。"""
        self._audit_target = text

    def _is_known_path(self, path):
        return (path in KNOWN_GET_PATHS or path in KNOWN_POST_PATHS
                or path.startswith("/v1/job/"))

    def audit(self, parsed, identity, result, code):
        """写一条审计（§8）。调用方保证已通过来源校验。"""
        if result in (400, 401, 403, 409):
            target = ""                       # 校验失败：目标摘要为空（§8.3）
        else:
            target = sanitize_secret(self._audit_target)
        if self._is_known_path(parsed.path):
            action = "%s %s" % (self.command, parsed.path)
        else:
            # 未通过路由校验：记录实际请求行，查询串脱敏（§8.2）
            action = "%s %s" % (self.command, sanitize_secret(self.path))
        write_audit_entry(identity=identity, action=action, target=target,
                          result=result, code=code, client=self.client_address[0])

    # ---- 鉴权与来源校验（§2.3：①来源 → ②身份 → ③防重放）----
    def guard(self, parsed):
        """通过返回身份名；失败返回 None（已发送响应并已审计）。"""
        client = self.client_address[0]
        # ① 来源校验：先于一切（S-01）；来源校验失败不在审计记录范围（§8.2）
        if not is_private(client):
            self.fail("FORBIDDEN", "仅允许局域网访问：%s" % client, 403)
            return None
        # ② 身份校验：请求头优先，查询串过渡兼容（§2.2）
        supplied = self.headers.get("X-Auth-Token") or (
            parse_qs(parsed.query).get("token") or [""])[0]
        identity = match_identity(supplied)
        if identity is None:
            self.audit(parsed, identity="", result=401, code="UNAUTHORIZED")
            self.fail("UNAUTHORIZED", "令牌无效", 401)
            return None
        # ③ 防重放校验：通过后才进入路由；未通过②的请求不会走到这里（不消耗 nonce）
        verdict = self.check_replay()
        if verdict is not None:
            status, code, message = verdict
            self.audit(parsed, identity=identity, result=status, code=code)
            self.fail(code, message, status)
            return None
        return identity

    def check_replay(self):
        """防重放校验（§3）。通过返回 None；失败返回 (status, code, message)。"""
        ts_raw = self.headers.get("X-Timestamp")
        nonce = self.headers.get("X-Nonce")
        if not ts_raw or not nonce:
            return (400, "BAD_REQUEST", "缺少防重放头：X-Timestamp / X-Nonce")
        try:
            ts = float(ts_raw.strip())
        except (TypeError, ValueError):
            return (409, "REPLAY_DETECTED", "X-Timestamp 无法解析为时间戳")
        if not math.isfinite(ts) or abs(time.time() - ts) > REPLAY_WINDOW:
            return (409, "REPLAY_DETECTED",
                    "时间戳超出允许窗口（±%d 秒）" % REPLAY_WINDOW)
        if not 1 <= len(nonce) <= NONCE_MAX_LEN:
            return (400, "BAD_REQUEST",
                    "X-Nonce 长度非法（1–%d 字符）" % NONCE_MAX_LEN)
        if not nonce_check_and_store(nonce, ts):
            return (409, "REPLAY_DETECTED", "重复的 nonce（疑似重放）")
        return None

    # ---- 分发入口：鉴权 → 路由 → 审计 ----
    def dispatch(self, router):
        self._resp_status = None
        self._resp_code = None
        self._audit_target = ""
        parsed = urlparse(self.path)
        identity = self.guard(parsed)
        if identity is None:
            return
        try:
            router(parsed)
        except Exception as exc:
            self.fail("INTERNAL", str(exc), 500)
        finally:
            self.audit(parsed, identity=identity,
                       result=self._resp_status if self._resp_status is not None else 500,
                       code=self._resp_code)

    def do_GET(self):
        self.dispatch(self.route_get)

    def do_POST(self):
        self.dispatch(self.route_post)

    # 未实现的 HTTP 方法与未知接口一样走包络错误，不裸抛 HTML 错误页（§1.3）
    def do_HEAD(self):
        self.dispatch(self._unknown_route)

    def do_PUT(self):
        self.dispatch(self._unknown_route)

    def do_DELETE(self):
        self.dispatch(self._unknown_route)

    def do_PATCH(self):
        self.dispatch(self._unknown_route)

    def do_OPTIONS(self):
        self.dispatch(self._unknown_route)

    def _unknown_route(self, parsed):
        self.fail("NOT_FOUND",
                  "未知接口或方法：%s %s" % (self.command, parsed.path), 404)

    def route_get(self, parsed):
        path = parsed.path
        query = {k: v[0] for k, v in parse_qs(parsed.query).items()}

        if path in ("/", "/v1/health"):
            self.ok({"status": "up", "node_version": NODE_VERSION})
            return

        if path == "/v1/info":
            self.ok(collect_info())
            return

        if path == "/v1/audit":
            # S1 新增（契约 §7.2）：审计查询，target 记录脱敏后的查询串
            self.set_target("filter=" + sanitize_secret(parsed.query))
            try:
                self.ok(query_audit(query))
            except ParamError as exc:
                self.fail("BAD_REQUEST", str(exc), 400)
            return

        if path.startswith("/v1/job/"):
            job_id = path.rsplit("/", 1)[-1]
            wait = min(float(query.get("wait", 0)), 120.0)
            deadline = time.time() + wait
            while True:
                job = get_job(job_id)
                if job is None:
                    self.fail("NOT_FOUND", "任务不存在：%s" % job_id, 404)
                    return
                if job["status"] != "running" or time.time() >= deadline:
                    self.ok(job)
                    return
                time.sleep(0.15)

        if path == "/v1/fs/list":
            list_path = query.get("path", ".")
            self.set_target("path=" + list_path)
            self.ok({"entries": fs_list(list_path)})
            return

        if path == "/v1/fs/read":
            read_path = query["path"]
            self.set_target("path=" + read_path)
            self.ok(fs_read(read_path,
                            int(query.get("max", 2 * 1024 * 1024))))
            return

        if path == "/v1/fs/stat":
            stat_path = query["path"]
            self.set_target("path=" + stat_path)
            self.ok(fs_stat(stat_path))
            return

        if path == "/v1/screen":
            monitor = int(query.get("monitor", -1))
            max_width = int(query.get("max_width", 0))
            self.set_target("monitor=%d max_width=%d" % (monitor, max_width))
            png = capture_png(
                monitor=monitor,
                max_width=max_width,
                level=int(query.get("level", 3)),
            )
            self._resp_status = 200
            self._resp_code = None
            self.send_response(200)
            self.send_header("Content-Type", "image/png")
            self.send_header("Content-Length", str(len(png)))
            self.end_headers()
            self.wfile.write(png)
            return

        self.fail("NOT_FOUND", "未知接口：%s" % path, 404)

    def route_post(self, parsed):
        path = parsed.path

        if path == "/v1/exec":
            body = self.read_body()
            if not body.get("cmd"):
                self.fail("BAD_REQUEST", "缺少 cmd")
                return
            cmd_text = body["cmd"] if isinstance(body["cmd"], str) else str(body["cmd"])
            self.set_target("cmd=" + cmd_text[:200])
            if body.get("detach"):
                pid = start_detached(body["cmd"], body.get("shell", "cmd"),
                                     body.get("cwd"))
                self.ok({"detached": True, "pid": pid})
                return
            job_id = start_job(
                body["cmd"],
                shell=body.get("shell", "cmd"),
                cwd=body.get("cwd"),
                timeout=float(body.get("timeout", 60)),
            )
            self.ok({"job_id": job_id})
            return

        if path == "/v1/input":
            body = self.read_body()
            actions = body.get("actions")
            if isinstance(actions, list):
                self.set_target("actions=" + ",".join(
                    a.get("type", "") if isinstance(a, dict) else "" for a in actions))
            results = []
            for action in body.get("actions", []):
                kind = action.get("type")
                if kind in ("click", "doubleclick"):
                    button = action.get("button", "left")
                    if kind == "doubleclick":
                        results.append(mouse_click(action["x"], action["y"], button, True))
                    else:
                        results.append(mouse_click(action["x"], action["y"], button))
                elif kind == "move":
                    results.append(mouse_move(action["x"], action["y"]))
                elif kind == "wheel":
                    results.append(mouse_wheel(action.get("delta", 120)))
                elif kind == "type":
                    results.append(type_text(action.get("text", "")))
                elif kind == "key":
                    results.append(press_key(action.get("key", "")))
                else:
                    self.fail("BAD_REQUEST", "未知动作：%s" % kind)
                    return
            state = desktop_state()
            self.ok({
                "sent": results,
                "interactive": state["interactive"],
                "locked": state["locked"],
            })
            return

        if path == "/v1/fs/write":
            body = self.read_body()
            write_path = body.get("path")
            if write_path is not None:
                if body.get("data_b64") is not None:
                    payload_len = len(base64.b64decode(body["data_b64"]))
                else:
                    payload_len = len((body.get("text") or "").encode("utf-8"))
                self.set_target("path=%s bytes=%d" % (write_path, payload_len))
            self.ok(fs_write(body["path"], body.get("text"),
                             body.get("data_b64"), bool(body.get("append"))))
            return

        if path == "/v1/self-update":
            body = self.read_body()
            raw = base64.b64decode(body["source_b64"])
            try:
                result = self_update(raw)
            except ValueError as exc:
                # 语法校验失败返回 400（契约 §6.8）
                self.fail("BAD_REQUEST", str(exc), 400)
                return
            self.set_target("bytes=%d" % result["bytes"])
            self.ok(result)
            threading.Timer(0.4, lambda: os._exit(0)).start()
            return

        self.fail("NOT_FOUND", "未知接口：%s" % path, 404)


# --------------------------------------------------------------------------
# 启动
# --------------------------------------------------------------------------

def local_addresses():
    found = []
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if ip not in found:
                found.append(ip)
    except Exception:
        pass
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.connect(("8.8.8.8", 80))
        ip = probe.getsockname()[0]
        probe.close()
        if ip not in found:
            found.append(ip)
    except Exception:
        pass
    return [ip for ip in found if is_private(ip)]


def main():
    global VERBOSE, IDENTITIES, TOKEN
    global TLS_ENABLED, TLS_PLAINTEXT_DEBUG, CERT_FINGERPRINT
    parser = argparse.ArgumentParser(description="CrossDevice 执行器")
    parser.add_argument("--port", type=int, default=8788)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--token", default=None,
                        help="设置/覆盖 default 身份令牌；不传则复用配置或自动生成（32 hex）")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--config", default=None,
                        help="node.json 路径（默认 %%LOCALAPPDATA%%\\CrossDevice\\node.json；"
                             "tls/audit 默认目录相对该文件所在目录解析）")
    parser.add_argument("--cert", default=None, help="TLS 证书 PEM 路径（优先于配置）")
    parser.add_argument("--key", default=None, help="TLS 私钥 PEM 路径（优先于配置）")
    parser.add_argument("--debug-plaintext", action="store_true",
                        help="调试：主监听端口改以明文 HTTP 服务（默认关闭，D31）")
    args = parser.parse_args()

    VERBOSE = args.verbose

    # ---- 配置与身份（契约 §2 / §9.1）----
    cfg, identities, config_file = load_config(args)
    IDENTITIES = identities
    TOKEN = next((i["token"] for i in identities if i["name"] == DEFAULT_IDENTITY_NAME),
                 identities[0]["token"] if identities else "")
    base_dir = os.path.dirname(os.path.abspath(config_file))
    audit_cfg = cfg.get("audit") if isinstance(cfg.get("audit"), dict) else {}
    set_audit_paths(base_dir, audit_cfg.get("retention_days", 180))
    cleanup_audit_files()

    # ---- TLS（契约 §4.2）----
    ssl_context = None
    if args.debug_plaintext:
        TLS_PLAINTEXT_DEBUG = True          # 明文调试：主端口直接以 HTTP 服务（D31）
    else:
        cert, key = resolve_tls_paths(args, cfg, base_dir)
        ssl_context = build_ssl_context(cert, key)   # 失败 -> 打印生成指引并退出
        TLS_ENABLED = True
        CERT_FINGERPRINT = cert_fingerprint_sha256(cert)

    state = desktop_state()
    info = collect_info()

    # 热更新后旧进程可能还没释放端口，重试等待而不是直接失败
    server = None
    last_error = None
    for _ in range(24):
        try:
            server = NodeHTTPServer((args.host, args.port), Handler,
                                    ssl_context=ssl_context)
            break
        except OSError as exc:
            last_error = exc
            time.sleep(0.5)
    if server is None:
        raise SystemExit("端口 %d 无法监听：%s" % (args.port, last_error))
    server.daemon_threads = True

    # ---- 启动横幅（契约 §7.1：保留既有行，追加 TLS/身份，访问地址改 https://）----
    line = "=" * 62
    print(line)
    print(" CrossDevice 执行器 v%s" % NODE_VERSION)
    print(line)
    print(" 主机名    : %s" % info["hostname"])
    print(" 用户      : %s" % info["user"])
    print(" 监听      : %s:%d" % (args.host, args.port))
    if TLS_ENABLED:
        print(" TLS       : 启用（SHA-256 指纹 %s…）" % (CERT_FINGERPRINT or "")[:16])
    else:
        print(" TLS       : 关闭（--debug-plaintext 调试模式）")
    print(" 身份      : %d 个（%s）" % (len(IDENTITIES),
                                        ", ".join(i["name"] for i in IDENTITIES)))
    print(" 令牌      : %s" % TOKEN)
    print(" 交互会话  : %s" % ("是" if state["interactive"] else "否（截屏/键鼠不可用）"))
    print(" 锁屏      : %s" % ("是（GUI 操作不可用）" if state["locked"] else "否"))
    print(" 提权      : %s" % ("是" if info["elevated"] else "否"))
    print(" DPI 感知  : %s (系统 %d DPI)" % (info["dpi_awareness"], info["system_dpi"]))
    print(" 显示器    : %d 个" % len(info["monitors"]))
    scheme = "http" if TLS_PLAINTEXT_DEBUG else "https"
    for ip in local_addresses():
        print(" 访问地址  : %s://%s:%d" % (scheme, ip, args.port))
    print(line)
    if TLS_PLAINTEXT_DEBUG:
        print(" 警告：明文调试模式已开启（--debug-plaintext），传输不加密，")
        print("      令牌与数据可被窃听；仅供本机调试，用后请关闭该选项重新启动。")
        print(line)
    if not state["interactive"]:
        print(" 警告：当前不在交互式桌面会话，截屏与键鼠注入将失败。")
        print("      请以登录用户的普通进程方式启动，不要注册为 Windows 服务。")
        print(line)
    print(" 按 Ctrl+C 停止")
    print()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
