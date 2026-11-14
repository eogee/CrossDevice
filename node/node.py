#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CrossDevice 执行器（node）

被控端常驻进程：只做"手和眼"，不含任何 AI 逻辑。
零第三方依赖，仅使用 Python 标准库 + ctypes 调用 Win32 API。

提供能力：
    /v1/health        健康检查（S3 增 rollback_flag 回滚标记）
    /v1/info          环境自检（S3 增 device_id / elevated_resident）
    /v1/exec          启动命令任务，返回 job_id（创建即写入任务历史）
    /v1/job/<id>      查询任务结果（wait 长轮询；内存 miss 后查任务历史库）
    /v1/fs/list       列目录
    /v1/fs/read       读文件
    /v1/fs/write      写文件（S2 起受工作空间白名单约束）
    /v1/fs/stat       文件信息
    /v1/fs/checksum   分块流式 MD5 校验和（S2 新增）
    /v1/fs/download   流式下载，支持 Range 206（S2 新增）
    /v1/fs/upload/*   上传三段式 begin/chunk/commit/abort，断点续传（S2 新增）
    /v1/fs/delete     删除文件（白名单 + confirm 显式确认，S2 新增）
    /v1/fs/mkdir      递归建目录（白名单，S2 新增）
    /v1/fs/move       移动（src/dst 双白名单，S2 新增）
    /v1/task/list     任务历史列表（一期仅本人可见，S2 新增）
    /v1/task/<id>     任务详情（S2 新增）
    /v1/screen        截屏，返回 PNG
    /v1/input         鼠标键盘注入（S3 起受输入租约约束，X-Input-Lease 头）
    /v1/audit         审计日志查询（S1 新增）
    /v1/self-update   热更新自身源码并重启（V1.3 起要求 sha256+HMAC 签名，§20）
    /v1/update/enroll  轮换更新签名密钥 hmac_key（S3 新增，§20.1）
    /v1/update/pin     追加可信 sha256 白名单（S3 新增，§20.2）
    /v1/elevate/install 高权限驻留计划任务安装引导（S3 新增，§22）
    /v1/elevate/remove 高权限驻留计划任务清理（S3 新增，§22）
    /v1/pair/begin     发起设备一次确认配对（M4 新增，免鉴权 + 私网来源，§23）
    /v1/pair/session   查询配对会话状态（M4 新增，免鉴权 + 仅回环，确认数据源，§23）
    /v1/pair/approve   本地确认配对并生成一次性 6 位码（M4 新增，免鉴权 + 仅回环，§23）
    /v1/pair/reject    本地拒绝配对（M4 新增，免鉴权 + 仅回环，§23）
    /v1/pair/confirm   凭配对码签发身份令牌（M4 新增，免鉴权 + 私网来源，§23）

安全基线（S1，唯一行为依据 docs/接口契约.md）：
    - 传输：默认 HTTPS（TLS 1.3，自签证书 + TOFU）；--debug-plaintext 才回退明文（D31）
    - 身份：node.json 多控制端身份（tokens 列表），令牌用 hmac.compare_digest 常量时间比较
    - 防重放：每个 /v1/* 请求必须带 X-Timestamp / X-Nonce，nonce 仅内存缓存（重启清空）
    - 审计：<config 目录>/audit/audit-YYYYMMDD.jsonl 追加写，默认留存 180 天；
      业务 403（SANDBOX_DENIED）与 S3 例外（409 INPUT_LEASE_TAKEN / 400 UPDATE_REJECTED）
      落审计且 target 照常（§8.2）
    - 新端点一律过同一 guard 链：私网来源 → 身份 → 防重放 → 审计

能力扩展（S2，契约 §13–§17）：
    - 大文件流式：checksum / download（Range 206）/ 上传三段式，全程分块读写不整载
    - 工作空间白名单：workspace 默认空 = 仅默认暂存目录可写，其余写/删/建目录/
      移动/上传全拒（§14；B42 起暂存目录恒可用且报错/查询接口自带允许根列表）
    - 任务历史：sqlite 落库（tasks.db）、/v1/task/list 与详情、留存先到先清（§15）
    - 端口与多实例：默认 51888、占用 +1 顺延并持久化、--instance 实例隔离（§16）

能力扩展（S3，契约 §19–§22）：
    - 发现广播：UDP 51889 XDCAST 帧（device_id/hostname/port/version/caps/ts），
      启动即发 1 帧 + 每 10 秒心跳；只发送不监听；报文不含任何凭据（§19.1，D38）
    - 更新签名：device_id 与 update.hmac_key 首次自动生成并持久化；self-update 按
      sha256 → HMAC-SHA256 → trusted_hashes 白名单顺序校验（任一失败 400 UPDATE_REJECTED
      且不落盘）；替换前备份 .bak + version.json；替换后 detached 拉起一次性看门狗（§20）
    - 输入租约：X-Input-Lease acquire/renew/release/take 全语义、过期惰性判定、
      被抢占一次性标记（下一次请求 409 INPUT_LEASE_TAKEN）（§21，D21）
    - 高权限驻留：/v1/elevate/install 经 ShellExecuteW runas + schtasks（登录触发 +
      最高权限）引导，UAC 拒绝/超时明确报错；remove 幂等清理（§22，D22）
    - 健康与展示：/v1/health 增 rollback_flag；横幅增 驻留 行；CLI 增
      --elevate-task-install / --elevate-task-remove 提权子命令

设备一次确认配对（M4，契约 V1.5 §23，B34/D41/FR-15）：
    - 端点族 /v1/pair/* 走 guard 变体（§2.3/§1.2 唯一例外）：免令牌免防重放头，
      ① 私网来源校验照常；回环确认端点（session/approve/reject）另加仅 127.0.0.1/::1
      检查（非回环 → 403，落审计）；其余既有端点的 guard 链零改动
    - 会话状态机：idle → pending → approved → consumed；expired / voided 终态；
      单活跃会话（内存结构重启清空），过期惰性判定（无后台线程）
    - 防滥用三件套：一次性 6 位数字码（常量时间比较）+ 短时效（pending 120s /
      code 300s，node.json pair 键可调）+ 猜码上限（默认 5 次失败作废会话）；
      begin 来源限频（默认 10 秒，含被 429 拒绝的请求）
    - confirm 签发 32 hex 新令牌入 node.json tokens（name 冲突自动后缀、上限 16）；
      配对码与令牌永不落审计；广播不自动信任（D38）与 xd add 手工路径不变

启动方式：
    python node.py [--port 51888] [--host 0.0.0.0] [--token <令牌>] [--verbose]
                   [--config <node.json 路径>] [--cert <cert.pem> --key <key.pem>]
                   [--workspace "<根1>,<根2>"] [--instance <名>] [--debug-plaintext]
                   [--elevate-task-install <名>] [--elevate-task-remove <名>]
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
import secrets
import shutil
import socket
import sqlite3
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

NODE_VERSION = "0.5.1"
MAX_OUTPUT = 256 * 1024          # 单个任务输出上限
MAX_BODY = 64 * 1024 * 1024      # 请求体上限
DEFAULT_PORT = 51888             # S2 默认端口（D28/B20，偏差 7；契约 §16.1）
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

# ---- S3 韧性层全局状态（契约 V1.3）----
DEFAULT_ELEVATE_TASK = "CrossDeviceNode"   # 高权限驻留计划任务默认名（§22.1）
DEVICE_ID = ""                      # 12hex 设备标识（§19.1，首次启动生成并持久化 node.json）
UPDATE_HMAC_KEY = ""                # self-update 签名密钥 64hex（§20.1，缺失自动生成并写回）
TRUSTED_HASHES = []                 # 可信 sha256 白名单（§20.2，/v1/update/pin 维护，上限 16）
MAX_TRUSTED_HASHES = 16             # trusted_hashes 上限（§20.2）
UPDATE_LOCK = threading.Lock()      # hmac_key / trusted_hashes 内存态互斥
INPUT_LEASE_SECONDS = 60            # 输入租约时长秒（§21.1：下限 5、缺省 60、非法回退默认）
INPUT_LEASE = {"holder": None, "acquired_at": None, "expires_at": None}   # §21.1 内存租约
INPUT_LEASE_LOCK = threading.Lock() # 租约读写互斥（§21.1）
INPUT_LEASE_PREEMPTED = set()       # 被抢占身份的一次性标记集合（§21.1，D21）
ELEVATED_TASK_NAME = None           # 高权限驻留计划任务名（§22；None = 未驻留）
CONFIG_FILE = ""                    # 当前配置文件绝对路径（S3 键持久化用）
ACTUAL_PORT = 0                     # 实际绑定端口（广播帧 / 看门狗拉起参数用，§16.1）
DETACHED_PROCESS = 0x00000008       # detached 启动标志（看门狗/重启进程，§20.4）

# ---- S3 发现广播（§19.1，D28/D25/D38）----
BROADCAST_PORT = 51889              # UDP 发现广播端口（仅发送，不监听）
BROADCAST_INTERVAL = 10             # 心跳间隔秒（D25：启动即发 1 帧 + 每 10 秒 1 帧）
BROADCAST_MAX_BYTES = 512           # 报文上限字节（§19.1：超限跳过不截断）
BROADCAST_CAPS = ["exec", "screen", "input", "fs", "update", "elevate"]   # §19.1 能力表

# ---- M4 配对层全局状态（契约 V1.5 §23，B34/D41/FR-15）----
PAIR_PENDING_TTL = 120              # pending 未确认最长等待秒（§23.2，下限 5、非法回退默认）
PAIR_CODE_TTL = 300                 # approved 后配对码时效秒（§23.2，≤5 分钟，下限 5）
PAIR_MAX_ATTEMPTS = 5               # confirm 猜码失败上限（§23.2，1–10）
PAIR_BEGIN_INTERVAL = 10            # 同一来源 IP 两次 begin 最小间隔秒（0 = 关闭限频）
PAIR_SESSION = None                 # 当前配对会话（单活跃；None = idle；重启清空，§23.2）
PAIR_LOCK = threading.Lock()        # 会话状态机与限频表共用一把锁
PAIR_BEGIN_TS = {}                  # {来源 IP: 上次 begin 时刻}（含被 429 拒绝的，§23.3）
PAIR_ACTIVE_STATES = ("pending", "approved")     # 活跃态（终态保留待下次 begin 覆盖）
PAIR_LOOPBACK = ("127.0.0.1", "::1")             # 回环确认端点允许的客户端（§23.1）
PAIR_LOOPBACK_PATHS = frozenset({                # 仅回环的端点（§23.1）
    "/v1/pair/session", "/v1/pair/approve", "/v1/pair/reject",
})

if os.name != "nt":
    raise SystemExit("node.py 仅支持 Windows（当前系统：%s）" % os.name)

# --------------------------------------------------------------------------
# Win32 基础设施
# --------------------------------------------------------------------------

user32 = ctypes.WinDLL("user32", use_last_error=True)
gdi32 = ctypes.WinDLL("gdi32", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
shell32 = ctypes.WinDLL("shell32", use_last_error=True)   # ShellExecuteExW 提权（§22.1）
# CommandLineToArgvW（B43）：Windows 官方 argv 切分语义，shell=none 依赖
shell32.CommandLineToArgvW.restype = ctypes.POINTER(ctypes.c_wchar_p)
shell32.CommandLineToArgvW.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_int)]

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
        # B42 新增（契约 §6.2 V1.6）：工作空间白名单可查询（含默认暂存目录）
        "workspace_roots": list(WORKSPACE_ROOTS),
        "workspace_staging": STAGING_ROOT or None,
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
        # S2 新增字段（契约 §6.2/§17.1）：本机私网 IPv4 列表
        "addresses": local_addresses(),
        # S3 新增字段（契约 §6.2/§19.1/§22.2）：设备标识与高权限驻留标记
        "device_id": DEVICE_ID,
        "elevated_resident": ELEVATED_TASK_NAME is not None,
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


def split_windows_argv(text):
    """按 CommandLineToArgvW（Windows 官方 argv 语义）切分命令行（B43）。

    引号内空格不拆散、\\" 为字面引号；与历史 prompt.split() 行为对齐：
    先 strip()（CommandLineToArgvW 对前导空白会产出空首参），空串返回 []。
    """
    stripped = text.strip()
    if not stripped:
        return []
    n = ctypes.c_int(0)
    lp = shell32.CommandLineToArgvW(stripped, ctypes.byref(n))
    if not lp:
        return []
    try:
        return list(lp[:n.value])
    finally:
        kernel32.LocalFree(lp)


def build_argv(prompt, shell):
    """构造非 cmd 形态的 argv（cmd 形态由 spawn_shell 走字符串路径，B43）。

    - powershell：-EncodedCommand（base64 UTF-16LE）——PS 5.1 向原生 exe 传参
      不转义内嵌双引号（PS 7.3 才修复），-Command 形态深层嵌套引号不可靠；
      编码形态无引号歧义，任务历史仍存原始 cmd。
    - none：CommandLineToArgvW 切分（B43 前 prompt.split() 按空格硬切，
      会拆散带引号参数）。
    """
    if shell == "powershell":
        encoded = base64.b64encode(prompt.encode("utf-16-le")).decode("ascii")
        return ["powershell", "-NoProfile", "-NonInteractive",
                "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded]
    if shell == "none":
        return list(prompt) if isinstance(prompt, list) else split_windows_argv(prompt)
    raise ValueError("build_argv 仅支持 powershell/none；cmd 形态走 spawn_shell")


def spawn_shell(prompt, shell, cwd, **popen_kwargs):
    """按 shell 形态拉起子进程（B43 引号逐字透传的唯一入口）。

    cmd 形态：命令行以字符串 + shell=True 直达 COMSPEC /c——不经
    list2cmdline 的 \\" 转义，cmd /c 的首尾引号剥除老规则不再吞掉内层引号
    （B43 前 ["cmd", "/c", prompt] 列表形态导致 tasklist /FI "..."、
    python -c "..." 等带引号命令全部失效）。powershell/none 走 build_argv
    （前者已 base64 编码无引号歧义，后者已按 Windows 语义切分）。
    """
    if shell in ("powershell", "none"):
        return subprocess.Popen(build_argv(prompt, shell), cwd=cwd, **popen_kwargs)
    return subprocess.Popen(prompt, shell=True, cwd=cwd, **popen_kwargs)


def start_detached(prompt, shell="cmd", cwd=None):
    """启动 GUI 程序用：不等待、不接管输出，否则子进程会占住管道让任务一直挂着。"""
    DETACHED_PROCESS = 0x00000008
    proc = spawn_shell(
        prompt, shell, cwd,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        stdin=subprocess.DEVNULL,
        creationflags=CREATE_NO_WINDOW | DETACHED_PROCESS,
    )
    return proc.pid


def _run_job(job_id, prompt, shell, cwd, timeout):
    started = time.time()
    try:
        proc = spawn_shell(
            prompt, shell, cwd,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL, creationflags=CREATE_NO_WINDOW,
        )
        try:
            out, err = proc.communicate(timeout=timeout)
            status = "done"
        except subprocess.TimeoutExpired:
            proc.kill()
            out, err = proc.communicate()
            status = "timeout"
        result = {
            "status": status,
            "exit_code": proc.returncode,
            "stdout": _trim(_decode(out)),
            "stderr": _trim(_decode(err)),
            "duration": round(time.time() - started, 3),
            "ended_at": time.time(),
        }
    except Exception as exc:
        result = {
            "status": "failed",
            "exit_code": None,
            "stdout": "",
            "stderr": str(exc),
            "duration": round(time.time() - started, 3),
            "ended_at": time.time(),
        }
    with JOBS_LOCK:
        JOBS[job_id].update(result)
    # 任务线程结束落库终态（契约 §15.1；失败仅告警，不影响内存结果）
    db_update_finished(job_id, result["status"], result["exit_code"],
                       result["stdout"], result["stderr"],
                       result["duration"], result["ended_at"])


def start_job(prompt, shell="cmd", cwd=None, timeout=60, identity=""):
    job_id = uuid.uuid4().hex[:12]
    with JOBS_LOCK:
        JOBS[job_id] = {
            "id": job_id, "identity": identity, "status": "running",
            "cmd": prompt, "shell": shell, "cwd": cwd,
            "started_at": time.time(), "ended_at": None,
            "exit_code": None, "stdout": "", "stderr": "", "duration": None,
        }
    db_insert_running(JOBS[job_id])     # 创建即写入任务历史（契约 §15.1）
    threading.Thread(target=_run_job, args=(job_id, prompt, shell, cwd, timeout),
                     daemon=True).start()
    return job_id


def get_job(job_id):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        return dict(job) if job else None


# --------------------------------------------------------------------------
# 任务历史持久化（契约 §15 / §10 冻结 DDL）
# --------------------------------------------------------------------------

TASKS_DB_PATH = ""                  # <config 目录>/tasks[-<实例>].db（§15.1/§16.2）
TASKS_CONN = None                   # 单连接 + 全局锁串行化（§15.1 允许的线程安全方式）
TASKS_LOCK = threading.Lock()
TASKS_RETENTION_DAYS = 30           # 留存天数默认（§15.4，D36）
TASKS_MAX_ENTRIES = 100000          # 留存条数默认（§15.4，D36）

TASKS_DDL = """
CREATE TABLE IF NOT EXISTS jobs (
    id          TEXT PRIMARY KEY,           -- 12 hex，与内存 job id 同源
    identity    TEXT NOT NULL DEFAULT '',   -- 发起身份名（S1 身份模型）
    cmd         TEXT NOT NULL,
    shell       TEXT NOT NULL DEFAULT 'cmd',
    cwd         TEXT,
    status      TEXT NOT NULL,              -- running / done / timeout / failed
    exit_code   INTEGER,
    stdout      TEXT,
    stderr      TEXT,
    started_at  REAL NOT NULL,
    ended_at    REAL,
    duration    REAL
)
"""


class TaskAuthzError(Exception):
    """任务列表 identity 参数越权（§15.2，D34 → 403 FORBIDDEN）。"""


def tasks_db_init(path):
    """初始化任务历史库（§15.1）：单连接 + 全局锁，多任务线程并发落库无损坏。"""
    global TASKS_DB_PATH, TASKS_CONN
    TASKS_DB_PATH = path
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute(TASKS_DDL)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_jobs_started_at ON jobs(started_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_jobs_identity ON jobs(identity)")
    conn.commit()
    TASKS_CONN = conn


def db_insert_running(job):
    """exec 创建任务即落库（§15.1）：status=running，identity=请求身份。失败仅告警。"""
    with TASKS_LOCK:
        try:
            TASKS_CONN.execute(
                "INSERT INTO jobs (id, identity, cmd, shell, cwd, status, exit_code,"
                " stdout, stderr, started_at, ended_at, duration)"
                " VALUES (?, ?, ?, ?, ?, 'running', NULL, '', '', ?, NULL, NULL)",
                (job["id"], job.get("identity", ""), job["cmd"], job["shell"],
                 job["cwd"], job["started_at"]))
            TASKS_CONN.commit()
        except sqlite3.Error as exc:
            sys.stderr.write("[警告] 任务落库失败：%s（%s）\n" % (job["id"], exc))


def db_update_finished(job_id, status, exit_code, stdout, stderr, duration, ended_at):
    """任务线程结束时更新终态（§15.1）。失败仅告警。"""
    with TASKS_LOCK:
        try:
            TASKS_CONN.execute(
                "UPDATE jobs SET status=?, exit_code=?, stdout=?, stderr=?,"
                " duration=?, ended_at=? WHERE id=?",
                (status, exit_code, stdout, stderr, duration, ended_at, job_id))
            TASKS_CONN.commit()
        except sqlite3.Error as exc:
            sys.stderr.write("[警告] 任务结果落库失败：%s（%s）\n" % (job_id, exc))


def db_get_job(job_id):
    """按 id 查任务全量行（§6.4：内存 miss 后查库，记录均为终态）。"""
    with TASKS_LOCK:
        try:
            row = TASKS_CONN.execute(
                "SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
        except sqlite3.Error:
            return None
    return dict(row) if row else None


def db_get_task_of(task_id, identity):
    """本人任务详情（§15.2，D34）：不存在或非本人一律返回 None（对外 404）。"""
    with TASKS_LOCK:
        try:
            row = TASKS_CONN.execute(
                "SELECT * FROM jobs WHERE id = ? AND identity = ?",
                (task_id, identity)).fetchone()
        except sqlite3.Error:
            return None
    return dict(row) if row else None


def db_recover_running():
    """启动恢复（§15.3）：遗留 running 标 failed，stderr 追加中断说明并补齐时间。"""
    now = time.time()
    with TASKS_LOCK:
        try:
            rows = TASKS_CONN.execute(
                "SELECT id, started_at FROM jobs WHERE status = 'running'").fetchall()
            for row in rows:
                TASKS_CONN.execute(
                    "UPDATE jobs SET status = 'failed', exit_code = NULL,"
                    " stderr = COALESCE(stderr, '') || ?,"
                    " ended_at = ?, duration = ? WHERE id = ?",
                    ("\n执行器重启，任务中断", now, now - row["started_at"], row["id"]))
            TASKS_CONN.commit()
            if rows:
                sys.stderr.write("[信息] 已将 %d 个中断任务标记为 failed\n" % len(rows))
        except sqlite3.Error as exc:
            sys.stderr.write("[警告] 任务恢复失败：%s\n" % exc)


def tasks_cleanup():
    """留存清理（§15.4）：年龄与数量阈值先到先清；不影响审计日志（D36）。"""
    with TASKS_LOCK:
        try:
            cutoff = time.time() - TASKS_RETENTION_DAYS * 86400
            TASKS_CONN.execute("DELETE FROM jobs WHERE started_at < ?", (cutoff,))
            total = TASKS_CONN.execute("SELECT COUNT(*) FROM jobs").fetchone()[0]
            if total > TASKS_MAX_ENTRIES:
                excess = total - TASKS_MAX_ENTRIES
                TASKS_CONN.execute(
                    "DELETE FROM jobs WHERE id IN"
                    " (SELECT id FROM jobs ORDER BY started_at ASC LIMIT ?)",
                    (excess,))
            TASKS_CONN.commit()
        except sqlite3.Error as exc:
            sys.stderr.write("[警告] 任务历史清理失败：%s\n" % exc)


def tasks_retention_loop():
    """运行期每小时清理一次（§15.4）；顺带执行审计留存清理（S1 遗留 #5 收口：
    审计原为仅启动期清理，现与任务清理同循环每小时执行，口径一致按文件名日期删超期）。"""
    while True:
        time.sleep(3600)
        tasks_cleanup()
        cleanup_audit_files()


def load_tasks_config(cfg):
    """加载留存配置（§15.4）：下限 1，非法值回退默认。"""
    global TASKS_RETENTION_DAYS, TASKS_MAX_ENTRIES
    tasks_cfg = cfg.get("tasks") if isinstance(cfg.get("tasks"), dict) else {}

    def pick(value, default):
        try:
            return max(1, int(value))
        except (TypeError, ValueError):
            return default

    TASKS_RETENTION_DAYS = pick(tasks_cfg.get("retention_days", 30), 30)
    TASKS_MAX_ENTRIES = pick(tasks_cfg.get("max_entries", 100000), 100000)


def task_list(query, requester):
    """实现 GET /v1/task/list（契约 §15.2）。identity 越权抛 TaskAuthzError。"""
    ident = query.get("identity")
    if ident is not None and ident != requester:
        raise TaskAuthzError()          # 一期任务仅本人可见（D34）
    status = query.get("status")
    if status is not None and status not in ("running", "done", "timeout", "failed"):
        raise ParamError("status 参数非法（running/done/timeout/failed）")
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
    limit = 50
    if "limit" in query:
        try:
            limit = int(query["limit"])
        except (TypeError, ValueError):
            raise ParamError("limit 参数必须是整数")
        if not 1 <= limit <= 200:
            raise ParamError("limit 参数超出范围（1–200）")
    offset = 0
    if "offset" in query:
        try:
            offset = int(query["offset"])
        except (TypeError, ValueError):
            raise ParamError("offset 参数必须是整数")
        if offset < 0:
            raise ParamError("offset 参数不能为负")

    where = ["identity = ?"]
    params = [requester]
    if status is not None:
        where.append("status = ?")
        params.append(status)
    if since is not None:
        where.append("started_at >= ?")
        params.append(since)
    if until is not None:
        where.append("started_at <= ?")
        params.append(until)
    cond = " AND ".join(where)
    with TASKS_LOCK:
        total = TASKS_CONN.execute(
            "SELECT COUNT(*) FROM jobs WHERE " + cond, params).fetchone()[0]
        rows = TASKS_CONN.execute(
            "SELECT id, identity, cmd, shell, cwd, status, exit_code,"
            " started_at, ended_at, duration FROM jobs WHERE " + cond
            + " ORDER BY started_at DESC LIMIT ? OFFSET ?",
            params + [limit, offset]).fetchall()
    # 摘要不含 stdout/stderr（§15.2）；entries 按 started_at 降序
    return {"entries": [dict(row) for row in rows], "total": total}


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
# 工作空间白名单（契约 §14）
# --------------------------------------------------------------------------

WORKSPACE_ROOTS = []                # 判定用根列表：用户根 + 默认暂存目录（均规范化；§14.1/§14.3）
USER_WORKSPACE_ROOTS = []           # 用户显式配置的根（不含暂存目录；空 = 仅默认暂存可用）
STAGING_ROOT = ""                   # 默认暂存目录 <config 目录>/tmp（B42：自动化友好，恒可用，
                                    # 不计入 16 上限；启动时自动创建）
MAX_WORKSPACE_ROOTS = 16            # 用户白名单根数量上限（§14.1）


def normalize_real(path):
    """路径规范化（契约 §14.3）：realpath 解析符号链接 / .. 穿越 / 8.3 短名，
    再 normcase 归一盘符与大小写。"""
    return os.path.normcase(os.path.realpath(path))


def workspace_hit(path):
    """工作空间白名单判定 helper（契约 §14.3，独立可调用，便于冒烟白盒测试）。

    判定：请求路径与白名单根均做 realpath + normcase 规范化；
    命中 = 等于根，或以 根 + os.sep 开头。

    返回 (ok, reason, normalized)：
        ok=True,  reason="ok"            通过（命中某个存在的白名单根）
        ok=False, reason="denied"        未命中任何根 → 403 SANDBOX_DENIED
        ok=False, reason="root_missing"  按前缀落入根但根目录不存在 → 400（不自动建根）
    """
    norm = normalize_real(path)
    hit = [root for root in WORKSPACE_ROOTS
           if norm == root or norm.startswith(root + os.sep)]
    if not hit:
        return False, "denied", norm
    if any(os.path.isdir(root) for root in hit):
        return True, "ok", norm
    return False, "root_missing", norm


def load_workspace(args, cfg, config_file=None):
    """加载白名单根（契约 §14.1）：CLI --workspace（逗号分隔）覆盖配置文件 workspace。

    B42 起（V1.6）默认附加暂存目录 <config 目录>/tmp（--instance 时 tmp-<名>，
    与任务库/审计同源隔离 §16.2）：自动化任务恒有可写暂存位置。定位是
    「自动化友好」而非安全让步——exec 本为全能力通道，专用暂存目录不新增
    攻击面。暂存目录不计入 16 上限；启动时自动创建；与用户根去重合并。
    """
    global WORKSPACE_ROOTS, USER_WORKSPACE_ROOTS, STAGING_ROOT
    if args.workspace is not None:
        raw = args.workspace.split(",")
    else:
        raw = cfg.get("workspace") if isinstance(cfg.get("workspace"), list) else []
    roots = []
    for item in raw:
        if isinstance(item, str) and item.strip():
            roots.append(item.strip())
    if len(roots) > MAX_WORKSPACE_ROOTS:
        sys.stderr.write("[警告] 工作空间根数量超过上限 %d，仅保留前 %d 个\n"
                         % (MAX_WORKSPACE_ROOTS, MAX_WORKSPACE_ROOTS))
        roots = roots[:MAX_WORKSPACE_ROOTS]
    USER_WORKSPACE_ROOTS = [normalize_real(root) for root in roots]
    # 暂存目录：与配置文件同目录（node.json → tmp；node-<名>.json → tmp-<名>）
    if config_file:
        stem = os.path.splitext(os.path.basename(config_file))[0]
        inst = stem[len("node-"):] if stem.startswith("node-") else ""
        staging_raw = os.path.join(os.path.dirname(os.path.abspath(config_file)),
                                   "tmp-" + inst if inst else "tmp")
        try:
            os.makedirs(staging_raw, exist_ok=True)
        except OSError as exc:
            sys.stderr.write("[警告] 暂存目录创建失败：%s（%s）\n" % (staging_raw, exc))
        STAGING_ROOT = normalize_real(staging_raw)
    merged = list(USER_WORKSPACE_ROOTS)
    if STAGING_ROOT and STAGING_ROOT not in merged:
        merged.append(STAGING_ROOT)
    WORKSPACE_ROOTS = merged


# --------------------------------------------------------------------------
# 大文件流式（契约 §13）：分块 MD5 / 上传三段式 / 孤儿清理
# --------------------------------------------------------------------------

UPLOAD_CHUNK_SIZE = 4 * 1024 * 1024     # 上传分块大小（§13.3）
UPLOAD_MAX_SESSIONS = 8                 # 活跃上传会话上限（§13.3）
DOWNLOAD_BLOCK = 1024 * 1024            # 下载/checksum/commit 校验分块 ≤1MB（性能底线）
UPLOAD_SESSIONS = {}                    # upload_id -> 会话字典（仅内存，不跨重启，§13.3）
UPLOAD_LOCK = threading.Lock()          # 会话字典读写锁
UPLOADS_MANIFEST = ""                   # 上传清单文件路径（§13.5，启动清理孤儿用）
UPLOADS_MANIFEST_LOCK = threading.Lock()


class UploadError(Exception):
    """上传阶段业务错误（§13.3）：code 为错误码，status 为对应 HTTP 状态码。"""

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code
        self.status = 404 if code == "NOT_FOUND" else 400


def md5_file(path, block_size=DOWNLOAD_BLOCK):
    """分块流式计算文件 MD5（1MB 块，不整载；§13.1/§13.2/§13.3）。"""
    digest = hashlib.md5()
    with open(path, "rb") as fh:
        while True:
            block = fh.read(block_size)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def _read_uploads_manifest():
    try:
        with open(UPLOADS_MANIFEST, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, list) else []
    except (OSError, ValueError):
        return []


def uploads_manifest_add(temp_path):
    """begin 登记：把临时文件路径写入上传清单（原子写，§13.5）。"""
    with UPLOADS_MANIFEST_LOCK:
        items = _read_uploads_manifest()
        if temp_path in items:
            return
        items.append(temp_path)
        try:
            atomic_write_json(UPLOADS_MANIFEST, items)
        except OSError as exc:
            sys.stderr.write("[警告] 上传清单登记失败：%s\n" % exc)


def uploads_manifest_remove(temp_path):
    """commit / abort 移除登记（原子写，§13.5）。"""
    with UPLOADS_MANIFEST_LOCK:
        items = _read_uploads_manifest()
        if temp_path not in items:
            return
        items.remove(temp_path)
        try:
            atomic_write_json(UPLOADS_MANIFEST, items)
        except OSError as exc:
            sys.stderr.write("[警告] 上传清单移除失败：%s\n" % exc)


def cleanup_upload_orphans():
    """node 启动时清理上次进程遗留的上传临时文件并清空清单（契约 §13.5）。"""
    items = _read_uploads_manifest()
    removed = 0
    for item in items:
        if not isinstance(item, str) or not item:
            continue
        if os.path.exists(item):
            try:
                os.remove(item)
                removed += 1
            except OSError as exc:
                sys.stderr.write("[警告] 上传临时文件清理失败：%s（%s）\n" % (item, exc))
    if os.path.exists(UPLOADS_MANIFEST):
        try:
            atomic_write_json(UPLOADS_MANIFEST, [])
        except OSError as exc:
            sys.stderr.write("[警告] 上传清单清空失败：%s\n" % exc)
    if removed and VERBOSE:
        sys.stderr.write("[信息] 已清理 %d 个遗留上传临时文件\n" % removed)


def _cleanup_session_files(sess):
    """删除会话临时文件并移除清单登记（内存移除由调用方完成）。"""
    try:
        os.remove(sess["temp"])
    except OSError:
        pass
    uploads_manifest_remove(sess["temp"])


def _discard_session(sess):
    """终止会话：移出内存 + 删临时文件 + 移除清单（调用方需持有 UPLOAD_LOCK）。"""
    UPLOAD_SESSIONS.pop(sess["upload_id"], None)
    _cleanup_session_files(sess)


def _truncate_to(path, size):
    """把文件截断到指定长度（chunk 写失败回滚用，保证续传偏移与磁盘一致）。"""
    try:
        with open(path, "r+b") as fh:
            fh.truncate(size)
    except OSError:
        pass


def upload_begin(target, size, md5_digest):
    """begin 阶段（契约 §13.3）。白名单由调用方先行校验；返回响应 data。"""
    abs_target = os.path.abspath(target)
    norm = normalize_real(abs_target)
    parent = os.path.dirname(abs_target)
    if parent:
        try:
            os.makedirs(parent, exist_ok=True)
        except OSError as exc:
            raise UploadError("BAD_REQUEST", "无法创建上传目标目录：%s" % exc)
    with UPLOAD_LOCK:
        old = None
        for sess in UPLOAD_SESSIONS.values():
            if sess["norm"] == norm:
                old = sess
                break
        if old is not None:
            if old["size"] == size and old["md5"] == md5_digest:
                # 同目标且 size/md5 均一致：复用会话（断点续传，§13.3）
                return {"upload_id": old["upload_id"],
                        "chunk_size": UPLOAD_CHUNK_SIZE,
                        "resume_offset": old["received"]}
            _discard_session(old)       # size 或 md5 不一致：终止旧会话后重建
        if len(UPLOAD_SESSIONS) >= UPLOAD_MAX_SESSIONS:
            raise UploadError("BAD_REQUEST",
                              "上传会话已达上限 %d，请先 commit 或 abort"
                              % UPLOAD_MAX_SESSIONS)
        upload_id = uuid.uuid4().hex[:16]
        temp = abs_target + ".crosspart-" + upload_id
        try:
            with open(temp, "ab"):      # 预创建临时文件占位（顺带验证目录可写）
                pass
        except OSError as exc:
            raise UploadError("BAD_REQUEST", "无法创建上传临时文件：%s" % exc)
        UPLOAD_SESSIONS[upload_id] = {
            "upload_id": upload_id, "path": abs_target, "norm": norm,
            "size": size, "md5": md5_digest, "received": 0, "temp": temp,
        }
    uploads_manifest_add(temp)
    return {"upload_id": upload_id, "chunk_size": UPLOAD_CHUNK_SIZE,
            "resume_offset": 0}


def upload_chunk(upload_id, offset, data):
    """chunk 阶段（契约 §13.3）：校验通过后按 offset 追加写入临时文件。"""
    with UPLOAD_LOCK:
        sess = UPLOAD_SESSIONS.get(upload_id)
        if sess is None:
            raise UploadError("NOT_FOUND", "上传会话不存在或已结束：%s" % upload_id)
        if offset != sess["received"]:
            raise UploadError("BAD_REQUEST",
                              "offset 与会话当前偏移不符：会话当前偏移为 %d"
                              % sess["received"])
        if len(data) > UPLOAD_CHUNK_SIZE:
            raise UploadError("BAD_REQUEST",
                              "分块数据超过 chunk_size（%d 字节）" % UPLOAD_CHUNK_SIZE)
        if sess["received"] + len(data) > sess["size"]:
            raise UploadError("BAD_REQUEST", "累计字节将超过声明 size（%d）" % sess["size"])
        try:
            with open(sess["temp"], "ab") as fh:
                fh.write(data)
        except OSError:
            _truncate_to(sess["temp"], sess["received"])   # 回滚部分写入
            raise
        sess["received"] += len(data)
        return {"received": sess["received"], "next_offset": sess["received"]}


def upload_commit(upload_id):
    """commit 阶段（契约 §13.3）：流式 MD5 校验，失败清理会话与临时文件；
    成功 os.replace 落盘并移除清单登记。"""
    with UPLOAD_LOCK:
        sess = UPLOAD_SESSIONS.pop(upload_id, None)
    if sess is None:
        raise UploadError("NOT_FOUND", "上传会话不存在或已结束：%s" % upload_id)
    if sess["received"] != sess["size"]:
        raise UploadError("BAD_REQUEST",
                          "分块未收全：已收 %d/%d，可重新 begin 查询 resume_offset"
                          % (sess["received"], sess["size"]))
    try:
        actual = md5_file(sess["temp"])     # 1MB 分块流式校验，不整载
    except OSError as exc:
        _cleanup_session_files(sess)
        raise UploadError("BAD_REQUEST", "临时文件读取失败：%s" % exc)
    if actual != sess["md5"]:
        _cleanup_session_files(sess)        # MD5 不一致：清理会话与临时文件（§13.3）
        raise UploadError("BAD_REQUEST",
                          "MD5 校验失败：声明 %s，实际 %s（会话与临时文件已清理）"
                          % (sess["md5"], actual))
    # 覆盖已存在目标时，Windows 实时扫描可能瞬时占用目标文件导致 WinError 5：
    # 与 xd 侧原子写同款短重试（10 次 × 0.1s），仍失败才清理会话并报 400
    last_exc = None
    for _ in range(10):
        try:
            os.replace(sess["temp"], sess["path"])   # 目标已存在则覆盖（§13.3）
            last_exc = None
            break
        except OSError as exc:
            last_exc = exc
            time.sleep(0.1)
    if last_exc is not None:
        _cleanup_session_files(sess)
        raise UploadError("BAD_REQUEST", "落盘失败：%s" % last_exc)
    uploads_manifest_remove(sess["temp"])
    return {"path": sess["path"], "size": sess["size"], "md5": sess["md5"]}


def upload_abort(upload_id):
    """abort 阶段（契约 §13.3）：删除临时文件与清单登记。"""
    with UPLOAD_LOCK:
        sess = UPLOAD_SESSIONS.pop(upload_id, None)
    if sess is None:
        raise UploadError("NOT_FOUND", "上传会话不存在或已结束：%s" % upload_id)
    _cleanup_session_files(sess)
    return {"aborted": True}


# --------------------------------------------------------------------------
# 自更新（契约 §6.8 / §20：签名校验 → 备份 → 替换 → 看门狗 → 重启）
# --------------------------------------------------------------------------

def schedule_restart(delay=2):
    script = os.path.abspath(__file__)
    bat = os.path.join(tempfile.gettempdir(), "xd-node-restart.bat")
    # 参数逐个加引号透传（S2 新增 --workspace/--instance 值可含空格/逗号）；
    # bat 文件中 % 是变量展开前缀，须转义为 %% 才能原样传给新进程
    args = " ".join('"%s"' % a for a in sys.argv[1:]).replace("%", "%%")
    content = (
        "@echo off\r\n"
        'cd /d "%s"\r\n'
        "ping -n %d 127.0.0.1 >nul\r\n"
        'start "" /min "%s" "%s" %s\r\n'
        % (os.getcwd(), int(delay) + 1, sys.executable, script, args)
    )
    with open(bat, "w", encoding="mbcs", errors="replace") as fh:
        fh.write(content)
    subprocess.Popen(["cmd", "/c", bat],
                     creationflags=DETACHED_PROCESS | CREATE_NO_WINDOW,
                     close_fds=True)


def sha256_file(path, block_size=DOWNLOAD_BLOCK):
    """分块流式计算文件 SHA-256（64hex 小写）；读取失败抛出原异常。"""
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            block = fh.read(block_size)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def update_signature_verify(source, sha256_claim, hmac_claim):
    """更新包签名校验（契约 §20.2，校验顺序冻结；任一失败即拒绝且不落盘）。

    顺序：① sha256 与解码后源码实际 sha256 一致（常量时间比较）；
          ② hmac 与 HMAC-SHA256(key=utf8(hmac_key), msg=utf8(sha256 小写)) 一致；
             节点无 hmac_key → 拒绝；
          ③ trusted_hashes 非空时强制 sha256 ∈ 白名单（空 = 仅 HMAC，一期默认）。

    通过返回 None；失败返回中文错误信息（调用方 → 400 UPDATE_REJECTED）。
    缺 sha256/hmac（旧格式）同样返回错误信息（E-02 唯一兼容例外，偏差 9）。
    """
    if not isinstance(sha256_claim, str) or not isinstance(hmac_claim, str):
        return "缺少 sha256/hmac 签名参数（V1.3 起旧格式请求不再支持）"
    # ① sha256 与实际解码内容一致
    actual_sha = hashlib.sha256(source).hexdigest()
    if not hmac.compare_digest(sha256_claim.encode("utf-8", "replace"),
                               actual_sha.encode("ascii")):
        return "更新包校验失败：sha256 与源码实际内容不一致"
    # ② HMAC-SHA256 签名（key 为 hmac_key 64hex 字符串的 UTF-8 编码）
    if not UPDATE_HMAC_KEY:
        return "更新包校验失败：节点无更新签名密钥（未 enroll）"
    expected = hmac.new(UPDATE_HMAC_KEY.encode("utf-8"),
                        sha256_claim.encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(hmac_claim.encode("utf-8", "replace"),
                               expected.encode("ascii")):
        return "更新包校验失败：HMAC 签名不匹配"
    # ③ 白名单（非空时强制）
    with UPDATE_LOCK:
        trusted = list(TRUSTED_HASHES)
    if trusted and sha256_claim not in trusted:
        return "更新包校验失败：sha256 不在可信哈希白名单中（请先 /v1/update/pin）"
    return None


def launch_watchdog_once(bak_path, port):
    """替换成功后以 detached 方式拉起一次性看门狗（契约 §20.4，D33）。

    看门狗路径依次尝试 <node.py 同目录>/watchdog.py → <node.py 同目录>/../watchdog.py；
    均不存在 → 跳过拉起并 stderr 告警（更新仍执行，回滚保护缺失）。
    返回看门狗进程 pid；未拉起返回 None。
    """
    here = os.path.dirname(os.path.abspath(__file__))
    watchdog = None
    for candidate in (os.path.join(here, "watchdog.py"),
                      os.path.abspath(os.path.join(here, os.pardir, "watchdog.py"))):
        if os.path.isfile(candidate):
            watchdog = candidate
            break
    if watchdog is None:
        sys.stderr.write("[警告] 未找到 watchdog.py（%s 或其上级目录），"
                         "跳过看门狗拉起：本次更新无自动回滚保护\n" % here)
        return None
    # --args 与 schedule_restart 同款透传口径：进程直拉按 list2cmdline 逐参数引号化拼串
    argv = [sys.executable, watchdog,
            "--node", os.path.abspath(__file__),
            "--python", sys.executable,
            "--args", subprocess.list2cmdline(sys.argv[1:]),
            "--bak", os.path.abspath(bak_path),
            "--once", "--grace", "60",
            "--port", str(port)]
    try:
        proc = subprocess.Popen(argv, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL,
                                creationflags=CREATE_NO_WINDOW | DETACHED_PROCESS,
                                close_fds=True)
        if VERBOSE:
            sys.stderr.write("[信息] 看门狗已拉起（pid %d）：%s\n" % (proc.pid, watchdog))
        return proc.pid
    except OSError as exc:
        sys.stderr.write("[警告] 看门狗拉起失败：%s（更新仍执行，回滚保护缺失）\n" % exc)
        return None


def rollback_flag_exists():
    """node.py 同目录是否存在 rollback.flag（§6.1/§20.4）；每次实时判断文件存在性。"""
    return os.path.exists(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                       "rollback.flag"))


def self_update(source, port):
    """热更新替换（契约 §20.3，签名校验已由调用方完成）：
    写 .new → 语法编译校验 → 备份 .bak（覆盖）→ 原子写 version.json →
    os.replace 替换 → detached 拉起一次性看门狗 → bat 延迟重启。
    语法校验失败抛 ValueError（调用方 → 400 BAD_REQUEST，"源码语法错误"文案维持现状）。
    """
    target = os.path.abspath(__file__)
    temp = target + ".new"
    with open(temp, "wb") as fh:
        fh.write(source)
    try:
        compile(source, temp, "exec")
    except SyntaxError as exc:
        os.remove(temp)
        raise ValueError("源码语法错误：%s" % exc)
    # 备份当前 node.py（覆盖旧备份，node.py 同目录，§20.3/D13）
    bak = target + ".bak"
    shutil.copyfile(target, bak)
    try:
        old_sha = sha256_file(target)
    except OSError as exc:
        os.remove(temp)
        raise RuntimeError("备份失败：无法读取当前 node.py（%s）" % exc)
    # 版本记录（同目录原子写，§20.3）
    try:
        atomic_write_json(os.path.join(os.path.dirname(target), "version.json"), {
            "old_sha256": old_sha,
            "new_sha256": hashlib.sha256(source).hexdigest(),
            "ts": time.time(),
        })
    except OSError as exc:
        os.remove(temp)
        raise RuntimeError("版本记录写入失败：%s" % exc)
    # os.replace 带 10×0.1s 短重试：Windows 实时扫描可能瞬时占用 node.py.new /
    # node.py 造成 WinError 5（与 upload_commit 落盘同款防护）
    last_exc = None
    for _ in range(10):
        try:
            os.replace(temp, target)
            last_exc = None
            break
        except OSError as exc:
            last_exc = exc
            time.sleep(0.1)
    if last_exc is not None:
        try:
            os.remove(temp)
        except OSError:
            pass
        raise RuntimeError("替换失败：%s" % last_exc)
    launch_watchdog_once(bak, port)
    schedule_restart()
    return {"path": target, "bytes": len(source)}


# --------------------------------------------------------------------------
# 配置与多身份（契约 §2 / §9.1）
# --------------------------------------------------------------------------

def default_config_path():
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    return os.path.join(base, "CrossDevice", "node.json")


def default_config_dir():
    return os.path.dirname(default_config_path())


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


def load_config(args, config_path=None):
    """加载 / 迁移 node.json（契约 §9.1），返回 (cfg, identities, 配置文件路径)。

    - 旧格式 {"token": X} 首次运行自动迁移为 tokens=[{"name":"default","token":X}]
      并原子写回；未知键（如 port）原样保留。
    - --token 覆盖 default 身份令牌，其余身份保留，结果写回配置。
    - 无任何令牌且未传 --token：生成 32 hex 新令牌作为 default。
    - config_path：显式配置路径（--instance 时为 <config 目录>/node-<名>.json，§16.2）。
    """
    path = config_path or args.config or default_config_path()
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
# S3 配置持久化与新键初始化（契约 §9.1 / §19.1 / §20.1 / §21.1 / §22）
# --------------------------------------------------------------------------

def persist_config(mutator):
    """读改写当前配置文件（S3：enroll/pin/elevate 使用）：读盘最新内容 → mutator 修改 →
    原子写回。读失败按空配置处理（写回时保留 tokens 等既有键由读盘内容保证）。"""
    cfg = {}
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as fh:
            cfg = json.load(fh)
        if not isinstance(cfg, dict):
            cfg = {}
    except (OSError, ValueError):
        cfg = {}
    mutator(cfg)
    atomic_write_json(CONFIG_FILE, cfg)


def _pick_pair_param(section, key, default, low, high=None):
    """pair 参数读取（契约 §9.1/§23.2 边界值表）：无法解析为整数 → 回退默认；
    越界 → 钳到边界（同 input.lease_seconds 既有口径）。"""
    try:
        value = int(section.get(key, default))
    except (TypeError, ValueError):
        return default
    if high is None:
        return max(low, value)
    return min(high, max(low, value))


def ensure_s3_config(cfg, config_file):
    """node.json S3/M4 新键初始化（契约 §9.1/§19.1/§20.1/§21.1/§22/§23.2）：
    - device_id：缺失或非法 → uuid4().hex[:12] 生成并原子写回（§19.1）；
    - update.hmac_key：缺失或非法 → os.urandom(32).hex() 生成并原子写回（§20.1）；
      trusted_hashes 缺省 []；
    - input.lease_seconds：下限 5、缺省 60、非法回退默认（§21.1）；
    - elevated：缺省视为未驻留（§22）；
    - pair 四参数：pending_ttl/code_ttl 下限 5、max_attempts 1–10、begin_interval ≥0
      （0 = 关闭限频），非法回退默认（§23.2，V1.5 新增）。
    仅在发生变更时写盘；输入/驻留/配对键仅读入内存，不主动写盘（缺省兼容）。
    """
    global DEVICE_ID, UPDATE_HMAC_KEY, TRUSTED_HASHES, INPUT_LEASE_SECONDS
    global ELEVATED_TASK_NAME
    global PAIR_PENDING_TTL, PAIR_CODE_TTL, PAIR_MAX_ATTEMPTS, PAIR_BEGIN_INTERVAL
    changed = False

    device_id = cfg.get("device_id")
    if isinstance(device_id, str) and re.fullmatch(r"[0-9a-f]{12}", device_id):
        DEVICE_ID = device_id
    else:
        DEVICE_ID = uuid.uuid4().hex[:12]
        cfg["device_id"] = DEVICE_ID
        changed = True

    update_cfg = cfg.get("update") if isinstance(cfg.get("update"), dict) else None
    if update_cfg is None:
        update_cfg = {}
        cfg["update"] = update_cfg
        changed = True
    hmac_key = update_cfg.get("hmac_key")
    if isinstance(hmac_key, str) and re.fullmatch(r"[0-9a-f]{64}", hmac_key):
        UPDATE_HMAC_KEY = hmac_key
    else:
        UPDATE_HMAC_KEY = os.urandom(32).hex()
        update_cfg["hmac_key"] = UPDATE_HMAC_KEY
        changed = True
    hashes = update_cfg.get("trusted_hashes")
    if isinstance(hashes, list):
        TRUSTED_HASHES = [h for h in hashes
                          if isinstance(h, str) and re.fullmatch(r"[0-9a-f]{64}", h)]
        if len(TRUSTED_HASHES) != len(hashes):
            update_cfg["trusted_hashes"] = TRUSTED_HASHES
            changed = True
    else:
        TRUSTED_HASHES = []

    input_cfg = cfg.get("input") if isinstance(cfg.get("input"), dict) else {}
    try:
        lease_seconds = int(input_cfg.get("lease_seconds", 60))
    except (TypeError, ValueError):
        lease_seconds = 60                      # 非法回退默认（§21.1）
    INPUT_LEASE_SECONDS = max(5, lease_seconds)   # 下限 5（§21.1）

    elevated = cfg.get("elevated")
    if (isinstance(elevated, dict) and isinstance(elevated.get("task_name"), str)
            and elevated.get("task_name")):
        ELEVATED_TASK_NAME = elevated["task_name"]
    else:
        ELEVATED_TASK_NAME = None

    # ---- M4 配对参数（契约 §9.1/§23.2）：缺省即默认；非法回退默认；越界钳到边界 ----
    pair_cfg = cfg.get("pair") if isinstance(cfg.get("pair"), dict) else {}
    PAIR_PENDING_TTL = _pick_pair_param(pair_cfg, "pending_ttl", 120, 5)
    PAIR_CODE_TTL = _pick_pair_param(pair_cfg, "code_ttl", 300, 5)
    PAIR_MAX_ATTEMPTS = _pick_pair_param(pair_cfg, "max_attempts", 5, 1, 10)
    PAIR_BEGIN_INTERVAL = _pick_pair_param(pair_cfg, "begin_interval", 10, 0)

    if changed:
        try:
            atomic_write_json(config_file, cfg)
        except OSError as exc:
            sys.stderr.write("[警告] S3 配置键（device_id/update）写回失败：%s\n" % exc)


def update_enroll():
    """更新签名密钥建立/轮换（契约 §20.1）：每次调用生成新 64hex hmac_key，
    同步内存与配置文件并返回。旧密钥随即失效。持久化失败抛异常（→ 500）。"""
    global UPDATE_HMAC_KEY
    key = os.urandom(32).hex()
    with UPDATE_LOCK:
        UPDATE_HMAC_KEY = key

    def mutator(cfg):
        update_cfg = cfg.get("update") if isinstance(cfg.get("update"), dict) else {}
        cfg["update"] = update_cfg
        update_cfg["hmac_key"] = key

    persist_config(mutator)
    return key


def update_pin_add(sha256_value):
    """可信哈希白名单追加（契约 §20.2）：去重、上限 16（超限拒绝）。
    返回 (ok, 拒绝消息)；成功时同步持久化 node.json。"""
    with UPDATE_LOCK:
        if sha256_value in TRUSTED_HASHES:
            return True, None                    # 去重：已在白名单中视为成功
        if len(TRUSTED_HASHES) >= MAX_TRUSTED_HASHES:
            return False, "trusted_hashes 已达上限 %d，无法追加" % MAX_TRUSTED_HASHES
        TRUSTED_HASHES.append(sha256_value)

    def mutator(cfg):
        update_cfg = cfg.get("update") if isinstance(cfg.get("update"), dict) else {}
        cfg["update"] = update_cfg
        update_cfg["trusted_hashes"] = list(TRUSTED_HASHES)

    persist_config(mutator)
    return True, None


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

    绑定语义（契约 §16.1 的端口占用检测依赖 bind 失败的可靠性）：
    - Windows 上 SO_REUSEADDR 允许两个套接字静默共绑同一端口（实测 case：
      先到者与后到者均设 REUSE 时后到者 bind 成功），会让"端口被占用"判定失效，
      因此默认禁用 SO_REUSEADDR，改设 SO_EXCLUSIVEADDRUSE 独占绑定；
    - allow_reuse=True 仅在调用方探测到端口无活监听者、仅剩 TIME_WAIT 残留时
      使用（回退 SO_REUSEADDR 绑定同端口），避免热重启后端口无谓顺延。

    TLS 模式下在 accept 阶段完成握手：明文请求打到 TLS 端口产生的握手
    异常在这里捕获（verbose 记日志、关闭连接、继续服务），不使服务崩溃。
    """

    allow_reuse_address = False         # 默认不用 SO_REUSEADDR（见类注释）

    def __init__(self, address, handler, ssl_context=None, allow_reuse=False):
        self._allow_reuse = allow_reuse
        super().__init__(address, handler)
        self.ssl_context = ssl_context

    def server_bind(self):
        if os.name == "nt" and not self._allow_reuse:
            try:
                self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            except OSError:
                pass                    # 极老系统不支持时保持默认语义
        super().server_bind()

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


def set_audit_paths(audit_dir, retention_days):
    """设置审计目录（§8.1；--instance 时为 audit-<名>/，实例隔离见 §16.2）。"""
    global AUDIT_DIR, AUDIT_RETENTION_DAYS
    AUDIT_DIR = audit_dir
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
# 输入租约（契约 §21，D21/FR-06/FR-12）
# --------------------------------------------------------------------------

INPUT_LEASE_ACTIONS = ("acquire", "renew", "release", "take")   # §21.2 请求头合法值


def _lease_lazy_expire_locked():
    """过期惰性判定（§21.1，需持锁）：now > expires_at 即视为空闲；无后台线程。"""
    lease = INPUT_LEASE
    if (lease["holder"] is not None and lease["expires_at"] is not None
            and time.time() > lease["expires_at"]):
        lease["holder"] = None
        lease["acquired_at"] = None
        lease["expires_at"] = None


def input_lease_snapshot(identity):
    """当前租约快照（§21.3）：{holder, mine, expires_at}，含惰性过期判定。"""
    with INPUT_LEASE_LOCK:
        _lease_lazy_expire_locked()
        lease = INPUT_LEASE
        return {"holder": lease["holder"],
                "mine": lease["holder"] == identity,
                "expires_at": lease["expires_at"]}


def input_lease_check(identity, mode):
    """输入租约判定（契约 §21.2 语义表，冻结）。

    mode：None（无头 = 隐式 acquire）或 acquire/renew/release/take（合法性由调用方先行校验）。
    判定顺序：被抢占标记 → 租约判定 → 通过后由调用方执行动作（§21.2）。

    返回 (verdict, payload)：
        ("allow", None)                 通过（租约快照由调用方事后经 snapshot 取得）
        ("deny409", 消息)               → 409 INPUT_LEASE_TAKEN
        ("deny400", 消息)               → 400 BAD_REQUEST
    """
    now = time.time()
    with INPUT_LEASE_LOCK:
        # ① 被抢占标记（D21）：被抢占身份的下一次任何 /v1/input 请求 → 409
        #    （不执行动作），处理后清除一次性标记；再下一次恢复正常判定。
        if identity in INPUT_LEASE_PREEMPTED:
            INPUT_LEASE_PREEMPTED.discard(identity)
            return "deny409", "输入租约已被其他控制端抢占（下一次请求恢复正常）"
        _lease_lazy_expire_locked()
        lease = INPUT_LEASE
        holder = lease["holder"]
        mine = holder == identity

        if mode == "renew":
            # 本人持有 → 续至 now+lease 并执行；空闲/过期/他人持有 → 409
            if not mine:
                return "deny409", "租约续期失败：租约未被本人持有"
            lease["expires_at"] = now + INPUT_LEASE_SECONDS
        elif mode == "release":
            # 本人持有 → 释放（清空租约）并执行动作（actions 可空）；
            # 他人持有或无租约 → 400 BAD_REQUEST
            if not mine:
                return "deny400", "租约释放失败：租约未被本人持有"
            lease["holder"] = None
            lease["acquired_at"] = None
            lease["expires_at"] = None
        elif mode == "take":
            # 显式抢占：空闲 → 直接授予；本人持有 → 续期（并清除自身被抢占标记，如有）；
            # 他人持有 → 立即改持有人为请求者，原持有人写入被抢占标记（D21）
            if holder is not None and not mine:
                INPUT_LEASE_PREEMPTED.add(holder)
            lease["holder"] = identity
            lease["acquired_at"] = now
            lease["expires_at"] = now + INPUT_LEASE_SECONDS
            INPUT_LEASE_PREEMPTED.discard(identity)
        else:
            # 无头（隐式 acquire）/ acquire：空闲或过期 → 授予并执行；
            # 本人持有 → 执行并续至 now+lease（FR-12"60 秒自动续期"口径）；
            # 他人持有未过期 → 409 INPUT_LEASE_TAKEN（不执行动作）
            if holder is not None and not mine:
                return "deny409", ("输入租约被他人持有：%s"
                                   "（可用 X-Input-Lease: take 显式抢占）" % holder)
            lease["holder"] = identity
            lease["acquired_at"] = now
            lease["expires_at"] = now + INPUT_LEASE_SECONDS
        return "allow", None


# --------------------------------------------------------------------------
# 高权限驻留（契约 §22，B18/D12/D22）
# --------------------------------------------------------------------------

SEE_MASK_NOCLOSEPROCESS = 0x00000040
SW_HIDE = 0
WAIT_TIMEOUT_WIN32 = 0x00000102
ERROR_CANCELLED = 1223                # UAC 弹窗被用户取消
ELEVATE_TASK_NAME_RE = r"[A-Za-z0-9_\-\. ]{1,64}"

shell32.ShellExecuteExW.restype = wintypes.BOOL
kernel32.WaitForSingleObject.argtypes = [HANDLE, wintypes.DWORD]
kernel32.WaitForSingleObject.restype = wintypes.DWORD
kernel32.GetExitCodeProcess.argtypes = [HANDLE, ctypes.POINTER(wintypes.DWORD)]
kernel32.GetExitCodeProcess.restype = wintypes.BOOL
kernel32.TerminateProcess.argtypes = [HANDLE, wintypes.UINT]
kernel32.TerminateProcess.restype = wintypes.BOOL
kernel32.CloseHandle.argtypes = [HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL


class SHELLEXECUTEINFOW(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("fMask", wintypes.ULONG),
        ("hwnd", wintypes.HWND),
        ("lpVerb", wintypes.LPCWSTR),
        ("lpFile", wintypes.LPCWSTR),
        ("lpParameters", wintypes.LPCWSTR),
        ("lpDirectory", wintypes.LPCWSTR),
        ("nShow", ctypes.c_int),
        ("hInstApp", wintypes.HINSTANCE),
        ("lpIDList", ctypes.c_void_p),
        ("lpClass", wintypes.LPCWSTR),
        ("hkeyClass", ctypes.c_void_p),
        ("dwHotKey", wintypes.DWORD),
        ("hIconOrMonitor", wintypes.HANDLE),
        ("hProcess", wintypes.HANDLE),
    ]


shell32.ShellExecuteExW.argtypes = [ctypes.POINTER(SHELLEXECUTEINFOW)]


def build_schtasks_create_args(task_name, python_exe, node_path, config_path, port):
    """计划任务创建命令构造 helper（契约 §22.1，独立可调用，供冒烟白盒校验）。

    返回完整 schtasks 参数列表（含 "schtasks" 前缀）：
        schtasks /create /tn <名> /sc onlogon /rl highest /f
                /tr "\"<python>\" \"<node.py>\" --config <配置路径> --port <端口>"
    /tr 值内的引号结构由 subprocess.list2cmdline 编码为契约所示形态。
    """
    tr_value = '"%s" "%s" --config %s --port %d' % (python_exe, node_path,
                                                    config_path, int(port))
    return ["schtasks", "/create", "/tn", task_name, "/sc", "onlogon",
            "/rl", "highest", "/f", "/tr", tr_value]


def elevate_runexe(file, params, timeout=30):
    """提权运行 helper（契约 §22.1，独立可调用，供冒烟白盒验证错误映射）。

    ShellExecuteExW + SEE_MASK_NOCLOSEPROCESS + verb="runas" + SW_HIDE，
    等待进程退出（超时 timeout 秒，超时终止子进程）。
    返回 (exit_code, 错误信息)：成功 (0, None)；失败/取消/超时返回非零与中文错误。
    """
    # 文件存在性预检：ShellExecuteExW 对不存在的文件同样可能走 UAC 同意流程并
    # 返回 ERROR_CANCELLED，语义错位（实测）且会闪现弹窗；先拦下给出明确错误
    if not os.path.isfile(file):
        return -1, "提权启动失败：文件不存在（%s）" % file
    sei = SHELLEXECUTEINFOW()
    sei.cbSize = ctypes.sizeof(SHELLEXECUTEINFOW)
    sei.fMask = SEE_MASK_NOCLOSEPROCESS
    sei.hwnd = None
    sei.lpVerb = "runas"
    sei.lpFile = file
    sei.lpParameters = params if params else None
    sei.lpDirectory = None
    sei.nShow = SW_HIDE
    if not shell32.ShellExecuteExW(ctypes.byref(sei)):
        err_code = ctypes.get_last_error()
        if err_code == ERROR_CANCELLED:
            return -1, "用户拒绝 UAC 提权"
        return -1, "提权启动失败（WinError %s）：%s" % (
            err_code, os.strerror(err_code) if err_code else "未知错误")
    hproc = sei.hProcess
    if not hproc:
        return -1, "提权启动失败：未获得子进程句柄"
    try:
        waited = kernel32.WaitForSingleObject(hproc, int(timeout * 1000))
        if waited == WAIT_TIMEOUT_WIN32:
            kernel32.TerminateProcess(hproc, 1)
            return -1, "提权确认超时（%d 秒）" % int(timeout)
        exit_code = wintypes.DWORD(0)
        if not kernel32.GetExitCodeProcess(hproc, ctypes.byref(exit_code)):
            return -1, "提权子进程退出码获取失败（WinError %d）" % ctypes.get_last_error()
        if exit_code.value != 0:
            return exit_code.value, "提权子进程异常退出（退出码 %s）" % exit_code.value
        return 0, None
    finally:
        kernel32.CloseHandle(hproc)


def elevate_task_cli(task_name, install, port=None, config_path=None):
    """--elevate-task-install / --elevate-task-remove 子命令（契约 §22.1）：
    进程本身已被提权（由 elevate/install 经 runas 拉起），直接执行对应 schtasks 命令、
    打印结果，以 schtasks 退出码退出；不进入 HTTP 服务。"""
    if config_path is None:
        config_path = CONFIG_FILE or default_config_path()
    if port is None:
        port = ACTUAL_PORT or DEFAULT_PORT
    if install:
        argv = build_schtasks_create_args(task_name, sys.executable,
                                          os.path.abspath(__file__),
                                          config_path, port)
    else:
        argv = ["schtasks", "/delete", "/tn", task_name, "/f"]
    try:
        proc = subprocess.run(argv, capture_output=True)
    except OSError as exc:
        sys.stderr.write("schtasks 执行失败：%s\n" % exc)
        return 1
    out = _decode(proc.stdout).strip()
    err = _decode(proc.stderr).strip()
    if out:
        print(out)
    if err:
        sys.stderr.write(err + "\n")
    print("计划任务%s%s（退出码 %d）" % ("创建" if install else "删除",
          "成功" if proc.returncode == 0 else "失败", proc.returncode))
    return proc.returncode


def elevate_install(task_name):
    """实现 POST /v1/elevate/install 的落盘与内存同步（§22.1，UAC 交互由端点层完成）：
    复核通过后原子写 node.json elevated 标记并同步内存全局。"""
    global ELEVATED_TASK_NAME

    def mutator(cfg):
        cfg["elevated"] = {"task_name": task_name}

    persist_config(mutator)
    ELEVATED_TASK_NAME = task_name


def elevate_remove_mark():
    """实现 POST /v1/elevate/remove 的标记清除（§22.1，幂等）：清内存与 node.json。"""
    global ELEVATED_TASK_NAME

    def mutator(cfg):
        cfg.pop("elevated", None)

    try:
        persist_config(mutator)
    except OSError as exc:
        sys.stderr.write("[警告] elevated 标记清除失败：%s\n" % exc)   # 仅告警（§22.1）
    ELEVATED_TASK_NAME = None


def schtasks_query(task_name):
    """schtasks /query /tn <名> 复核任务是否存在；存在返回 True。"""
    try:
        proc = subprocess.run(["schtasks", "/query", "/tn", task_name],
                              capture_output=True, creationflags=CREATE_NO_WINDOW)
    except OSError:
        return False
    return proc.returncode == 0


# --------------------------------------------------------------------------
# 设备一次确认配对（契约 V1.5 §23，B34/D41/FR-15）
# --------------------------------------------------------------------------

def is_loopback(ip):
    """回环判定（契约 §23.1：仅 127.0.0.1/::1，127.0.0.0/8 其余地址不算）。
    独立 helper，便于冒烟白盒验证（对照 is_private 的函数级口径）。"""
    return ip in PAIR_LOOPBACK


def _pair_lazy_expire_locked():
    """会话过期惰性判定（§23.2，需持锁，无后台线程）：
    pending/approved 超 expires_at（pending 为创建+pending_ttl、approved 为
    确认+code_ttl）即转 expired；终态保留在表内供错误回报，下次 begin 覆盖。"""
    sess = PAIR_SESSION
    if sess is not None and sess["state"] in PAIR_ACTIVE_STATES \
            and time.time() > sess["expires_at"]:
        sess["state"] = "expired"


def pair_begin(client):
    """POST /v1/pair/begin 业务逻辑（契约 §23.3）：来源限频（含被 429 拒绝的刷新）
    → 单活跃会话检查（活跃不重置不替换）→ 创建 pending 会话（终态旧会话覆盖）。

    返回 (data, err, status)：成功 (data, None, 200)；失败 (None, (code, message), status)。
    """
    global PAIR_SESSION
    now = time.time()
    with PAIR_LOCK:
        # ① 来源限频：距上次 begin 不足 begin_interval → 429；
        #    本次 begin（无论成败，含被 429 拒绝的）刷新 last_begin_ts
        last = PAIR_BEGIN_TS.get(client)
        PAIR_BEGIN_TS[client] = now
        if PAIR_BEGIN_INTERVAL > 0 and last is not None \
                and now - last < PAIR_BEGIN_INTERVAL:
            wait = max(1, int(round(PAIR_BEGIN_INTERVAL - (now - last))))
            return None, ("PAIR_RATE_LIMITED",
                          "配对请求过于频繁，请约 %d 秒后重试" % wait), 429
        # ② 惰性过期 + 单活跃会话检查：活跃（pending/approved）→ 409 不重置不替换
        _pair_lazy_expire_locked()
        if PAIR_SESSION is not None and PAIR_SESSION["state"] in PAIR_ACTIVE_STATES:
            return None, ("PAIR_SESSION_ACTIVE",
                          "已存在活跃配对会话（expires_at=%d），请由被控端确认、"
                          "拒绝或等其过期后再试" % int(PAIR_SESSION["expires_at"])), 409
        # ③ 创建 pending 会话（有终态旧会话则覆盖替换）
        session_id = uuid.uuid4().hex[:16]
        PAIR_SESSION = {
            "session_id": session_id,
            "state": "pending",
            "source_ip": client,
            "created_at": now,
            "expires_at": now + PAIR_PENDING_TTL,
            "code": None,               # approved 后生成 6 位数字码（§23.2）
            "attempts": 0,              # confirm 猜码失败计数
        }
        return {"session_id": session_id, "state": "pending",
                "expires_at": PAIR_SESSION["expires_at"]}, None, 200


def pair_session_snapshot():
    """GET /v1/pair/session 业务逻辑（契约 §23.3）：无会话 → {"state": "idle"}；
    有会话 → 全字段 + approved 专属 code/code_expires_at/attempts_left。"""
    with PAIR_LOCK:
        _pair_lazy_expire_locked()
        sess = PAIR_SESSION
        if sess is None:
            return {"state": "idle"}
        data = {
            "session_id": sess["session_id"],
            "state": sess["state"],
            "source_ip": sess["source_ip"],
            "created_at": sess["created_at"],
            "expires_at": sess["expires_at"],
        }
        if sess["state"] == "approved":
            data["code"] = sess["code"]
            data["code_expires_at"] = sess["expires_at"]
            data["attempts_left"] = max(0, PAIR_MAX_ATTEMPTS - sess["attempts"])
        return data


def pair_approve():
    """POST /v1/pair/approve 业务逻辑（契约 §23.3）：pending → approved 生成 6 位码；
    幂等（已 approved 未过期 → 同一码与时效）；无活跃会话/已过期 → (None, err, 404)。

    返回 (data, err, status)；err 为 (code, message)。approve 不消耗尝试次数。
    """
    with PAIR_LOCK:
        _pair_lazy_expire_locked()
        sess = PAIR_SESSION
        if sess is None or sess["state"] not in PAIR_ACTIVE_STATES:
            return None, ("PAIR_NO_SESSION", "无待确认的配对会话"), 404
        if sess["state"] == "approved":
            # 幂等：确认窗重开/进程重启后重读场景 → 返回同一 code 与 expires_at
            return {"session_id": sess["session_id"], "code": sess["code"],
                    "expires_at": sess["expires_at"]}, None, 200
        # pending → approved：6 位数字码（含前导零 000000–999999 等概率，§23.2）
        sess["state"] = "approved"
        sess["code"] = "%06d" % secrets.randbelow(1000000)
        sess["expires_at"] = time.time() + PAIR_CODE_TTL
        sess["attempts"] = 0
        return {"session_id": sess["session_id"], "code": sess["code"],
                "expires_at": sess["expires_at"]}, None, 200


def pair_reject():
    """POST /v1/pair/reject 业务逻辑（契约 §23.3）：活跃会话 → 立即 voided
    （被控端拒绝则连接不建立）；无活跃会话 → (None, err, 404)。"""
    with PAIR_LOCK:
        _pair_lazy_expire_locked()
        sess = PAIR_SESSION
        if sess is None or sess["state"] not in PAIR_ACTIVE_STATES:
            return None, ("PAIR_NO_SESSION", "无可拒绝的配对会话"), 404
        session_id = sess["session_id"]
        sess["state"] = "voided"
        return {"rejected": True, "session_id": session_id}, None, 200


def pair_confirm(code, name):
    """POST /v1/pair/confirm 业务逻辑（契约 §23.3）：码校验 → 签发身份令牌。

    参数合法性由调用方先行校验（400 不消耗尝试次数）。返回 (data, err, status)：
    - 成功：({token, identity, device_id, cert_fingerprint, node_version}, None, 200)，
      会话转 consumed，新身份已写入配置文件与内存 IDENTITIES；
    - 失败：err 为 (错误码, message)，会话按状态机转移（猜码达上限 → voided）。
    """
    with PAIR_LOCK:
        _pair_lazy_expire_locked()
        sess = PAIR_SESSION
        if sess is None:
            return None, ("PAIR_NO_SESSION", "无配对会话"), 404
        if sess["state"] == "consumed":
            return None, ("PAIR_NO_SESSION", "配对会话已消费（码已使用）"), 404
        if sess["state"] == "voided":
            return None, ("PAIR_NO_SESSION", "配对会话已作废"), 404
        if sess["state"] == "pending":
            return None, ("PAIR_NOT_APPROVED",
                          "配对会话尚未经被控端本地确认"), 409
        if sess["state"] == "expired":
            return None, ("PAIR_EXPIRED", "配对码已过期，请重新发起配对"), 400
        # approved：配对码常量时间比较（§23.2）
        if not hmac.compare_digest(code.encode("utf-8"),
                                   (sess["code"] or "").encode("utf-8")):
            sess["attempts"] += 1
            if sess["attempts"] >= PAIR_MAX_ATTEMPTS:
                sess["state"] = "voided"        # 防暴力猜码：会话作废（§23.3）
                return None, ("PAIR_ATTEMPTS_EXCEEDED",
                              "配对码尝试已达上限 %d，会话已作废" % PAIR_MAX_ATTEMPTS), 403
            left = PAIR_MAX_ATTEMPTS - sess["attempts"]
            return None, ("PAIR_CODE_MISMATCH",
                          "配对码不匹配，剩余可尝试次数：%d" % left), 401
        # 码匹配 → 签发身份：name 冲突自动后缀 -2/-3…（§17.3 同款口径）
        existing = {item["name"] for item in IDENTITIES}
        effective = name
        suffix = 2
        while effective in existing:
            effective = "%s-%d" % (name, suffix)
            suffix += 1
        if len(IDENTITIES) >= MAX_IDENTITIES:
            # 身份列表满：会话保持 approved（可先 rm 身份腾位后重试，契约未定 voided）
            return None, ("BAD_REQUEST", "身份列表已达上限 %d，无法签发新身份"
                          % MAX_IDENTITIES), 400
        token = uuid.uuid4().hex            # 32 hex（§2.1/D38，同既有生成口径）

        def mutator(cfg):
            tokens = cfg.get("tokens")
            if not isinstance(tokens, list):
                tokens = [{"name": item["name"], "token": item["token"]}
                          for item in IDENTITIES]
            tokens.append({"name": effective, "token": token})
            cfg["tokens"] = tokens

        persist_config(mutator)             # 原子写回 node.json tokens（§23.3）
        IDENTITIES.append({"name": effective, "token": token})
        sess["state"] = "consumed"          # 码一次性：consumed 即失效
        return {"token": token, "identity": effective,
                "device_id": DEVICE_ID, "cert_fingerprint": CERT_FINGERPRINT,
                "node_version": NODE_VERSION}, None, 200


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
    "/v1/fs/stat", "/v1/fs/checksum", "/v1/fs/download",
    "/v1/screen", "/v1/audit", "/v1/task/list",
    "/v1/pair/session",                                     # M4 新增（§23，仅回环）
})
KNOWN_POST_PATHS = frozenset({
    "/v1/exec", "/v1/input", "/v1/fs/write", "/v1/self-update",
    "/v1/fs/delete", "/v1/fs/mkdir", "/v1/fs/move",
    "/v1/fs/upload/begin", "/v1/fs/upload/chunk",
    "/v1/fs/upload/commit", "/v1/fs/upload/abort",
    "/v1/update/enroll", "/v1/update/pin",                  # S3 新增（§20）
    "/v1/elevate/install", "/v1/elevate/remove",            # S3 新增（§22）
    "/v1/pair/begin", "/v1/pair/confirm",                   # M4 新增（§23，私网）
    "/v1/pair/approve", "/v1/pair/reject",                  # M4 新增（§23，仅回环）
})


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "xd-node/" + NODE_VERSION

    # 每请求重置的审计状态（见 dispatch）
    _resp_status = None
    _resp_code = None
    _audit_target = ""
    _identity = ""                      # 本请求身份名（guard 通过后写入）

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

    def fail(self, code, message, status=400, extra=None):
        """错误响应（§1.3 包络）。extra：可选结构化附加字段（B42 起 SANDBOX_DENIED
        附 allowed_roots/staging_root，供调用方机读；其余错误不传）。"""
        err = {"code": code, "message": message}
        if extra:
            err.update(extra)
        self.send_json({"ok": False, "error": err}, status)

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

    def require_workspace(self, raw_path):
        """写方向白名单校验（契约 §14.2/§14.3）。通过返回 True；失败已发送响应。

        SANDBOX_DENIED 属业务 403：审计 target 由调用方先行设置，照常落审计（§8.2）。
        约束范围：fs/write、fs/delete、fs/mkdir、fs/move（src+dst）、upload/begin。
        B42 起（V1.6）拒绝响应自带指引：message 明示当前允许的根（仅剩默认
        暂存时附配置入口），error 对象附 allowed_roots/staging_root 供机读。
        """
        ok, reason, _norm = workspace_hit(raw_path)
        if ok:
            return True
        if reason == "root_missing":
            self.fail("BAD_REQUEST", "工作空间根目录不存在：%s" % raw_path, 400)
        elif USER_WORKSPACE_ROOTS:
            self.fail("SANDBOX_DENIED",
                      "路径超出工作空间白名单：%s；当前允许的根：%s"
                      % (raw_path, "；".join(WORKSPACE_ROOTS)), 403,
                      extra={"allowed_roots": list(WORKSPACE_ROOTS),
                             "staging_root": STAGING_ROOT or None})
        else:
            self.fail("SANDBOX_DENIED",
                      "路径超出工作空间白名单：%s；默认仅允许 node 暂存目录 %s；"
                      "如需写入其他位置，请在被控端 node.json 配置 workspace 键"
                      "或以 --workspace 启动参数添加允许根"
                      "（被控端本地配置，控制端不可远程修改）"
                      % (raw_path, STAGING_ROOT or "（未就绪）"), 403,
                      extra={"allowed_roots": list(WORKSPACE_ROOTS),
                             "staging_root": STAGING_ROOT or None})
        return False

    def _is_known_path(self, path):
        return (path in KNOWN_GET_PATHS or path in KNOWN_POST_PATHS
                or path.startswith("/v1/job/") or path.startswith("/v1/task/"))

    def audit(self, parsed, identity, result, code):
        """写一条审计（§8）。调用方保证已通过来源校验。"""
        # §8.2：校验失败（401/409/400，含业务 400 与来源 403）target 置空；例外（照常记录，
        # 已鉴权主体的可追溯行为）：
        #   - 业务 403（SANDBOX_DENIED 白名单越界）（S2）
        #   - 409 INPUT_LEASE_TAKEN（输入冲突/被抢占）与 400 UPDATE_REJECTED（更新包被拒）（S3）
        clear = (result in (400, 401, 409)
                 or (result == 403 and code != "SANDBOX_DENIED"))
        keep = ((result == 403 and code == "SANDBOX_DENIED")
                or (result == 409 and code == "INPUT_LEASE_TAKEN")
                or (result == 400 and code == "UPDATE_REJECTED"))
        if clear and not keep:
            target = ""
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

    # ---- pair 族 guard 变体与分发（契约 V1.5 §23.1：免令牌免防重放，§1.2 唯一例外）----
    def guard_pair(self, parsed):
        """pair 族来源校验（§2.3 变体）：① 私网来源照常；② 回环限定端点另加
        仅 127.0.0.1/::1 检查。跳过令牌与防重放校验（既有 guard 链本体零改动）。

        通过返回 True；失败已发送响应。非私网 403 不落审计（§8.2 既有口径）；
        回环限定拒绝 403 是通过①后的来源限定拒绝——要落审计（identity=""）。
        """
        client = self.client_address[0]
        if not is_private(client):
            self.fail("FORBIDDEN", "仅允许局域网访问：%s" % client, 403)
            return False
        if parsed.path in PAIR_LOOPBACK_PATHS and not is_loopback(client):
            self.audit(parsed, identity="", result=403, code="FORBIDDEN")
            self.fail("FORBIDDEN",
                      "该端点仅允许本机回环（127.0.0.1/::1）访问：%s" % client, 403)
            return False
        return True

    def dispatch_pair(self, parsed):
        """/v1/pair/* 分发入口：guard 变体 → pair 路由 → finally 审计。
        全族审计 identity 一律空字符串（§23.5）；码值/令牌永不入 target。"""
        if not self.guard_pair(parsed):
            return
        try:
            self.route_pair(parsed)
        except Exception as exc:
            self.fail("INTERNAL", str(exc), 500)
        finally:
            self.audit(parsed, identity="",
                       result=self._resp_status if self._resp_status is not None else 500,
                       code=self._resp_code)

    def route_pair(self, parsed):
        """pair 族路由：按 方法+路径 分发；不匹配组合 → 404（同 _unknown_route 口径）。"""
        path = parsed.path
        if self.command == "GET":
            if path == "/v1/pair/session":
                data = pair_session_snapshot()
                self.ok(data)
                return
        elif self.command == "POST":
            # begin 永不 set_target（§8.3 一律空）；approve/reject 成功前 set_target
            if path == "/v1/pair/begin":
                self.read_body()                     # 空体或 {}（排空请求体保 keep-alive）
                data, err, status = pair_begin(self.client_address[0])
                if err:
                    self.fail(err[0], err[1], status)
                else:
                    self.ok(data)
                return
            if path == "/v1/pair/approve":
                self.read_body()
                data, err, status = pair_approve()
                if err:
                    self.fail(err[0], err[1], status)
                else:
                    self.set_target("session=%s" % data["session_id"])
                    self.ok(data)
                return
            if path == "/v1/pair/reject":
                self.read_body()
                data, err, status = pair_reject()
                if err:
                    self.fail(err[0], err[1], status)
                else:
                    self.set_target("session=%s" % data["session_id"])
                    self.ok(data)
                return
            if path == "/v1/pair/confirm":
                self.route_pair_confirm()
                return
        self.fail("NOT_FOUND", "未知接口或方法：%s %s" % (self.command, path), 404)

    def route_pair_confirm(self):
        """POST /v1/pair/confirm（契约 §23.3）：参数校验（400 不消耗尝试次数）→
        码校验 → 签发。成功 set_target("name=<生效名>")；失败路径一律不 set_target
        （§8.3：确认族失败 target 空，配对码值永不落审计）。"""
        body = self.read_body()
        code = body.get("code")
        name = body.get("name")
        if not isinstance(code, str) or not re.fullmatch(r"[0-9]{6}", code):
            self.fail("BAD_REQUEST", "code 必须是 6 位数字字符串", 400)
            return
        if not isinstance(name, str) or not 1 <= len(name) <= 64:
            self.fail("BAD_REQUEST", "name 必须是 1–64 字符的字符串", 400)
            return
        data, err, status = pair_confirm(code, name)
        if err:
            self.fail(err[0], err[1], status)
            return
        self.set_target("name=%s" % data["identity"])
        self.ok(data)

    # ---- 分发入口：鉴权 → 路由 → 审计 ----
    def dispatch(self, router):
        self._resp_status = None
        self._resp_code = None
        self._audit_target = ""
        self._identity = ""
        parsed = urlparse(self.path)
        if parsed.path.startswith("/v1/pair/"):
            # V1.5 §23：pair 族按路径前缀分流走 guard 变体（免令牌免防重放），
            # 既有 guard()/check_replay() 本体与非 pair 路径行为零改动（E-02）
            self.dispatch_pair(parsed)
            return
        identity = self.guard(parsed)
        if identity is None:
            return
        self._identity = identity
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
            # S3 新增 rollback_flag（§6.1/§20.4）：node.py 同目录存在 rollback.flag
            # → true（看门狗曾回滚、需人工处置），每次请求实时判断文件存在性
            self.ok({"status": "up", "node_version": NODE_VERSION,
                     "rollback_flag": rollback_flag_exists()})
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
            try:
                wait = min(float(query.get("wait", 0)), 120.0)
            except (TypeError, ValueError):
                self.fail("BAD_REQUEST", "wait 参数必须是数字（秒）", 400)
                return
            deadline = time.time() + wait
            while True:
                job = get_job(job_id)
                if job is not None:
                    # 长轮询仅对内存任务生效（库中记录均为终态，§6.4）
                    if job["status"] != "running" or time.time() >= deadline:
                        self.ok(job)
                        return
                    time.sleep(0.15)
                    continue
                # 内存 miss → 查任务历史库（§6.4/S2）；均无 → 404
                row = db_get_job(job_id)
                if row is not None:
                    self.ok(row)
                    return
                self.fail("NOT_FOUND", "任务不存在：%s" % job_id, 404)
                return

        if path == "/v1/task/list":
            # S2 新增（契约 §15.2）：任务历史列表，一期仅本人可见（D34）
            self.set_target("filter=" + sanitize_secret(parsed.query))
            try:
                self.ok(task_list(query, self._identity))
            except TaskAuthzError:
                self.fail("FORBIDDEN", "任务列表仅限查询本人任务（identity 参数越权）", 403)
            except ParamError as exc:
                self.fail("BAD_REQUEST", str(exc), 400)
            return

        if path.startswith("/v1/task/"):
            # S2 新增（契约 §15.2）：任务详情（含 stdout/stderr）
            # 不存在或 identity ≠ 请求者一律 404（不泄露他人任务存在性，D34）；target 恒空（§8.3）
            task_id = path[len("/v1/task/"):]
            row = db_get_task_of(task_id, self._identity)
            if row is None:
                self.fail("NOT_FOUND", "任务不存在：%s" % task_id, 404)
                return
            self.ok(row)
            return

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

        if path == "/v1/fs/checksum":
            # S2 新增（契约 §13.1）：分块流式 MD5，不整载
            ck_path = query.get("path")
            self.set_target("path=" + (ck_path or ""))
            if not ck_path:
                self.fail("BAD_REQUEST", "缺少 path 参数", 400)
                return
            if not os.path.exists(ck_path):
                self.fail("NOT_FOUND", "文件不存在：%s" % ck_path, 404)
                return
            if os.path.isdir(ck_path):
                self.fail("BAD_REQUEST", "目标是目录，仅支持文件：%s" % ck_path, 400)
                return
            self.ok({"path": os.path.abspath(ck_path),
                     "size": os.path.getsize(ck_path),
                     "md5": md5_file(ck_path)})
            return

        if path == "/v1/fs/download":
            # S2 新增（契约 §13.2）：原始字节响应 + Range 206
            self.handle_fs_download(query)
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

    def handle_fs_download(self, query):
        """实现 GET /v1/fs/download（契约 §13.2）。

        无 Range → 200 全量流式；Range: bytes=start-end → 206 + Content-Range
        （end≥size 截断为 size-1；start≥size / start>end / 非法格式 / 后缀与多区间 → 400）。
        响应头恒带 X-File-Size / X-File-MD5 / application/octet-stream；
        响应体为原始字节，按 1MB 缓冲循环发送，Content-Length 恒准确（keep-alive 依赖）。
        """
        dl_path = query.get("path")
        range_header = self.headers.get("Range")
        if not dl_path:
            self.fail("BAD_REQUEST", "缺少 path 参数", 400)
            return
        self.set_target("path=%s range=full" % dl_path)   # §8.3（后续按实际区间覆盖）
        if not os.path.exists(dl_path):
            self.fail("NOT_FOUND", "文件不存在：%s" % dl_path, 404)
            return
        if os.path.isdir(dl_path):
            self.fail("BAD_REQUEST", "目标是目录，仅支持文件：%s" % dl_path, 400)
            return
        size = os.path.getsize(dl_path)
        digest = md5_file(dl_path)              # X-File-MD5：全文件 MD5（1MB 分块）
        start, end = 0, size - 1
        range_text = "full"
        is_partial = False
        if range_header:
            # 仅支持 bytes=start-end 闭区间单区间形式（§13.2）
            m = re.fullmatch(r"\s*bytes=(\d+)-(\d+)\s*", range_header)
            if not m:
                self.fail("BAD_REQUEST",
                          "Range 头格式不支持（仅支持 bytes=start-end 单区间）", 400)
                return
            start, end = int(m.group(1)), int(m.group(2))
            if start >= size:
                self.fail("BAD_REQUEST",
                          "Range 起始位置超出文件大小（size=%d）" % size, 400)
                return
            if start > end:
                self.fail("BAD_REQUEST", "Range 起始位置大于结束位置", 400)
                return
            if end >= size:
                end = size - 1                  # 标准 HTTP 语义：截断到末尾
            is_partial = True
            range_text = "%d-%d" % (start, end)
        self.set_target("path=%s range=%s" % (dl_path, range_text))   # §8.3
        length = end - start + 1
        status = 206 if is_partial else 200
        self._resp_status = status
        self._resp_code = None
        self.send_response(status)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(length))
        self.send_header("X-File-Size", str(size))
        self.send_header("X-File-MD5", digest)
        if is_partial:
            self.send_header("Content-Range", "bytes %d-%d/%d" % (start, end, size))
        self.end_headers()
        try:
            with open(dl_path, "rb") as fh:
                fh.seek(start)
                remaining = length
                while remaining > 0:
                    block = fh.read(min(DOWNLOAD_BLOCK, remaining))
                    if not block:
                        break                   # 文件被并发截断的防御
                    self.wfile.write(block)
                    remaining -= len(block)
        except OSError:
            self.close_connection = True        # 客户端中断，放弃剩余字节

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
                identity=self._identity,        # 任务历史记录发起身份（§15.1）
            )
            self.ok({"job_id": job_id})
            return

        if path == "/v1/input":
            body = self.read_body()
            actions = body.get("actions")
            if isinstance(actions, list):
                self.set_target("actions=" + ",".join(
                    a.get("type", "") if isinstance(a, dict) else "" for a in actions))
            # ---- S3 输入租约（契约 §21.2）：判定先于动作执行与锁屏/交互检查 ----
            # 请求头 X-Input-Lease: acquire|renew|release|take（值非法 → 400）；
            # 无头 = 隐式 acquire（偏差 10：兼容 S1/S2 无头客户端）。空 actions 合法
            # （供 xd release 释放租约使用）。409 INPUT_LEASE_TAKEN 不执行动作。
            lease_mode = self.headers.get("X-Input-Lease")
            if lease_mode is not None and lease_mode not in INPUT_LEASE_ACTIONS:
                self.fail("BAD_REQUEST",
                          "X-Input-Lease 头非法（acquire/renew/release/take）", 400)
                return
            verdict, message = input_lease_check(self._identity, lease_mode)
            if verdict == "deny409":
                self.fail("INPUT_LEASE_TAKEN", message, 409)
                return
            if verdict == "deny400":
                self.fail("BAD_REQUEST", message, 400)
                return
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
                # S3 新增（§6.7/§21.3）：处理完成后的租约状态快照
                "lease": input_lease_snapshot(self._identity),
            })
            return

        if path == "/v1/fs/write":
            body = self.read_body()
            write_path = body.get("path")
            if not isinstance(write_path, str) or not write_path:
                self.fail("BAD_REQUEST", "缺少 path", 400)
                return
            if body.get("data_b64") is not None:
                try:
                    payload_len = len(base64.b64decode(body["data_b64"]))
                except Exception:
                    self.fail("BAD_REQUEST", "data_b64 解码失败", 400)
                    return
            else:
                payload_len = len((body.get("text") or "").encode("utf-8"))
            self.set_target("path=%s bytes=%d" % (write_path, payload_len))
            if not self.require_workspace(write_path):   # S2 起受白名单约束（§14.2）
                return
            try:
                self.ok(fs_write(write_path, body.get("text"),
                                 body.get("data_b64"), bool(body.get("append"))))
            except OSError as exc:
                self.fail("BAD_REQUEST", "写入失败：%s" % exc, 400)
            return

        if path == "/v1/fs/delete":
            # S2 新增（契约 §14.4）：仅文件、需 confirm 显式确认（D24）
            body = self.read_body()
            del_path = body.get("path")
            self.set_target("path=%s"
                            % (del_path if isinstance(del_path, str) else ""))
            if not isinstance(del_path, str) or not del_path:
                self.fail("BAD_REQUEST", "缺少 path", 400)
                return
            if not self.require_workspace(del_path):
                return
            if body.get("confirm") is not True:
                self.fail("BAD_REQUEST", "删除需显式确认：confirm 必须为 true", 400)
                return
            if not os.path.exists(del_path):
                self.fail("NOT_FOUND", "文件不存在：%s" % del_path, 404)
                return
            if os.path.isdir(del_path):
                self.fail("BAD_REQUEST", "仅支持删除文件，不支持目录：%s" % del_path, 400)
                return
            try:
                os.remove(del_path)
            except OSError as exc:
                self.fail("BAD_REQUEST", "删除失败：%s" % exc, 400)
                return
            self.ok({"path": os.path.abspath(del_path), "deleted": True})
            return

        if path == "/v1/fs/mkdir":
            # S2 新增（契约 §14.4）：递归创建，已存在视为成功
            body = self.read_body()
            mkdir_path = body.get("path")
            self.set_target("path=%s"
                            % (mkdir_path if isinstance(mkdir_path, str) else ""))
            if not isinstance(mkdir_path, str) or not mkdir_path:
                self.fail("BAD_REQUEST", "缺少 path", 400)
                return
            if not self.require_workspace(mkdir_path):
                return
            try:
                os.makedirs(mkdir_path, exist_ok=True)
            except OSError as exc:
                self.fail("BAD_REQUEST", "创建目录失败：%s" % exc, 400)
                return
            self.ok({"path": os.path.abspath(mkdir_path), "created": True})
            return

        if path == "/v1/fs/move":
            # S2 新增（契约 §14.4）：src 与 dst 均须在白名单内（§14.2）
            body = self.read_body()
            mv_src = body.get("src")
            mv_dst = body.get("dst")
            self.set_target("src=%s dst=%s" % (
                mv_src if isinstance(mv_src, str) else "",
                mv_dst if isinstance(mv_dst, str) else ""))
            if (not isinstance(mv_src, str) or not mv_src
                    or not isinstance(mv_dst, str) or not mv_dst):
                self.fail("BAD_REQUEST", "缺少 src 或 dst", 400)
                return
            if not self.require_workspace(mv_src):
                return
            if not self.require_workspace(mv_dst):
                return
            if not os.path.exists(mv_src):
                self.fail("NOT_FOUND", "源不存在：%s" % mv_src, 404)
                return
            if os.path.exists(mv_dst):
                self.fail("BAD_REQUEST", "目标已存在：%s" % mv_dst, 400)
                return
            try:
                try:
                    os.replace(mv_src, mv_dst)       # 同卷（文件与目录均可）
                except OSError:
                    shutil.move(mv_src, mv_dst)      # 跨卷：复制 + 删除
            except OSError as exc:
                self.fail("BAD_REQUEST", "移动失败：%s" % exc, 400)
                return
            self.ok({"src": os.path.abspath(mv_src),
                     "dst": os.path.abspath(mv_dst), "moved": True})
            return

        if path == "/v1/fs/upload/begin":
            # S2 新增（契约 §13.3）：上传三段式之 begin，白名单在此校验
            body = self.read_body()
            up_path = body.get("path")
            up_size = body.get("size")
            up_md5 = body.get("md5")
            if not isinstance(up_path, str) or not up_path:
                self.fail("BAD_REQUEST", "缺少 path", 400)
                return
            if (not isinstance(up_size, int) or isinstance(up_size, bool)
                    or up_size < 0):
                self.fail("BAD_REQUEST", "size 必须是 ≥0 的整数", 400)
                return
            if not isinstance(up_md5, str) or not re.fullmatch(r"[0-9a-f]{32}", up_md5):
                self.fail("BAD_REQUEST", "md5 必须是 32 位小写十六进制", 400)
                return
            self.set_target("path=%s size=%d" % (up_path, up_size))   # §8.3
            if not self.require_workspace(up_path):
                return
            try:
                self.ok(upload_begin(up_path, up_size, up_md5))
            except UploadError as exc:
                self.fail(exc.code, str(exc), exc.status)
            return

        if path == "/v1/fs/upload/chunk":
            # S2 新增（契约 §13.3）：上传三段式之 chunk，只引用 upload_id（begin 已校验白名单）
            body = self.read_body()
            upload_id = body.get("upload_id")
            offset = body.get("offset")
            data_b64 = body.get("data_b64")
            if not isinstance(upload_id, str) or not upload_id:
                self.fail("BAD_REQUEST", "缺少 upload_id", 400)
                return
            self.set_target("upload=%s offset=%s" % (upload_id, offset))   # §8.3
            if (not isinstance(offset, int) or isinstance(offset, bool)
                    or offset < 0):
                self.fail("BAD_REQUEST", "offset 必须是 ≥0 的整数", 400)
                return
            if not isinstance(data_b64, str):
                self.fail("BAD_REQUEST", "缺少 data_b64", 400)
                return
            try:
                data = base64.b64decode(data_b64, validate=True)
            except Exception:
                self.fail("BAD_REQUEST", "data_b64 解码失败", 400)
                return
            try:
                self.ok(upload_chunk(upload_id, offset, data))
            except UploadError as exc:
                self.fail(exc.code, str(exc), exc.status)
            return

        if path == "/v1/fs/upload/commit":
            # S2 新增（契约 §13.3）：上传三段式之 commit，MD5 校验失败清理会话与临时文件
            body = self.read_body()
            upload_id = body.get("upload_id")
            if not isinstance(upload_id, str) or not upload_id:
                self.fail("BAD_REQUEST", "缺少 upload_id", 400)
                return
            self.set_target("upload=%s" % upload_id)   # §8.3
            try:
                result = upload_commit(upload_id)
            except UploadError as exc:
                self.fail(exc.code, str(exc), exc.status)
                return
            self.set_target("upload=%s size=%d" % (upload_id, result["size"]))
            self.ok(result)
            return

        if path == "/v1/fs/upload/abort":
            # S2 新增（契约 §13.3）：上传三段式之 abort
            body = self.read_body()
            upload_id = body.get("upload_id")
            if not isinstance(upload_id, str) or not upload_id:
                self.fail("BAD_REQUEST", "缺少 upload_id", 400)
                return
            self.set_target("upload=%s" % upload_id)   # §8.3
            try:
                self.ok(upload_abort(upload_id))
            except UploadError as exc:
                self.fail(exc.code, str(exc), exc.status)
            return

        if path == "/v1/self-update":
            # S3 签名升级（契约 §6.8/§20.2）：请求体 {"source_b64","sha256","hmac"}，
            # 校验顺序 sha256 → hmac → trusted_hashes 白名单，任一失败 → 400
            # UPDATE_REJECTED 且不落盘；旧格式缺 sha256/hmac → 400 UPDATE_REJECTED
            # （E-02 唯一兼容例外，偏差 9）。审计 target=bytes=<N>，缺 source_b64/
            # 未解码记 bytes=0（§8.3）。
            body = self.read_body()
            self.set_target("bytes=0")
            source_b64 = body.get("source_b64")
            if not isinstance(source_b64, str) or not source_b64:
                self.fail("BAD_REQUEST", "缺少 source_b64", 400)
                return
            try:
                raw = base64.b64decode(source_b64)
            except Exception:
                self.fail("BAD_REQUEST", "source_b64 解码失败", 400)
                return
            self.set_target("bytes=%d" % len(raw))
            reject = update_signature_verify(raw, body.get("sha256"), body.get("hmac"))
            if reject is not None:
                self.fail("UPDATE_REJECTED", reject, 400)
                return
            try:
                result = self_update(raw, ACTUAL_PORT)
            except ValueError as exc:
                # 语法校验失败返回 400（契约 §6.8，"源码语法错误"文案维持现状）
                self.fail("BAD_REQUEST", str(exc), 400)
                return
            self.ok(result)
            threading.Timer(0.4, lambda: os._exit(0)).start()
            return

        if path == "/v1/update/enroll":
            # S3 新增（契约 §20.1）：每次调用生成新 hmac_key、持久化并返回（轮换，
            # 旧密钥随即失效）。审计 target 恒为空字符串——hmac_key 永不落审计/日志/横幅。
            key = update_enroll()
            self.ok({"hmac_key": key})
            return

        if path == "/v1/update/pin":
            # S3 新增（契约 §20.2）：请求体 {"sha256": <64hex 小写>} → 追加
            # trusted_hashes（去重、上限 16、超限 → 400）。
            body = self.read_body()
            sha_value = body.get("sha256")
            if not isinstance(sha_value, str) or not re.fullmatch(r"[0-9a-f]{64}",
                                                                  sha_value):
                self.fail("BAD_REQUEST", "sha256 必须是 64 位小写十六进制", 400)
                return
            self.set_target("sha256=%s" % sha_value)
            added, reject = update_pin_add(sha_value)
            if not added:
                self.fail("BAD_REQUEST", reject, 400)
                return
            self.ok({"added": True, "trusted_hashes": list(TRUSTED_HASHES)})
            return

        if path == "/v1/elevate/install":
            # S3 新增（契约 §22.1）：经 ShellExecuteW runas 提权运行自身提权子命令，
            # 由子进程执行 schtasks /create（登录触发 + 最高权限）；UAC 拒绝/超时/
            # 子进程失败 → 500 INTERNAL 明确中文错误，不写 elevated 标记。
            body = self.read_body()
            task_name = body.get("task_name")
            if task_name is None:
                task_name = DEFAULT_ELEVATE_TASK
            self.set_target("task=%s" % task_name)
            if (not isinstance(task_name, str)
                    or not re.fullmatch(ELEVATE_TASK_NAME_RE, task_name)):
                self.fail("BAD_REQUEST",
                          "task_name 非法（限 [A-Za-z0-9_\\-\\. ]{1,64} 字符）", 400)
                return
            params = subprocess.list2cmdline([
                os.path.abspath(__file__),
                "--elevate-task-install", task_name,
                "--config", CONFIG_FILE,
                "--port", str(ACTUAL_PORT),
            ])
            exit_code, err = elevate_runexe(sys.executable, params, timeout=30)
            if exit_code != 0:
                if err:
                    self.fail("INTERNAL", err, 500)   # UAC 拒绝/超时/启动失败明确报错
                else:
                    self.fail("INTERNAL",
                              "计划任务创建失败：提权子进程退出码 %s" % exit_code, 500)
                return
            if not schtasks_query(task_name):
                self.fail("INTERNAL",
                          "计划任务创建失败：schtasks /query 复核未找到任务 %s" % task_name,
                          500)
                return
            try:
                elevate_install(task_name)
            except OSError as exc:
                self.fail("INTERNAL", "elevated 标记写入失败：%s" % exc, 500)
                return
            self.ok({"installed": True, "task_name": task_name})
            return

        if path == "/v1/elevate/remove":
            # S3 新增（契约 §22.1）：schtasks /delete（当前权限直接执行，不经提权）；
            # 任务不存在视为已清理（幂等）；其他失败 → 500 INTERNAL（提示手动清理）。
            body = self.read_body()
            task_name = body.get("task_name")
            if task_name is None:
                task_name = ELEVATED_TASK_NAME
            self.set_target("task=%s" % (task_name if isinstance(task_name, str)
                                         else ""))
            if (not isinstance(task_name, str) or not task_name
                    or not re.fullmatch(ELEVATE_TASK_NAME_RE, task_name)):
                self.fail("BAD_REQUEST",
                          "task_name 非法或缺失（节点亦无高权限驻留标记可取）", 400)
                return
            if schtasks_query(task_name):
                try:
                    proc = subprocess.run(["schtasks", "/delete", "/tn", task_name, "/f"],
                                          capture_output=True,
                                          creationflags=CREATE_NO_WINDOW)
                except OSError as exc:
                    self.fail("INTERNAL", "删除计划任务失败：%s" % exc, 500)
                    return
                if proc.returncode != 0:
                    summary = (_decode(proc.stderr).strip()
                               or _decode(proc.stdout).strip())[:200]
                    self.fail("INTERNAL",
                              "删除计划任务失败：%s（可手动执行 schtasks /delete /tn %s /f 清理）"
                              % (summary or ("退出码 %d" % proc.returncode), task_name),
                              500)
                    return
            # 任务不存在（query 未命中）视为已清理，同样清除标记并成功返回（幂等）
            elevate_remove_mark()
            self.ok({"removed": True, "task_name": task_name})
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


# --------------------------------------------------------------------------
# 发现广播发送（契约 §19.1，B12/D25/D38；node 只发送、不监听 51889）
# --------------------------------------------------------------------------

def build_broadcast_frame(port, device_id=None, hostname=None, ts=None):
    """构造 XDCAST 广播帧（契约 §19.1；帧构造与发送分离，便于白盒调用）。

    报文：JSON UTF-8 单行 ≤ 512 字节，字段 = magic/proto/device_id/hostname/
    port/version/caps/ts。序列化超 512 字节 → stderr 告警并返回 None
    （不截断，避免解析歧义）。
    """
    frame = {
        "magic": "XDCAST",
        "proto": 1,
        "device_id": device_id if device_id is not None else DEVICE_ID,
        "hostname": hostname if hostname is not None else socket.gethostname(),
        "port": int(port),
        "version": NODE_VERSION,
        "caps": list(BROADCAST_CAPS),
        "ts": ts if ts is not None else time.time(),
    }
    try:
        data = json.dumps(frame, ensure_ascii=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        sys.stderr.write("[警告] 广播帧序列化失败：%s\n" % exc)
        return None
    if len(data) > BROADCAST_MAX_BYTES:
        sys.stderr.write("[警告] 广播帧 %d 字节超过上限 %d，跳过本帧（不截断）\n"
                         % (len(data), BROADCAST_MAX_BYTES))
        return None
    return data


def broadcast_targets():
    """发送目标（契约 §19.1）：受限广播 255.255.255.255 + 本机每个私网 IPv4 的
    /24 定向广播（a.b.c.255，复用 local_addresses() 口径）+ 回环定向广播
    127.255.255.255（供同机控制端接收）。去重保序。"""
    targets = ["255.255.255.255"]
    for ip in local_addresses():
        parts = ip.split(".")
        if len(parts) == 4:
            targets.append("%s.%s.%s.255" % (parts[0], parts[1], parts[2]))
    targets.append("127.255.255.255")
    seen = set()
    ordered = []
    for t in targets:
        if t not in seen:
            seen.add(t)
            ordered.append(t)
    return ordered


def send_broadcast_frame(frame, targets, sock=None):
    """逐目标发送一帧广播（契约 §19.1）：socket 设 SO_BROADCAST、不绑定固定端口
    （源端口随机）；单目标失败（如无广播路由）仅 stderr 告警，不影响其余目标与服务。
    返回成功发送的目标数；frame 为 None（超限/序列化失败）时不发送。
    """
    if frame is None:
        return 0
    own_sock = sock is None
    if own_sock:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        except OSError:
            pass                    # 极老系统不支持时保持默认语义
    sent = 0
    for target in targets:
        try:
            sock.sendto(frame, (target, BROADCAST_PORT))
            sent += 1
        except OSError as exc:
            sys.stderr.write("[警告] 广播发送失败（%s:%d）：%s\n"
                             % (target, BROADCAST_PORT, exc))
    if own_sock:
        sock.close()
    return sent


def broadcast_loop(port):
    """广播心跳线程（契约 §19.1，D25）：启动即发 1 帧 + 每 10 秒 1 帧；
    daemon 线程，node 退出即停。目标地址每轮重算（兼容 DHCP 地址漂移）。"""
    while True:
        send_broadcast_frame(build_broadcast_frame(port), broadcast_targets())
        time.sleep(BROADCAST_INTERVAL)


def _port_has_listener(host, port):
    """探测端口是否已有活监听者（区分真占用与 TIME_WAIT 残留，§16.1 配套）。

    超时取 0.15 秒：回环上活监听者毫秒级应答；对 bind 未 listen 的端口 Windows
    会静默丢 SYN 直到超时——超时过长会拖慢顺延节奏（集成期实测问题，已修）。
    """
    probe_host = "127.0.0.1" if host in ("0.0.0.0", "::", "", "*") else host
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.15)
    try:
        sock.connect((probe_host, port))
        return True
    except OSError:
        return False
    finally:
        sock.close()


def _bind_attempt(host, port, ssl_context):
    """单次端口绑定尝试（契约 §16.1 配套）。

    先以 SO_EXCLUSIVEADDRUSE 独占绑定（NodeHTTPServer 默认）；失败且探测到端口
    并无活监听者（仅 TIME_WAIT 残留）时，回退 SO_REUSEADDR 绑定同一端口，
    避免热重启后端口无谓顺延。成功返回服务器实例；不可用返回 None。
    """
    try:
        return NodeHTTPServer((host, port), Handler, ssl_context=ssl_context)
    except OSError:
        pass
    if not _port_has_listener(host, port):
        try:
            return NodeHTTPServer((host, port), Handler, ssl_context=ssl_context,
                                  allow_reuse=True)
        except OSError:
            pass
    return None


def main():
    global VERBOSE, IDENTITIES, TOKEN
    global TLS_ENABLED, TLS_PLAINTEXT_DEBUG, CERT_FINGERPRINT, UPLOADS_MANIFEST
    global CONFIG_FILE, ACTUAL_PORT
    parser = argparse.ArgumentParser(description="CrossDevice 执行器")
    parser.add_argument("--port", type=int, default=None,
                        help="期望端口（优先级：CLI > node.json 的 port 字段 > 51888；"
                             "被占用自动 +1 顺延，契约 §16.1）")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--token", default=None,
                        help="设置/覆盖 default 身份令牌；不传则复用配置或自动生成（32 hex）")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--config", default=None,
                        help="node.json 路径（默认 %%LOCALAPPDATA%%\\CrossDevice\\node.json；"
                             "tls/audit 默认目录相对该文件所在目录解析；与 --instance 互斥）")
    parser.add_argument("--cert", default=None, help="TLS 证书 PEM 路径（优先于配置）")
    parser.add_argument("--key", default=None, help="TLS 私钥 PEM 路径（优先于配置）")
    parser.add_argument("--workspace", default=None,
                        help="工作空间白名单根（逗号分隔，覆盖 node.json 的 workspace；"
                             "默认空 = 拒绝一切写/删/建目录/移动/上传，契约 §14.1）")
    parser.add_argument("--instance", default=None,
                        help="实例名（限 [A-Za-z0-9_-]{1,32}；配置/身份/白名单/审计/任务库/"
                             "上传清单按实例隔离，TLS 目录共享；与 --config 互斥，契约 §16.2）")
    parser.add_argument("--debug-plaintext", action="store_true",
                        help="调试：主监听端口改以明文 HTTP 服务（默认关闭，D31）")
    parser.add_argument("--elevate-task-install", default=None, metavar="名",
                        help="提权子命令（契约 §22.1）：由 /v1/elevate/install 以 runas "
                             "拉起，直接执行 schtasks /create 后按退出码退出，不进 HTTP 服务")
    parser.add_argument("--elevate-task-remove", default=None, metavar="名",
                        help="提权子命令（契约 §22.1）：直接执行 schtasks /delete 后按退出码退出")
    args = parser.parse_args()

    VERBOSE = args.verbose

    # ---- 提权子命令（契约 §22.1）：进程本身已被提权（runas 拉起），直接执行
    # schtasks 并以其退出码退出，不进入 HTTP 服务 ----
    if args.elevate_task_install or args.elevate_task_remove:
        install = args.elevate_task_install is not None
        sub_task_name = args.elevate_task_install or args.elevate_task_remove
        if not re.fullmatch(ELEVATE_TASK_NAME_RE, sub_task_name):
            sys.stderr.write("task_name 非法：%s（限 [A-Za-z0-9_\\-\\. ]{1,64}）\n"
                             % sub_task_name)
            raise SystemExit(2)
        raise SystemExit(elevate_task_cli(
            sub_task_name, install,
            port=args.port,
            config_path=args.config or default_config_path()))

    # ---- 多实例与配置文件路径（契约 §16.2）----
    instance_name = None
    config_path = args.config
    if args.instance is not None:
        if args.config:
            raise SystemExit("--instance 与 --config 互斥，不能同时指定。")
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", args.instance):
            raise SystemExit("实例名非法：%s（限 [A-Za-z0-9_-]{1,32}）" % args.instance)
        instance_name = args.instance
        config_path = os.path.join(default_config_dir(), "node-%s.json" % instance_name)

    # ---- 配置与身份（契约 §2 / §9.1）----
    cfg, identities, config_file = load_config(args, config_path)
    IDENTITIES = identities
    TOKEN = next((i["token"] for i in identities if i["name"] == DEFAULT_IDENTITY_NAME),
                 identities[0]["token"] if identities else "")
    base_dir = os.path.dirname(os.path.abspath(config_file))

    # ---- S3 新键初始化（契约 §9.1/§19.1/§20.1/§21.1/§22）：device_id 与
    # update.hmac_key 缺失则生成并原子写回；lease_seconds / elevated 读入内存 ----
    CONFIG_FILE = os.path.abspath(config_file)
    ensure_s3_config(cfg, CONFIG_FILE)

    # ---- 审计（契约 §8.1；--instance 时为 audit-<名>/，实例隔离 §16.2）----
    audit_subdir = ("audit-%s" % instance_name) if instance_name else "audit"
    audit_cfg = cfg.get("audit") if isinstance(cfg.get("audit"), dict) else {}
    set_audit_paths(os.path.join(base_dir, audit_subdir),
                    audit_cfg.get("retention_days", 180))
    cleanup_audit_files()

    # ---- 工作空间白名单（契约 §14.1；B42 起附默认暂存目录）----
    load_workspace(args, cfg, config_file)

    # ---- 任务历史（契约 §15）：建库 → 恢复遗留 running → 启动清理 + 每小时后台清理 ----
    tasks_db_name = ("tasks-%s.db" % instance_name) if instance_name else "tasks.db"
    load_tasks_config(cfg)
    tasks_db_init(os.path.join(base_dir, tasks_db_name))
    db_recover_running()
    tasks_cleanup()
    threading.Thread(target=tasks_retention_loop, daemon=True).start()

    # ---- 上传孤儿清理（契约 §13.5）----
    uploads_manifest_name = ("uploads-%s.json" % instance_name) if instance_name \
        else "uploads.json"
    UPLOADS_MANIFEST = os.path.join(base_dir, uploads_manifest_name)
    cleanup_upload_orphans()

    # ---- 端口选择（契约 §16.1）：CLI --port > node.json port > 51888 ----
    if args.port is not None:
        if not 1 <= args.port <= 65535:
            raise SystemExit("--port 非法（1–65535）：%d" % args.port)
        port_expected = args.port
    else:
        cfg_port = cfg.get("port")
        if (isinstance(cfg_port, int) and not isinstance(cfg_port, bool)
                and 1 <= cfg_port <= 65535):
            port_expected = cfg_port
        else:
            port_expected = DEFAULT_PORT

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

    # ---- 端口绑定（契约 §16.1）：期望端口 +1 顺延，最多 51 个候选 ----
    # 首个候选最多尝试 6 次（间隔 0.5 秒，兼容热更新重启时旧进程未释放端口的竞态），
    # 其余候选各尝试 1 次；全部占用 → PORT_EXHAUSTED 说明后非零退出（不经 HTTP）。
    server = None
    actual_port = None
    for offset in range(51):
        candidate = port_expected + offset
        if candidate > 65535:
            break
        attempts = 6 if offset == 0 else 1
        for attempt in range(attempts):
            server = _bind_attempt(args.host, candidate, ssl_context)
            if server is not None:
                actual_port = candidate
                break
            if attempt < attempts - 1:
                time.sleep(0.5)
        if server is not None:
            break
    if server is None:
        print("PORT_EXHAUSTED：从期望端口 %d 起顺延尝试的候选端口全部不可用，无法启动。"
              % port_expected)
        print("可改用 --port <端口> 手动指定端口后重试。")
        raise SystemExit(1)
    server.daemon_threads = True
    ACTUAL_PORT = actual_port

    # ---- 端口持久化（契约 §16.1/D35）：把实际端口写回配置文件供下次启动优先复用 ----
    if cfg.get("port") != actual_port:
        try:
            cfg["port"] = actual_port
            atomic_write_json(config_file, cfg)
        except Exception as exc:
            sys.stderr.write("[警告] 端口持久化失败：%s\n" % exc)

    # ---- 发现广播（契约 §19.1）：端口绑定成功后才启动，port 为实际绑定端口；
    # 启动即发 1 帧 + 每 10 秒 1 帧（D25），daemon 线程随进程退出停止 ----
    threading.Thread(target=broadcast_loop, args=(actual_port,), daemon=True).start()

    # ---- 启动横幅（契约 §7.1/§16.3：保留既有行，端口用实际绑定值，新增实例行）----
    line = "=" * 62
    print(line)
    print(" CrossDevice 执行器 v%s" % NODE_VERSION)
    print(line)
    print(" 主机名    : %s" % info["hostname"])
    print(" 用户      : %s" % info["user"])
    print(" 监听      : %s:%d" % (args.host, actual_port))
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
        print(" 访问地址  : %s://%s:%d" % (scheme, ip, actual_port))
    print(" 实例      : %s" % (instance_name or "default"))
    # S3 新增（契约 §7.1/§22.2）：高权限驻留标注；降级运行（未驻留）为正常状态，仅标注不告警
    print(" 驻留      : %s" % ("是（计划任务 %s）" % ELEVATED_TASK_NAME
                              if ELEVATED_TASK_NAME else "否"))
    # B42 新增（契约 §14.1 V1.6）：白名单可见性——被控端所有者能一眼看到允许根与配置入口
    if USER_WORKSPACE_ROOTS:
        print(" 白名单    : %s" % "；".join(WORKSPACE_ROOTS))
    else:
        print(" 白名单    : 默认（仅暂存目录可写；node.json workspace 键可扩，D24）")
    print(" 暂存目录  : %s" % (STAGING_ROOT or "未就绪"))
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
