#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CrossDevice 证书验证工具（仅 Python 标准库）。

用法：
    py tools/verify_cert.py <cert.pem> <key.pem>

验证内容（对应接口契约第 4.1 章 TLS 口径）：
1. cert.pem 可解析为 PEM 证书（显式拒绝 UTF-8 BOM），解析出 DER 并计算
   SHA-256 指纹（= 证书 DER 的 SHA-256，小写 64 hex，即 TOFU 固定口径）；
2. ssl.SSLContext.load_cert_chain 同时加载证书与私钥
   （不匹配 / 格式错误 / 加密私钥均在此失败）；
3. 以该证书在 127.0.0.1 随机端口起一次性 TLS 服务器，与本机客户端完成
   真实 TLS 握手（客户端 CERT_NONE），断言两端协商协议均为 TLSv1.3；
4. 客户端取对端证书 DER 计算指纹，与第 1 步 cert.pem 指纹比对必须一致。

退出码：0 = PASS；1 = FAIL；2 = 用法错误。
"""

import base64
import hashlib
import socket
import ssl
import sys
import threading

RECV_TIMEOUT = 10.0
FINGERPRINT_LEN = 64


def pem_fingerprint(cert_path):
    """从 PEM 证书文件解析 DER，返回 (sha256 指纹, DER 字节数)。"""
    with open(cert_path, "rb") as f:
        raw = f.read()
    if raw.startswith(b"\xef\xbb\xbf"):
        raise ValueError("证书文件带 UTF-8 BOM（要求无 BOM），OpenSSL 之外的环节解析会出错")
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError("证书文件不是纯 ASCII 的 PEM 文本: %s" % exc)
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    if len(lines) < 3 or lines[0] != "-----BEGIN CERTIFICATE-----" or lines[-1] != "-----END CERTIFICATE-----":
        raise ValueError("缺少 -----BEGIN/END CERTIFICATE----- 包裹，不是 PEM 证书")
    b64 = "".join(lines[1:-1])
    try:
        der = base64.b64decode(b64, validate=True)
    except Exception as exc:
        raise ValueError("证书 base64 解码失败: %s" % exc)
    if not der:
        raise ValueError("证书 DER 为空")
    return hashlib.sha256(der).hexdigest(), len(der)


def load_chain(cert_path, key_path):
    """load_cert_chain 加载证书与私钥；失败即视为不匹配或格式错误。"""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
    return ctx


def handshake(server_ctx, cert_path):
    """回环 TLS 1.3 握手，返回 (客户端协商协议, 服务端协商协议, 对端证书指纹)。"""
    client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_ctx.check_hostname = False
    client_ctx.verify_mode = ssl.CERT_NONE  # 自签 + TOFU：客户端只做指纹固定，不校验证书链

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    outcome = {}

    def server_once():
        try:
            listener.settimeout(RECV_TIMEOUT)
            conn, _ = listener.accept()
            conn.settimeout(RECV_TIMEOUT)
            with server_ctx.wrap_socket(conn, server_side=True) as tls:
                outcome["server_protocol"] = tls.version()
                tls.sendall(b"pong")
        except Exception as exc:  # 任何服务端异常都记录为失败原因
            outcome["server_error"] = repr(exc)
        finally:
            listener.close()

    worker = threading.Thread(target=server_once, daemon=True)
    worker.start()

    with socket.create_connection(("127.0.0.1", port), timeout=RECV_TIMEOUT) as raw:
        raw.settimeout(RECV_TIMEOUT)
        with client_ctx.wrap_socket(raw, server_hostname="localhost") as tls:
            protocol = tls.version()
            der = tls.getpeercert(binary_form=True)
            tls.recv(4)
    worker.join(timeout=RECV_TIMEOUT)

    if "server_error" in outcome:
        raise RuntimeError("TLS 服务器端异常: %s" % outcome["server_error"])
    if der is None:
        raise RuntimeError("客户端未收到对端证书")
    fingerprint = hashlib.sha256(der).hexdigest()
    return protocol, outcome.get("server_protocol"), fingerprint


def main(argv):
    if len(argv) != 3:
        print("用法: py tools/verify_cert.py <cert.pem> <key.pem>", file=sys.stderr)
        return 2
    cert_path, key_path = argv[1], argv[2]
    print("[1] 证书文件: %s" % cert_path)
    print("    私钥文件: %s" % key_path)

    try:
        pem_fp, der_len = pem_fingerprint(cert_path)
    except Exception as exc:
        print("[FAIL] cert.pem 解析失败: %s" % exc)
        return 1
    print("[2] PEM 解析 OK：证书 DER %d 字节，SHA-256 指纹（TOFU 口径）%s" % (der_len, pem_fp))
    if len(pem_fp) != FINGERPRINT_LEN or pem_fp != pem_fp.lower():
        print("[FAIL] 指纹不是 64 位小写 hex")
        return 1

    try:
        server_ctx = load_chain(cert_path, key_path)
    except Exception as exc:
        print("[FAIL] load_cert_chain 加载失败（证书与私钥不匹配或格式错误）: %s" % exc)
        return 1
    print("[3] load_cert_chain 加载 OK（证书与私钥匹配，TLS 1.3 上下文就绪）")

    try:
        protocol, server_protocol, fp = handshake(server_ctx, cert_path)
    except Exception as exc:
        print("[FAIL] TLS 回环握手失败: %s" % exc)
        return 1

    print("[4] 回环握手 OK：客户端协议=%s，服务端协议=%s" % (protocol, server_protocol))
    print("    握手取回的对端证书指纹: %s" % fp)

    ok = True
    if protocol != "TLSv1.3" or server_protocol != "TLSv1.3":
        print("[FAIL] 未协商到 TLSv1.3（契约 4.2 要求 minimum_version=TLSv1_3）")
        ok = False
    if fp != pem_fp:
        print("[FAIL] 握手证书指纹与 cert.pem 文件指纹不一致")
        ok = False
    if ok:
        print("PASS: load_cert_chain 成功 + TLS 1.3 回环握手成功，证书指纹 = %s" % fp)
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
