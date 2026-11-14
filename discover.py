#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""局域网设备发现：ICMP 扫描 + ARP 表 + 主机名反查。"""

import concurrent.futures
import ipaddress
import re
import socket
import subprocess
import sys

CREATE_NO_WINDOW = 0x08000000
ARP_PATTERN = re.compile(
    r"^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F]{2}(?:[-:][0-9a-fA-F]{2}){5})"
)
NBT_PATTERN = re.compile(r"^\s*(\S+)\s+<00>\s+UNIQUE", re.MULTILINE)


def local_network():
    """返回 (本机IP, 网段对象)。"""
    candidates = []
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            candidates.append(info[4][0])
    except Exception:
        pass
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.connect(("8.8.8.8", 80))
        candidates.insert(0, probe.getsockname()[0])
        probe.close()
    except Exception:
        pass

    for ip in candidates:
        if ip.startswith(("127.", "169.254.")):
            continue
        try:
            return ip, ipaddress.ip_network(ip + "/24", strict=False)
        except ValueError:
            continue
    raise RuntimeError("无法确定本机局域网地址")


def ping(ip, timeout_ms=400):
    try:
        proc = subprocess.run(
            ["ping", "-n", "1", "-w", str(timeout_ms), str(ip)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=CREATE_NO_WINDOW,
            timeout=timeout_ms / 1000.0 + 2,
        )
        return proc.returncode == 0
    except Exception:
        return False


def ping_sweep(ip, network, workers=96, timeout_ms=400):
    hosts = [str(h) for h in network.hosts() if str(h) != ip]
    alive = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(ping, h, timeout_ms): h for h in hosts}
        for future in concurrent.futures.as_completed(futures):
            if future.result():
                alive.append(futures[future])
    return sorted(alive, key=lambda s: int(s.split(".")[-1]))


def arp_table():
    table = {}
    try:
        output = subprocess.run(["arp", "-a"], capture_output=True,
                                creationflags=CREATE_NO_WINDOW).stdout
    except Exception:
        return table
    for raw in output.decode("gbk", "replace").splitlines():
        match = ARP_PATTERN.match(raw)
        if match:
            table[match.group(1)] = match.group(2).replace("-", ":").upper()
    return table


def netbios_name(ip):
    """反查失败时用 nbtstat 拿 NetBIOS 名，能识别出 PTR 缺失的 Windows 主机。"""
    try:
        proc = subprocess.run(["nbtstat", "-A", ip], capture_output=True,
                              creationflags=CREATE_NO_WINDOW, timeout=3)
    except Exception:
        return None
    match = NBT_PATTERN.search(proc.stdout.decode("gbk", "replace"))
    return match.group(1) if match else None


def reverse_names(ips, timeout=3.0):
    names = {}

    def lookup(ip):
        try:
            name = socket.gethostbyaddr(ip)[0].split(".")[0]
            if name:
                return ip, name
        except Exception:
            pass
        return ip, netbios_name(ip)

    with concurrent.futures.ThreadPoolExecutor(max_workers=32) as pool:
        futures = [pool.submit(lookup, ip) for ip in ips]
        try:
            for future in concurrent.futures.as_completed(futures, timeout=timeout + 2):
                ip, name = future.result()
                if name and name != ip:
                    names[ip] = name
        except concurrent.futures.TimeoutError:
            pass    # 反查超时不影响扫描结果，缺失的主机名留空
    return names


def scan(cidr=None, timeout_ms=400, include_self=False):
    self_ip, network = local_network()
    if cidr:
        network = ipaddress.ip_network(cidr, strict=False)

    alive = ping_sweep(self_ip, network, timeout_ms=timeout_ms)
    arp = arp_table()
    if not include_self:
        alive = [ip for ip in alive if ip != self_ip]
    names = reverse_names(alive)

    devices = []
    for ip in alive:
        devices.append({
            "ip": ip,
            "mac": arp.get(ip),
            "hostname": names.get(ip),
            "self": ip == self_ip,
        })
    return {"self_ip": self_ip, "network": str(network), "devices": devices}


def main():
    import argparse
    import json

    parser = argparse.ArgumentParser(description="局域网设备发现")
    parser.add_argument("--cidr", default=None)
    parser.add_argument("--timeout", type=int, default=400)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    result = scan(args.cidr, args.timeout)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return

    print("本机 %s    网段 %s" % (result["self_ip"], result["network"]))
    print("-" * 66)
    print("%-16s %-18s %-20s" % ("IP", "MAC", "主机名"))
    print("-" * 66)
    for device in result["devices"]:
        print("%-16s %-18s %-20s" % (
            device["ip"], device["mac"] or "-", device["hostname"] or "-"))
    print("-" * 66)
    print("共发现 %d 台设备" % len(result["devices"]))


if __name__ == "__main__":
    sys.exit(main())
