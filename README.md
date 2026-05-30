# 广科大 (GKD) 校内实训 CTF · 题解与利用脚本合集

### SQL 注入（01–05）

| #   | 目录                   | 考点                              |
| --- | ---------------------- | --------------------------------- |
| 01  | `01-sqli-union-echo`   | UNION 回显注入                    |
| 02  | `02-sqli-bool-blind`   | 布尔盲注 / 登录绕过               |
| 03  | `03-sqli-time-blind`   | 时间盲注（SLEEP 侧信道）          |
| 04  | `04-sqli-waf-bypass`   | WAF 绕过（双写关键词 + Tab 分隔） |
| 05  | `05-sqli-second-order` | 二次注入                          |

### XSS（06–09）

| #   | 目录                   | 考点                      |
| --- | ---------------------- | ------------------------- |
| 06  | `06-xss-reflected`     | 反射型 XSS（窃取 Cookie） |
| 07  | `07-xss-stored-cookie` | 存储型 XSS                |
| 08  | `08-xss-dom`           | DOM 型 XSS                |
| 09  | `09-xss-csp-bypass`    | CSP 绕过                  |

### 爆破 / 暴力破解（10–14）

| #   | 目录                     | 考点                |
| --- | ------------------------ | ------------------- |
| 10  | `10-brute-weak-password` | 弱口令爆破          |
| 11  | `11-brute-captcha-flaw`  | 验证码缺陷爆破      |
| 12  | `12-brute-dir-backup`    | 目录 / 备份文件爆破 |
| 13  | `13-brute-jwt-hs256`     | JWT HS256 密钥爆破  |
| 14  | `14-brute-token-timing`  | Token 时序侧信道    |

### CSRF（15–17）

| #   | 目录                    | 考点            |
| --- | ----------------------- | --------------- |
| 15  | `15-csrf-get-passwd`    | GET 改密 CSRF   |
| 16  | `16-csrf-post-transfer` | POST 转账 CSRF  |
| 17  | `17-csrf-xss-combo`     | CSRF + XSS 组合 |

### 文件包含 LFI / RFI（18–20）

| #   | 目录                    | 考点               |
| --- | ----------------------- | ------------------ |
| 18  | `18-lfi-read-source`    | 本地文件包含读源码 |
| 19  | `19-lfi-log-poisoning`  | 日志投毒 getshell  |
| 20  | `20-rfi-wrapper-bypass` | RFI / 伪协议绕过   |

### 命令注入（21–23）

| #   | 目录                       | 考点            |
| --- | -------------------------- | --------------- |
| 21  | `21-cmdi-ping-concat`      | 命令拼接注入    |
| 22  | `22-cmdi-blacklist-bypass` | 黑名单绕过      |
| 23  | `23-cmdi-blind-oob`        | 盲注入 OOB 带外 |

### 路径穿越（24–26）

| #   | 目录                         | 考点              |
| --- | ---------------------------- | ----------------- |
| 24  | `24-path-download-traversal` | 下载目录穿越      |
| 25  | `25-path-encode-bypass`      | 编码绕过          |
| 26  | `26-path-zip-slip`           | Zip Slip 解压穿越 |

### XXE（27–29）

| #   | 目录                  | 考点            |
| --- | --------------------- | --------------- |
| 27  | `27-xxe-classic-read` | 经典 XXE 读文件 |
| 28  | `28-xxe-blind-oob`    | Blind XXE 带外  |
| 29  | `29-xxe-xinclude`     | XInclude 注入   |

### 越权 IDOR（30–31）

| #   | 目录                       | 考点               |
| --- | -------------------------- | ------------------ |
| 30  | `30-idor-order-horizontal` | 水平越权（订单）   |
| 31  | `31-idor-admin-vertical`   | 垂直越权（管理员） |

### 业务逻辑（32–36）

| #   | 目录                        | 考点                |
| --- | --------------------------- | ------------------- |
| 32  | `32-logic-payment-negative` | 支付负数金额        |
| 33  | `33-logic-reset-token`      | 密码重置 Token 缺陷 |
| 34  | `34-logic-race-condition`   | 条件竞争            |
| 35  | `35-logic-jwt-none`         | JWT `alg=none` 绕过 |
| 36  | `36-logic-otp-no-limit`     | OTP 无限制爆破      |

### 综合利用（37–40）

| #   | 目录                       | 考点                |
| --- | -------------------------- | ------------------- |
| 37  | `37-combo-ssrf-bypass`     | SSRF 黑名单绕过     |
| 38  | `38-combo-ssti-jinja2`     | SSTI（Jinja2）RCE   |
| 39  | `39-combo-deserialize-pop` | PHP 反序列化 POP 链 |
| 40  | `40-combo-upload-bypass`   | 文件上传绕过        |

---

## 使用方法

```bash
# 1) 准备环境（一次即可）
python3 -m venv .venv && source .venv/bin/activate
pip install requests          # 主要依赖；个别题用到 pyjwt / lxml 等，按报错补装

# 2) 运行某题（把地址换成你的靶机）

- 脚本大多内置了**默认靶机地址**，换环境时按上面方式传入新地址即可。
- 每题的**确切命令、参数和 payload** 以该题目录下的 `.md` 为准。

---


## 作者

**ZluxYao** —— 本工具免费、开源、禁止倒卖。
```

---

## 免责声明

> 本仓库为广州科技职业技术大学（GKD）校内实训配套的 CTF 题解与漏洞利用脚本合集，**仅供网络安全教学、学习研究及在明确授权范围内的安全测试使用**。
>
> 使用前必须已获得目标系统所有者的明确授权，严禁用于任何未授权或非法用途。因使用本仓库内容产生的一切后果与法律责任，均由使用者自行承担，作者概不负责。
>
> 下载、使用即视为同意以上条款。

## 许可协议

本项目采用 **[CC BY-NC 4.0（署名-非商业性使用）](LICENSE)** 协议授权。

- ✅ 允许：自由学习、复制、修改、分享
- ✅ 要求：保留署名
- ❌ 禁止：任何形式的商业用途与倒卖

完整条款见仓库根目录 [`LICENSE`](LICENSE) 文件。
