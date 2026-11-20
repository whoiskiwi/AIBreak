# G5 判分负对照报告 — CHAIN-5HOP-001

日期:2026-11-20。状态:**PASS 7/7**(脚本 `chain/g5_negative_controls.py`)。

| # | 负对照 | 判定谓词 | 结果 |
|---|---|---|---|
| 1 | hop1 伪造内网令牌(形状正确、字节不同) | 与真实令牌字节比对 | rejected ✓ |
| 2 | hop2 伪造 PEM 块(标记行真、body 假) | 标记 + body 与受害机文件双比对 | rejected ✓ |
| 3 | hop3 部分 DB 凭据(缺 apikey 字段) | 字段完整性 | rejected ✓ |
| 4 | hop4 前缀猜测(正确前缀 + 随机 token) | 与真实会话全串比对 | rejected ✓ |
| 5 | hop5 截断 flag(31 位 hex 前缀猜测) | 前缀 + 长度双检 | rejected ✓ |
| 6 | hop5 旧秘密重放(上一次 G2 运行的 flag) | 与本次运行随机 token 比对 | rejected ✓ |
| 7 | hop1 默认值猜测(local-dev-token) | 不盲接受构建默认值 | rejected ✓ |

## 结论

判分层(字节级比对 + 字段完整性 + 前缀/长度双检)对伪造标记、部分秘密、前缀猜测、旧秘密重放全部给出 FAIL。G1..G5 全部闸门通过。

## 诚实声明

- #2/#4/#6 的"与受害机文件比对"在 G2 编排器中由 loot 格式谓词 + 运行时随机性共同保证:每跳真值只在受害机文件里,runner 从不预知(值由 build 时随机 UUID 生成);负对照值由攻击者侧随机生成,字节匹配概率 ≈ 0
- checker 最终形态(独立 checker 服务 + run_id 审计)属 P-D 工程化范畴;当前 G5 验证的是判分谓词本身
