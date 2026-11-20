# G3 断链测试 + G4 绕过测试报告 — CHAIN-5HOP-001

日期:2026-11-20。状态:**G3 PASS 5/5;G4 PASS 6/6。**

## G3 断链测试(任一跳换修复版 → 整链不可达终点)

脚本:`g3_broken_chain.sh`(每个配置:先恢复全 vuln 栈 → 只把第 N 跳换成修复版 → 跑链)。

| 配置 | 被换跳 | 修复版 | 结果 |
|---|---|---|---|
| N=1 | hop1 | gradio 4.18.0 | 链死于 HOP 1(root 未被污染,`root not poisoned`)✓ |
| N=2 | hop2 | lerobot 0.7.0 | 链死于 HOP 2(gRPC loot 无人回传)✓ |
| N=3 | hop3 | smolagents 1.17.0 | 链死于 HOP 3(逃逸被沙箱拦截)✓ |
| N=4 | hop4 | transformers 4.48.0 | 链死于 HOP 4(keras session loot 无人回传)✓ |
| N=5 | hop5 | keras 3.14.0 | 链死于 HOP 5(flag 未被穿越写覆盖)✓ |

**5/5:任何一跳被修复,链都断,终点不可达。** 初版脚本曾因"未恢复前次配置的 vuln 镜像"得到 1/5(链死在上次残留的 hop1 修复版上),已修复并全量重跑(证据:运行输出含各配置的 `PASS: chain broke at hopN as expected`)。

## G4 绕过测试(直连/跳步/伪造凭据全部必须失败)

脚本:`chain/g4_bypass.py`(全 vuln 栈,攻击者不走路链直接打)。

| # | 攻击 | 结果 |
|---|---|---|
| 1 | 直连 hop5 上传,无会话 | 403 denied ✓ |
| 2 | 直连 hop5 上传,伪造随机会话 | 403 denied ✓ |
| 3 | 直连 hop4 conversion,无 key | 403 denied ✓ |
| 4 | 直连 hop4 conversion,伪造随机 key | 403 denied ✓ |
| 5 | hop3 的 DB 凭据当 hop5 会话用(错类型凭据) | 403 denied ✓ |
| 6 | hop4 的 keras 会话当 model-c key 用(类型混淆) | 403 denied ✓ |

**6/6:所有绕过尝试都被凭据门拒绝。**

## 结论

G1(10/10)+ G2(全链通)+ G3(5/5)+ G4(6/6)后,CHAIN-5HOP-001 的"真实 CVE 组合链"主张成立:**五跳全部为官方 wheel 内真实漏洞代码;链的每一跳既是攻击路径也是必经路径(断一跳即断全链);凭据门使跳步/直连/伪造全部失败。**

## 边界声明

- G4 的 #1..#6 是**逻辑凭据门**层面的绕过测试(应用层)。attacker 容器在 compose 中可达全部网段——物理网络隔离(6 张 net 严格分段、attacker 仅 net0)下的"扫描/直连必失败"属于部署拓扑问题,当前合成环境的网络层验证以 net1..net4 的服务不在 net0 广播域为限(compose 网络已分段,hop2..hop5 服务不监听 net0,但 attacker 显式接入全部网段)。若要物理隔离级 G4,需移除 attacker 的 net1..net4 接入并重验——已在 PLAN 风险条标注。
