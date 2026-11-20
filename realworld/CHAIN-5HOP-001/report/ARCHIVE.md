# CHAIN-5HOP-001 证据归档索引

日期:2026-11-20。验收清单第 7 项。本文索引全部验证证据;原始运行输出已逐字摘录在各报告内(报告内的运行输出块即当次运行的留证,含退出码与 loot 字节)。

## 目录结构

```
report/
├── DIAGNOSIS.md          # 诊断报告(验收第 6 项):五跳定位/利用/修复/双版本验证
├── ARCHIVE.md            # 本文件:run_id 与证据索引
├── G2_REPORT.md          # G2 全链验证(2026-11-20,第 4 次运行通过)
├── G3_G4_REPORT.md       # G3 断链 5/5 + G4 绕过 6/6(2026-11-20)
├── G5_REPORT.md          # G5 判分负对照 7/7(2026-11-20)
└── hop_reports/          # 各跳 G1 双版本验证(复制自各跳 report/)
    ├── HOP1_REPORT.md    # gradio 4.17.0/4.18.0
    ├── HOP2_REPORT.md    # lerobot 0.5.1/0.7.0(含修复版考证更正)
    ├── HOP3_REPORT.md    # smolagents 1.16.0/1.17.0
    ├── HOP4_REPORT.md    # transformers 4.47.1/4.48.0
    └── HOP5_REPORT.md    # keras 3.13.2/3.14.0
```

## run_id 汇总(全部 2026-11-20)

| 闸门 | 项目(compose -p) | 证据 |
|---|---|---|
| G1 hop1 | `hop1-vuln`(17861)/ `hop1-fix`(17862) | HOP1_REPORT.md 运行记录段 |
| G1 hop2 | `hop2-vuln`(17871)/ `hop2-fix`(17872, zenoh 17874) | HOP2_REPORT.md |
| G1 hop3 | `hop3-vuln`(17881)/ `hop3-fix`(17882) | HOP3_REPORT.md |
| G1 hop4 | `hop4-vuln`(17883)/ `hop4-fix`(17884) | HOP4_REPORT.md |
| G1 hop5 | `hop5-vuln`(17891)/ `hop5-fix`(17892) | HOP5_REPORT.md |
| G2 全链 | `chain-g2`(五容器拓扑,见 G2_REPORT) | G2_REPORT.md 运行记录段 |
| G3 断链 | `g3_broken_chain.sh` 逐配置恢复+替换,N=1..5 | G3_G4_REPORT.md 表 |
| G4 绕过 | `chain/g4_bypass.py`(#1..6) | G3_G4_REPORT.md 表 |
| G5 负对照 | `chain/g5_negative_controls.py`(#1..7) | G5_REPORT.md;归档日复跑 exit=0 |

## 复跑指引

- 单跳 G1:`docker compose -p hopN-vuln / -p hopN-fix up -d` 后 `docker exec hopN_attacker_{vuln,fix} python /app/reference_exploit*.py ...`(各跳报告"运行记录"段有完整命令)
- 全链:`g2_fullchain/docker-compose.yml` + `chain/run_chain.py`
- 断链:`g3_broken_chain.sh N`
- 绕过:`chain/g4_bypass.py`;负对照:`chain/g5_negative_controls.py`
- 判分口径(全链一致):exit 0 = 利用成功 / exit 2 = 攻击面不可达或被修复版拦截(负对照预期)/ exit 3 = 无回连 / exit 4 = 战果不完整;loot 以运行时随机生成值的字节比对为准
