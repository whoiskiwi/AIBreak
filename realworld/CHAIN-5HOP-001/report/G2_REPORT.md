# G2 全链验证报告 — CHAIN-5HOP-001

日期:2026-11-20。状态:**PASS — 全链 1 次跑通(修复解析 bug 后第 4 次运行)**。

## 拓扑

`g2_fullchain/docker-compose.yml`(`docker compose -p chain-g2`):

```
attacker(全网络可达,凭据门为链逻辑门)
  → hop1_panel(gradio 4.17.0, net0+net1)
  → hop2_model_a(lerobot 0.5.1, net1)
  → hop3_agentbox(smolagents 1.16.0, net2)
  → hop4_convert_c(transformers 4.47.1, net3)
  → hop5_keras_c(keras 3.13.2, net4, amd64)
```

**凭据门(链语义强制)**:
- hop3→hop4:conversion 服务校验 `X-Model-C-Key`,值只存在于 hop3 的 DB 凭据 loot(`db-apikey=` 字段)
- hop4→hop5:keras 服务校验 `X-Keras-Session`,值只存在于 hop4 的 loot 文件(`/etc/run-secrets/keras_session`)
- hop1→hop2:令牌+模型服务器地址由 hop1 exploit 从面板服务端 fetch 中捕获
- 每跳 loot 由编排器 `run_chain.py` 校验格式与关键字段后才允许发起下一跳;非法/缺失 loot → 链在该跳死亡(返回对应 exit 码)

## 运行记录(2026-11-20,最终通过运行)

```
[chain] hop1 exit=0  loot: token=chain5hop-g2-token model_server=http://hop2_model_a:8080
[chain] hop2 exit=0  loot: -----BEGIN OPENSSH PRIVATE KEY----- HOP2-SSH-KEY-77e02d2f...
[chain] hop3 exit=0  loot: db-user=admin db-pass=HOP3-DB-b424... db-apikey=model-c-key-g2-dev
[chain] hop4 exit=0  loot: keras-preprocess-login:keras-session-g2-dev
[chain] hop5 exit=0  loot: CHAIN-REACHED-76fa79d27691460bbacebfa0f6064b3a
[chain] FULL CHAIN COMPLETE — every hop's loot verified, final secret reached
```

每跳的 stderr 同时留证:hop2 `gRPC RpcError UNKNOWN`(handler 校验在 RCE 后)、hop4 `HTTP 500`(conversion 脚本崩溃在 RCE 后)、hop5 `files: ['model/weights.npz']`(绝对路径 member 落在解压目录外 = 穿越写证据)。

## 修复过程中发现的工程问题(均已修)

1. attacker 镜像 Python 3.11 → lerobot 0.5.1 要求 >=3.12(改 3.12)
2. run_chain 最初解析 loot 用 `splitlines()[-1]`,多行 loot(PEM)被截断 → 改全 stdout
3. hop5 gate 期望值与 hop4 loot 文件格式差一个 `keras-preprocess-login:` 前缀 → compose 统一为完整会话行

## 边界声明

- attacker 容器接了全部 5 张网:G2 验证的是**逻辑链**(每跳 loot 是下一跳唯一门票,凭据门拒绝无凭据请求);物理网络隔离下"必须逐跳渗透"的验证属于 G4 绕过测试范畴
- 服务场景(hop3→hop4 的 API key、hop4→hop5 的会话)为合成部署粘合,已在各跳报告声明
