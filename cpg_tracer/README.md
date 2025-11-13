# 批量运行
运行指南

  1. 准备实例列表（可选）
      - 手动列举：ids.txt 中每行一个 instance_id。
      - 或者把 SEC-bench 官方 JSON/JSONL 导出到 instances.jsonl，字段至少包含 instance_id、repo、base_commit 等。
  2. 批量执行脚本

     # 读取本地实例列表
     python -m cpg_tracer.run_instances \
         --config-file ids.txt \
         --llm-profile claude \
         --metadata-file evaluation/benchmarks/sec_bench/instances.jsonl \
         -- --output-dir cpg_tracer/output
  3. 使用 HuggingFace 数据集
```bash
python -m cpg_tracer.run_instances \
      --llm-profile claude \
      --config-file cpg_tracer/ids.txt \
      -- --output-dir cpg_tracer/output
```
     python -m cpg_tracer.run_instances \
         --all \
         --llm-profile claude \
         --hf-dataset SEC-bench/SEC-bench \
         --hf-split eval \
         -- --output-dir cpg_tracer/output
  4. 切片执行（比如第 5~15 个实例）

     python -m cpg_tracer.run_instances \
         --slice 5:15 \
         --llm-profile claude \
         --hf-dataset SEC-bench/SEC-bench \
         --hf-split eval \
         -- --output-dir cpg_tracer/output
  5. 仅查看将要运行的命令

     python -m cpg_tracer.run_instances --config-file ids.txt --dry-run -- --output-dir cpg_tracer/output

  -- 之后的参数都会直接传给 python -m cpg_tracer.backtrace（例如 --output-dir, --joern-port 等）。如果你提供 --metadata-file，
  backtrace 会优先从该文件读出 repo_url、base_commit、code_subdir、language；否则它会自动加载 HuggingFace 数据集（默认 SEC-bench/
  SEC-bench, split=eval）并在每次运行中根据 instance_id 填充这些参数。元数据必须包含 `sanitizer_report` 字段（或兼容字段 `asan_report`），
  用于驱动每个实例的 SINK_CONTEXT。
  批量脚本会在每次运行前检查 `<output_dir>/data_flow_out.json` 中是否已有对应的 `instance_id`。如果已经存在，就会跳过该实例并在终端
  进度条中标记为 skipped。

## 运行LLM
python -m vllm.entrypoints.openai.api_server \
    --model /home/ps/DATA1/wwh/hf_cache/hub/models--QCRI--LLMxCPG-Q/snapshots/1f48ab60420d90277207394f1254d27d3375b07e \
    --served-model-name "QCRI/LLMxCPG-Q" \
    --host 127.0.0.1 \
    --port 8000 \
    --trust-remote-code

### 主要命令
```bash
python -m cpg_tracer.backtrace \
  --repo-url https://github.com/nginx/njs \
  --instance-id njs.cve-2022-31307 \
  --base-commit f65981b0b8fcf02d69a40bc934803c25c9f607ab \
  --code-subdir src \
  --language c \
  --joern-port 16240 \
  --compose-file cpg_tracer/docker-compose.yml \
  --llm-profile claude
```

（当前实现会在 `importCode` 阶段固定使用 C 前端，`--language` 仅为兼容旧参数。）

如果实例缺少 `sanitizer_report`，请在对应的元数据条目里补齐该字段后再运行（该信息是定位真实 callsite 的唯一来源）。

### 构建joern_analysis
docker build -t joern_analysis -f Dockerfile .

## docker内部文件分布：
- 项目路径： /workspace/sec_bench/njs.cve-2022-31307
- 可执行文件：/opt/joern/joern-cli 路径下执行 ./joern
- 创建CPG命令：

## cpg_tracer

`cpg_tracer` 最初借鉴 LLMxCPG 中的 `queries/` 思路（LLM 生成 Joern 查询 + REST API 执行），但两者的任务场景截然不同：

- **LLMxCPG：漏洞挖掘 / 发现任务**
  - 目标是自动识别潜在漏洞（聚焦“是否存在问题”），因此对整个仓库广泛探索，可能遍历多个路径或未知 sink。
  - 代码来源通过 `all_source_code.zip` 预先放入容器，Joern workspace 在 build 阶段即构建完成。

- **cpg_tracer：漏洞复现 / PoC 生成**
  - 我们从已知的 sink 出发（SEC-bench 给定 sanitizer 报告），需要构造完整的 Source→Transform→Sink 数据/控制流链，以便复现崩溃。重点是“沿着特定路径倒推”和“保存轨迹”。
  - 必须根据实例的 `repo/base_commit` 动态 git clone，且为了 PoC 设计要记录每一步 LLM 查询、Joern stdout、上下文（`cpg_tracer/output/<instance>.json` 和 `.md`）。

- LLMxCPG 的数据集固定在 `all_source_code.zip` 中，容器 build 时就把所有源码放在 Joern workspace；我们则需要针对 **SEC-bench 中每个实例**（上百个不同的 Git 仓库与 commit）动态下载对应源码并切换版本。
- LLMxCPG 主要做“漏洞存在性判断”，我们则要抓出完整的 Source→Transform→Sink + 控制流上下文供 PoC 复现使用；因此 JSON 日志中记录了每次 LLM 生成的查询、Joern 返回的 stdout、路径等“完整轨迹”。
- LLMxCPG 只分析若干语言（JS、Python 等），而 SEC-bench 主要是 C/C++；我们增加了 `--language`、`--code-subdir` 选项来指定 c2cpg 入口，并挂载 `evaluation/benchmarks/sec_bench/<instance_id>` 到容器，以便 Joern REST 能访问每个实例的源码。

综上，`cpg_tracer` 用于在当前场景下自动化执行以下流程：

1. 克隆或复用指定的仓库版本（支持 `--repo-url` + `--base-commit`，也可以直接传 `--repo-root`）。
2. 通过 docker-compose 启动 Joern server，并把 `evaluation/benchmarks/sec_bench` 目录挂载到容器 (`/workspace/sec_bench`)。
3. 仅导入指定子目录（默认仓库根，可用 `--code-subdir src`）并强制使用给定语言（默认 `c`，可改 `--language`，`cpp` 等别名会自动回退为 `c`）。
4. 调用 LLM（通过 litellm）生成逐步 Joern 查询，直到找到完整的 Source→Sink→Context 链路。
5. 将所有查询/返回（完整轨迹）保存到 `cpg_tracer/output/<instance_id>.json` 与 `.md`。


### LLMxCPG 兼容目录

为满足“与 LLMxCPG 完全一致”场景，`cpg_tracer/llmxcpg_ported/` 收录了原 `llmxcpg/queries` 中的核心脚本与 `Components/` 模块（`joern_manager.py`、`model.py`、`slice.py`、`c_parser.py`、`enhancer.py`）。内部引用已经改成 `cpg_tracer` 包下的模块，可以直接在本仓库运行：

```bash
python -m cpg_tracer.llmxcpg_ported.generate_and_run_queries --help
```

如需复现原流程（多线程切片、LMM 生成多条 Joern 查询、逐条执行并记录 stdout/stderr），可在该目录下按照 LLMxCPG 的 README 调用，上层镜像/compose 与现有 `cpg_tracer` 共用。

### 注意事项

- 运行前确保当前终端拥有 Docker 权限（`docker ps` 不报错）。
- 第一次执行会自动 `git clone` + `checkout` 到 `evaluation/benchmarks/sec_bench/<instance_id>`，后续运行直接复用。
- 如果 Joern 容器已存在，可在运行前手动 `docker compose -f cpg_tracer/docker-compose.yml up -d joern_server_<port>`。
- 结果文件
  - `cpg_tracer/output/<instance_id>/<instance_id>.json`：包含路径、上下文、每轮 LLM/Joern 交互步骤、对话记录等。
  - `cpg_tracer/output/<instance_id>/<instance_id>.md`：可读的 Source/Transform/Sink 摘要。
  - `cpg_tracer/output/<instance_id>/<instance_id>.conversation.log`：原始对话日志，便于调试。

### 常见问题

- **Permission denied while trying to connect to the Docker daemon socket**
  - 当前终端没有 docker 组权限。重新登录或使用 sudo 拉起容器，再以同一权限级别运行脚本。
- **ConsoleException: No CPG generator exists for language**
  - `cpg_tracer` 会自动把常见别名（如 `cpp`、`cxx`、`javascript`、`typescript`）映射到 Joern 支持的语言，并在 REST 仍拒绝时回退为“无 language 参数”再次导入。所有 `importCode` 的 stdout 会直接打印在终端，便于复现/对比；若两次都失败，请在容器内使用 `joern`/`c2cpg.sh` 手动验证对应前端是否可用。
- **LLM provider not provided**
  - 请在 `config.toml` 的对应 LLM 配置中添加 `custom_llm_provider`，脚本已经自动传递该字段给 litellm。

### 输出轨迹说明

`<instance_id>.json` 中的 `steps`、`conversation` 字段记录了每一次 LLM query、Joern 执行状态、stdout/stderr，可用于追溯错误或调整 prompt。`paths`、`contexts` 则是成功的 Source→Sink 链路，给之后的 PoC 设计提供约束信息。
