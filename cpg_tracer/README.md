• 主要改动
  - 目录结构：cpg_tracer/ 目录包含
      - backtrace.py：入口脚本（python -m cpg_tracer.backtrace ...），从 config.toml 读取 LLM 配置，通过 litellm（或 fallback stub）与 Joern 迭代交互，逐步追溯 sink→source；
      - joern_manager.py：封装与 Joern server 的通信、导入代码、执行 CPGQL 查询、解析 reachableByFlows 输出；
      - prompts.py：定义 LLM 的系统提示，要求用 JSON 输出查询、意图、是否期待路径、是否完成；
      - cpgqls_client.py：轻量 HTTP 客户端，POST 到 http://<host>/api/cpgqls/query，无需额外安装；
      - litellm_stub.py：当环境里没有 litellm 包时的兜底实现，保持 completion() 接口以便离线运行；
      - __init__.py 占位。


  - 新建 cpg_tracer/ 目录：包含 __init__.py、prompts.py（新的 LLM 约束说明）、joern_manager.py（精简的 Joern 控制器，支持 docker-
    compose 重启、可解析 file/line 级的 reachableByFlows 输出）。
  - 新增 cpg_tracer/backtrace.py：命令行脚本，读取 config.toml 的 LLM 配置，通过 litellm 与 Joern 迭代交互。脚本会：
      - 载入仓库、锁定 sink（函数、文件、行号、参数）并发送上下文给 LLM。
      - 逐轮请求 LLM 生成 JSON 格式的 CPGQL 查询，执行后将 stdout、路径预览反馈给 LLM，直到路径充分或迭代耗尽。
      - 将收集到的 Source→Transform→Sink 路径写入 cpg_tracer/output/paths.json 与可读的 paths.md，便于后续 PoC 设计。

  使用说明

  1. 确保 Joern docker-compose 服务可用、config.toml 写好 LLM 信息。
  2. 运行示例：

     python -m cpg_tracer.backtrace \
       --repo-root /mnt/d/Work_space/Memory_agent/VulnTree/debug/workspace/njs.cve-2022-32414 \
       --sink-func njs_string_offset \
       --sink-file src/njs_string.c \
       --sink-line 2535 \
       --sink-param 3
  3. 输出文件位于 cpg_tracer/output/，其中 paths.md 以 <SOURCE>/<TRANSFORM>/<SINK> 摘要展示 LLM 认定完整的数据/控制流链。若 LLM
     判定路径仍不完备，会在对话中继续补齐。

  后续建议

  - 结合真实实例测试脚本，观察 LLM 生成的查询是否稳定并确实覆盖控制流约束；如遇空路径，可在 prompts 中加入更多示例或手动提供初始
    val sink = ... 模板。
  - 待脚本产出的路径可靠后，再将其嵌入 agent 的提示构建流程或作为 MCP 工具暴露给 agent。
