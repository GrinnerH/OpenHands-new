#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import logging
import textwrap
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

import tomllib
try:
    from litellm import completion
except ImportError:  # pragma: no cover - fallback when litellm not installed
    from .litellm_stub import completion

from .joern_manager import JoernManager, QueryStatus
from .prompts import SYSTEM_PROMPT, SANITIZER_REPORT
from .c_parser import analyze_c_code
from .enhancer import get_context

LOG = logging.getLogger("cpg_tracer")


# --------------------------------------------------------------------------- IO
def read_snippet(path: Path, line: int, radius: int = 25) -> str:
    lines = path.read_text().splitlines()
    start = max(0, line - radius - 1)
    end = min(len(lines), line + radius)
    snippet = []
    for idx in range(start, end):
        marker = ">" if idx + 1 == line else " "
        snippet.append(f"{marker} {idx+1:5d}: {lines[idx]}")
    return "\n".join(snippet)


def load_llm_config(config_path: Path, profile: Optional[str]) -> Dict[str, Any]:
    with config_path.open("rb") as f:
        data = tomllib.load(f)
    llm_section = data.get("llm", {})
    if profile:
        cfg = llm_section.get(profile)
    else:
        cfg = next(iter(llm_section.values())) if llm_section else None
    if not cfg:
        raise ValueError("LLM configuration not found in config.toml")
    required = ["model", "api_key", "base_url"]
    missing = [k for k in required if k not in cfg]
    if missing:
        raise ValueError(f"Missing LLM keys: {missing}")
    return cfg


def extract_json_block(content: str) -> Dict[str, Any]:
    """Extract JSON payload from assistant message."""
    block = content.strip()
    if block.startswith("```"):
        block = block.strip("`")
        if block.startswith("json"):
            block = block[4:]
    block = block.strip()
    try:
        return json.loads(block)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Assistant response is not valid JSON: {content}") from exc


def summarize_stdout(stdout: str, limit: int = 400) -> str:
    trimmed = stdout.strip().splitlines()
    joined = "\n".join(trimmed[:20])
    if len(joined) > limit:
        return joined[:limit] + "\n... (truncated) ..."
    return joined


def format_paths(paths: List[List[Dict[str, Any]]]) -> str:
    chunks = []
    for idx, flow in enumerate(paths, 1):
        chunks.append(f"FLOW #{idx}:")
        for node in flow:
            line = node.get("line_number")
            label = node.get("label")
            code = node.get("line_code") or node.get("code")
            chunks.append(f"  - {label}@{line}: {code}")
    return "\n".join(chunks)


def _render_snippet(source_lines: List[str], line_numbers: Iterable[int]) -> str:
    rows = []
    for line in line_numbers:
        if 1 <= line <= len(source_lines):
            rows.append(f"{line:5d}: {source_lines[line - 1]}")
    return "\n".join(rows)


def build_contexts(
    paths: List[List[Dict[str, Any]]], repo_root: Path
) -> List[Dict[str, Any]]:
    contexts: List[Dict[str, Any]] = []
    source_cache: Dict[str, List[str]] = {}
    block_cache: Dict[str, Any] = {}

    for idx, flow in enumerate(paths, 1):
        file_to_lines: Dict[str, List[int]] = {}
        for node in flow:
            file_path = node.get("file") or node.get("filename")
            line = node.get("line_number")
            if not file_path or not isinstance(line, int):
                continue
            file_to_lines.setdefault(file_path, []).append(line)

        for rel_path, lines in file_to_lines.items():
            path_obj = Path(rel_path)
            if path_obj.is_absolute():
                abs_path = path_obj
                rel_str = str(path_obj.relative_to(repo_root) if path_obj.is_relative_to(repo_root) else path_obj)
            else:
                abs_path = (repo_root / path_obj).resolve()
                rel_str = str(path_obj)

            if not abs_path.exists():
                continue
            if rel_str not in source_cache:
                content = abs_path.read_text()
                source_cache[rel_str] = content.splitlines()
                block_cache[rel_str] = analyze_c_code(content)

            blocks = block_cache[rel_str]
            context_lines = sorted(get_context(lines, blocks))
            snippet = _render_snippet(source_cache[rel_str], context_lines)
            contexts.append(
                {
                    "path_index": idx,
                    "file": rel_str,
                    "lines": context_lines,
                    "snippet": snippet,
                }
            )
    return contexts


def build_path_summary(
    paths: List[List[Dict[str, Any]]], contexts: List[Dict[str, Any]]
) -> str:
    lines = []
    contexts_by_path: Dict[int, List[Dict[str, Any]]] = {}
    for ctx in contexts:
        contexts_by_path.setdefault(ctx["path_index"], []).append(ctx)

    for idx, flow in enumerate(paths, 1):
        lines.append(f"### Path {idx}")
        if not flow:
            lines.append("空路径\n")
            continue
        if flow:
            src = flow[0]
            sink = flow[-1]
            lines.append(
                f"<SOURCE> {src.get('file')}:{src.get('line_number')} :: {src.get('line_code')}"
            )
        for node in flow[1:-1]:
            lines.append(
                f"<TRANSFORM> {node.get('label')} {node.get('file')}:{node.get('line_number')} :: {node.get('line_code')}"
            )
        if len(flow) > 1:
            lines.append(
                f"<SINK> {sink.get('file')}:{sink.get('line_number')} :: {sink.get('line_code')}"
            )
        ctx_items = contexts_by_path.get(idx, [])
        if ctx_items:
            lines.append("#### Context")
            for ctx in ctx_items:
                lines.append(f"- {ctx['file']} lines {ctx['lines']}")
                lines.append(ctx["snippet"])
                lines.append("")
        lines.append("")
    return "\n".join(lines)


def build_path_summary(
    paths: List[List[Dict[str, Any]]], contexts: List[Dict[str, Any]]
) -> str:
    lines = []
    for idx, flow in enumerate(paths, 1):
        lines.append(f"### Path {idx}")
        if not flow:
            lines.append("空路径\n")
            continue
        if flow:
            src = flow[0]
            sink = flow[-1]
            lines.append(f"<SOURCE> {src.get('file')}:{src.get('line_number')} :: {src.get('line_code')}")
        for node in flow[1:-1]:
            lines.append(
                f"<TRANSFORM> {node.get('label')} {node.get('file')}:{node.get('line_number')} :: {node.get('line_code')}"
            )
        if len(flow) > 1:
            lines.append(
                f"<SINK> {sink.get('file')}:{sink.get('line_number')} :: {sink.get('line_code')}"
            )
        lines.append("")
    return "\n".join(lines)


LANGUAGE_ALIASES = {
    "cpp": "c",
    "c++": "c",
    "cxx": "c",
    "cc": "c",
    "js": "jssrc",
    "javascript": "jssrc",
    "ts": "jssrc",
    "typescript": "jssrc",
}


def normalize_language(language: Optional[str]) -> Optional[str]:
    if not language:
        return None
    normalized = language.strip().lower()
    mapped = LANGUAGE_ALIASES.get(normalized, normalized)
    if mapped != normalized:
        LOG.info("Remapping language hint '%s' to '%s' for Joern import", language, mapped)
    return mapped


# ---------------------------------------------------------------------- session
def _log_conversation_message(role: str, content: str, buffer: Optional[List[str]] = None) -> None:
    prefix = f"[LLM][{role}]"
    LOG.info("%s %s", prefix, content.rstrip())
    if buffer is not None:
        buffer.append(f"{prefix} {content.rstrip()}")


class LLMPlanner:
    def __init__(self, cfg: Dict[str, Any], sink_context: str, log_buffer: Optional[List[str]] = None) -> None:
        self.cfg = cfg
        self.log_buffer = log_buffer
        self.messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": sink_context},
        ]
        _log_conversation_message("system", SYSTEM_PROMPT, self.log_buffer)
        _log_conversation_message("user", sink_context, self.log_buffer)
    def request(self) -> Dict[str, Any]:
        response = completion(
            model=self.cfg["model"],
            messages=self.messages,
            api_key=self.cfg["api_key"],
            base_url=self.cfg["base_url"],
            temperature=self.cfg.get("temperature", 0.0),
            custom_llm_provider=self.cfg.get("custom_llm_provider"),
        )
        message = response["choices"][0]["message"]["content"]
        self.messages.append({"role": "assistant", "content": message})
        _log_conversation_message("assistant", message, self.log_buffer)
        payload = extract_json_block(message)
        if "query" not in payload:
            raise ValueError(f"LLM payload missing 'query': {message}")
        return payload

    def feedback(self, text: str) -> None:
        self.messages.append({"role": "user", "content": text})
        _log_conversation_message("user", text, self.log_buffer)


# ---------------------------------------------------------------------- driver
def prepare_repo(args: argparse.Namespace) -> Path:
    if not args.repo_url:
        repo_path = Path(args.repo_root).resolve()
        if not repo_path.exists():
            raise FileNotFoundError(f"Repository path {repo_path} does not exist")
        return repo_path

    if not args.instance_id:
        raise ValueError("instance-id is required when repo-url is provided")

    clone_root = (
        Path(args.clone_dir).resolve()
        if args.clone_dir
        else Path("evaluation/benchmarks/sec_bench").resolve()
    )
    clone_dir = clone_root / args.instance_id
    if clone_dir.exists():
        LOG.info("Directory %s already exists, skipping clone", clone_dir)
    else:
        clone_dir.parent.mkdir(parents=True, exist_ok=True)
        LOG.info("Cloning %s into %s", args.repo_url, clone_dir)
        subprocess.run(["git", "clone", args.repo_url, str(clone_dir)], check=True)
    if args.base_commit:
        LOG.info("Checking out %s", args.base_commit)
        subprocess.run(
            ["git", "-C", str(clone_dir), "checkout", args.base_commit], check=True
        )
    return clone_dir

def get_source_dir(repo_root: Path, subdir: str) -> Path:
    source_dir = (repo_root / subdir).resolve()
    if not source_dir.exists():
        raise FileNotFoundError(f"Source directory {source_dir} does not exist")
    return source_dir


def map_container_path(host_path: Path, args: argparse.Namespace) -> Path:
    if not args.repo_url:
        return host_path
    clone_root = (
        Path(args.clone_dir).resolve()
        if args.clone_dir
        else Path("evaluation/benchmarks/sec_bench").resolve()
    )
    try:
        rel = host_path.relative_to(clone_root)
    except ValueError:
        rel = host_path.name
    return Path(args.container_mount_base).joinpath(rel)


def run_session(args: argparse.Namespace) -> Dict[str, Any]:
    repo_root = prepare_repo(args)
    host_source = get_source_dir(repo_root, args.code_subdir)
    container_repo = map_container_path(host_source, args)
    compose_file = Path(args.compose_file).resolve()
    config_path = Path(args.config).resolve()

    cfg = load_llm_config(config_path, args.llm_profile)
    manager = JoernManager(args.joern_port, str(compose_file), str(repo_root))
    language_hint = normalize_language(args.language)
    LOG.info(
        "Joern importCode inputPath=%s language=%s",
        container_repo,
        language_hint or "<none>",
    )
    try:
        status, stdout = manager.load_project(str(container_repo), language=language_hint)
    except RuntimeError as exc:
        text = str(exc)
        if language_hint and "No CPG generator exists for language" in text:
            LOG.warning(
                "Joern REST 不识别语言 '%s'，自动改为不传 language 再试一次", language_hint
            )
            status, stdout = manager.load_project(str(container_repo))
        else:
            raise
    LOG.info("Joern import stdout:\n%s", stdout.strip() or "<empty>")

    sink_file = repo_root / args.sink_file
    snippet = read_snippet(sink_file, args.sink_line)

    sink_context = textwrap.dedent(
        f"""\
        <SINK_CONTEXT>
        已知 sink 描述：
        - 函数: {args.sink_func}
        - 文件: {args.sink_file}
        - 行号: {args.sink_line}
        - 参数索引: {args.sink_param}
        代码上下文:
        {snippet}
        </SINK_CONTEXT>

        <SANITIZER_REPORT>
        {SANITIZER_REPORT.strip()}
        </SANITIZER_REPORT>

        行动要求：
        1) 先对 Sanitizer 报告与上述代码片段进行推理，输出一次 `PLAN_ONLY`（query 填写该字面值即可）的 JSON，内容包括：
           - 可能的崩溃机理/可疑变量
           - 准备探索的调用链与 Joern 查询思路
           - 为什么先从这些函数/变量切入
        2) 只有在完成 PLAN_ONLY 总结后，才开始执行 Joern 查询。
        3) 后续步骤按系统提示逐步逆向，直到构造出完整的数据/控制流路径。"""
    )

    conversation_log: List[str] = []
    planner = LLMPlanner(cfg, sink_context, log_buffer=conversation_log)
    collected_paths: List[List[Dict[str, Any]]] = []
    steps_log: List[Dict[str, Any]] = []
    iterations = 0

    while iterations < args.max_iters:
        iterations += 1
        LOG.info("Iteration %s", iterations)
        payload = planner.request()
        query = payload["query"]
        expect_paths = bool(payload.get("expect_paths"))

        status = QueryStatus.ERROR
        stdout = ""
        flows: List[List[Dict[str, Any]]] = []

        plan_only = query.strip().upper() == "PLAN_ONLY"
        if plan_only:
            status = QueryStatus.SUCCESS
            stdout = "PLAN_ONLY acknowledged; no Joern query executed."
        elif ".reachableBy" in query or expect_paths:
            status, flows, stdout = manager.run_reachable_query(query)
        else:
            status, stdout = manager.execute(query)

        if expect_paths and flows:
            collected_paths.extend(flows)

        full_stdout = stdout.rstrip() or "<empty>"
        summary_lines = [
            f"QUERY_EXECUTION_STATUS: {status.value}",
            f"EXPECT_PATHS: {expect_paths}",
            "STDOUT_FULL:",
            full_stdout,
        ]
        if flows:
            summary_lines.append("PATHS_PREVIEW:\n" + format_paths(flows[:2]))
        steps_log.append(
            {
                "iteration": iterations,
                "payload": payload,
                "status": status.value,
                "expect_paths": expect_paths,
                "query": query,
                "joern_stdout": stdout,
                "joern_flows": flows,
            }
        )
        planner.feedback("\n".join(summary_lines))

        if payload.get("stop") and collected_paths:
            break

    contexts = build_contexts(collected_paths, repo_root)
    return {
        "paths": collected_paths,
        "contexts": contexts,
        "iterations": iterations,
        "completed": bool(collected_paths),
        "steps": steps_log,
        "conversation": planner.messages,
        "conversation_log": conversation_log,
        "summary": build_path_summary(collected_paths, contexts),
    }


# --------------------------------------------------------------------------- CLI
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="CPG backward tracer (LLM-guided)")
    parser.add_argument("--repo-root", default=".", help="Path to repo root")
    parser.add_argument("--repo-url", help="Git repository URL to clone")
    parser.add_argument("--base-commit", help="Commit hash or ref to checkout")
    parser.add_argument(
        "--clone-dir",
        help="Directory to clone repository into when repo-url is provided (default: evaluation/benchmarks/sec_bench)",
    )
    parser.add_argument("--instance-id", help="Instance identifier (used for clone folder naming)")
    parser.add_argument(
        "--container-mount-base",
        default="/workspace/sec_bench",
        help="Mount point inside Joern container corresponding to clone-dir (default: /workspace/sec_bench)",
    )
    parser.add_argument(
        "--code-subdir",
        default=".",
        help="Relative subdirectory within repo to import (default: repo root)",
    )
    parser.add_argument(
        "--language",
        default="c",
        help="Language hint for importCode (e.g., c, cpp, jssrc). Default: c",
    )
    parser.add_argument("--sink-func", required=True)
    parser.add_argument("--sink-file", required=True)
    parser.add_argument("--sink-line", type=int, required=True)
    parser.add_argument("--sink-param", type=int, required=True)
    parser.add_argument("--compose-file", default="docker-compose.yml")
    parser.add_argument("--config", default="config.toml")
    parser.add_argument("--llm-profile", default=None)
    parser.add_argument("--joern-port", type=int, default=16240)
    parser.add_argument("--max-iters", type=int, default=30)
    parser.add_argument(
        "--output-dir",
        default="cpg_tracer/output",
        help="Directory to store resulting JSON summaries",
    )
    return parser


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
    args = build_parser().parse_args()
    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    result = run_session(args)
    suffix = args.instance_id or "output"
    summary_path = output_dir / f"{suffix}.json"
    summary_path.write_text(json.dumps(result, indent=2, ensure_ascii=False))
    md_path = output_dir / f"{suffix}.md"
    conversation_lines = result.get("conversation_log", [])
    conversation_text = "\n".join(conversation_lines)
    md_body = result.get("summary", "")
    if conversation_lines:
        md_body += "\n\n---\n## LLM Conversation\n```\n" + conversation_text + "\n```\n"
    md_path.write_text(md_body)
    convo_path = output_dir / f"{suffix}.conversation.log"
    if conversation_lines:
        convo_path.write_text(conversation_text + "\n")
    LOG.info("Wrote %s and %s", summary_path, md_path)


if __name__ == "__main__":
    main()
