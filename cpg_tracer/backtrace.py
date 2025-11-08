#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import logging
import textwrap
from pathlib import Path
from typing import Any, Dict, List, Optional

import tomllib
try:
    from litellm import completion
except ImportError:  # pragma: no cover - fallback when litellm not installed
    from .litellm_stub import completion

from .joern_manager import JoernManager, QueryStatus
from .prompts import SYSTEM_PROMPT

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


def build_path_summary(paths: List[List[Dict[str, Any]]]) -> str:
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


# ---------------------------------------------------------------------- session
class LLMPlanner:
    def __init__(self, cfg: Dict[str, Any], sink_context: str) -> None:
        self.cfg = cfg
        self.messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": sink_context},
        ]

    def request(self) -> Dict[str, Any]:
        response = completion(
            model=self.cfg["model"],
            messages=self.messages,
            api_key=self.cfg["api_key"],
            base_url=self.cfg["base_url"],
            temperature=self.cfg.get("temperature", 0.0),
        )
        message = response["choices"][0]["message"]["content"]
        self.messages.append({"role": "assistant", "content": message})
        payload = extract_json_block(message)
        if "query" not in payload:
            raise ValueError(f"LLM payload missing 'query': {message}")
        return payload

    def feedback(self, text: str) -> None:
        self.messages.append({"role": "user", "content": text})


# ---------------------------------------------------------------------- driver
def run_session(args: argparse.Namespace) -> Dict[str, Any]:
    repo_root = Path(args.repo_root).resolve()
    compose_file = Path(args.compose_file).resolve()
    config_path = Path(args.config).resolve()

    cfg = load_llm_config(config_path, args.llm_profile)
    manager = JoernManager(args.joern_port, str(compose_file), str(repo_root))
    manager.load_project(str(repo_root))

    sink_file = repo_root / args.sink_file
    snippet = read_snippet(sink_file, args.sink_line)

    sink_context = textwrap.dedent(
        f"""\
        已知 sink 描述：
        - 函数: {args.sink_func}
        - 文件: {args.sink_file}
        - 行号: {args.sink_line}
        - 参数索引: {args.sink_param}
        代码上下文:
        {snippet}

        目标：构造 Joern 查询，逐步逆向获得完整的数据流与控制流。
        每次收到查询结果后，我会反馈 Joern 的 stdout 以及解析出的路径，请继续计划直到路径充分。"""
    )

    planner = LLMPlanner(cfg, sink_context)
    collected_paths: List[List[Dict[str, Any]]] = []
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

        if ".reachableBy" in query or expect_paths:
            status, flows, stdout = manager.run_reachable_query(query)
        else:
            status, stdout = manager.execute(query)

        if expect_paths and flows:
            collected_paths.extend(flows)

        summary_lines = [
            f"QUERY_EXECUTION_STATUS: {status.value}",
            f"EXPECT_PATHS: {expect_paths}",
            "STDOUT_SNIPPET:",
            summarize_stdout(stdout),
        ]
        if flows:
            summary_lines.append("PATHS_PREVIEW:\n" + format_paths(flows[:2]))
        planner.feedback("\n".join(summary_lines))

        if payload.get("stop") and collected_paths:
            break

    return {
        "paths": collected_paths,
        "iterations": iterations,
        "completed": bool(collected_paths),
        "summary": build_path_summary(collected_paths),
    }


# --------------------------------------------------------------------------- CLI
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="CPG backward tracer (LLM-guided)")
    parser.add_argument("--repo-root", required=True, help="Path to repo root")
    parser.add_argument("--sink-func", required=True)
    parser.add_argument("--sink-file", required=True)
    parser.add_argument("--sink-line", type=int, required=True)
    parser.add_argument("--sink-param", type=int, required=True)
    parser.add_argument("--compose-file", default="docker-compose.yml")
    parser.add_argument("--config", default="config.toml")
    parser.add_argument("--llm-profile", default=None)
    parser.add_argument("--joern-port", type=int, default=8081)
    parser.add_argument("--max-iters", type=int, default=10)
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
    summary_path = output_dir / "paths.json"
    summary_path.write_text(json.dumps(result, indent=2, ensure_ascii=False))
    md_path = output_dir / "paths.md"
    md_path.write_text(result.get("summary", ""))
    LOG.info("Wrote %s and %s", summary_path, md_path)


if __name__ == "__main__":
    main()
