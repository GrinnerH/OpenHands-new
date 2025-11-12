#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import logging
import re
import textwrap
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import tomllib
import requests

USING_LITELLM = True
try:
    from litellm import completion
except ImportError:  # pragma: no cover - fallback when litellm not installed
    from .litellm_stub import completion
    USING_LITELLM = False

from .joern_manager import JoernManager, QueryStatus
from .prompts import SYSTEM_PROMPT, SANITIZER_REPORT
from .c_parser import analyze_c_code
from .enhancer import get_context

LOG = logging.getLogger("cpg_tracer")

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CLONE_DIR = (PROJECT_ROOT / "evaluation/benchmarks/sec_bench").resolve()

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


DEFAULT_CHAT_COMPLETIONS_PATH = "/chat/completions"
DEFAULT_CHAT_COMPLETION_TIMEOUT = 120


def normalize_base_url(base_url: str, ensure_v1: Optional[bool]) -> str:
    normalized = (base_url or "").strip()
    if not normalized:
        raise ValueError("base_url is required for LLM configuration")
    normalized = normalized.rstrip("/")
    if normalized.endswith(DEFAULT_CHAT_COMPLETIONS_PATH):
        normalized = normalized[: -len(DEFAULT_CHAT_COMPLETIONS_PATH)]
    ensure_v1 = True if ensure_v1 is None else bool(ensure_v1)
    if ensure_v1 and not normalized.endswith("/v1"):
        scheme_split = normalized.split("://", 1)
        remainder = scheme_split[1] if len(scheme_split) == 2 else normalized
        path_part = remainder.split("/", 1)[1] if "/" in remainder else ""
        has_path = bool(path_part)
        if not has_path:
            normalized = f"{normalized}/v1"
    return normalized


def build_chat_completion_url(base_url: str, path: Optional[str]) -> str:
    path_value = (path or DEFAULT_CHAT_COMPLETIONS_PATH).strip()
    if not path_value.startswith("/"):
        path_value = f"/{path_value}"
    base = base_url.rstrip("/")
    if base.endswith(path_value):
        return base
    return f"{base}{path_value}"


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
    cfg = dict(cfg)
    required = ["model", "api_key", "base_url"]
    missing = [k for k in required if k not in cfg]
    if missing:
        raise ValueError(f"Missing LLM keys: {missing}")
    ensure_v1 = cfg.get("ensure_v1_path")
    cfg["base_url"] = normalize_base_url(cfg["base_url"], ensure_v1)
    cfg["chat_completions_url"] = build_chat_completion_url(
        cfg["base_url"], cfg.get("chat_completions_path")
    )
    cfg.setdefault("request_timeout", DEFAULT_CHAT_COMPLETION_TIMEOUT)
    return cfg


THINK_BLOCK_PATTERN = re.compile(r"^\s*<think>(.*?)</think>\s*", re.DOTALL)


class AssistantResponseFormatError(ValueError):
    def __init__(
        self,
        content: str,
        assistant_visible: str,
        think_content: Optional[str],
        exc: json.JSONDecodeError,
    ) -> None:
        super().__init__(f"Assistant response is not valid JSON: {content}")
        self.assistant_visible = assistant_visible
        self.think_content = think_content
        self.original = exc


def _strip_code_fence(block: str) -> str:
    trimmed = block.strip()
    if not trimmed.startswith("```"):
        return trimmed
    without_ticks = trimmed.split("```", 1)[1]
    without_ticks = without_ticks.lstrip()
    if without_ticks.startswith("json"):
        without_ticks = without_ticks[4:]
    return without_ticks.rstrip("`").strip()


def _separate_think_block(content: str) -> Tuple[str, Optional[str]]:
    block = content.strip()
    think_content = None
    match = THINK_BLOCK_PATTERN.match(block)
    if match:
        think_content = match.group(1).strip()
        block = block[match.end():].strip()
    return block, think_content


def extract_json_block(content: str) -> Tuple[Dict[str, Any], Optional[str], str]:
    """Extract JSON payload from assistant message."""
    block, think_content = _separate_think_block(content)
    assistant_visible = block
    normalized = _strip_code_fence(block)
    try:
        return json.loads(normalized), think_content, assistant_visible
    except json.JSONDecodeError as exc:
        raise AssistantResponseFormatError(content, assistant_visible, think_content, exc) from exc


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


def append_dataflow_record(output_dir: Path, instance_id: Optional[str], dataflow: Dict[str, Any]) -> None:
    """Persist DATAFLOW_JSON entries to cpg_tracer/output/data_flow_out.json."""
    output_dir.mkdir(parents=True, exist_ok=True)
    record = {"instance_id": instance_id or "default", "dataflow": dataflow}
    path = output_dir / "data_flow_out.json"
    store: Dict[str, Any] = {"entries": []}
    if path.exists():
        try:
            raw = path.read_text().strip()
            if raw:
                store = json.loads(raw)
        except json.JSONDecodeError:
            LOG.warning("Failed to parse %s; reinitializing entries list", path)
            store = {"entries": []}
    if not isinstance(store, dict):
        store = {"entries": []}
    entries = store.setdefault("entries", [])
    if not isinstance(entries, list):
        entries = store["entries"] = []
    entries.append(record)
    path.write_text(json.dumps(store, indent=2, ensure_ascii=False))


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
class OpenAICompatibleClient:
    def __init__(self, cfg: Dict[str, Any]) -> None:
        self.cfg = cfg
        self.chat_url = cfg.get("chat_completions_url") or build_chat_completion_url(
            cfg["base_url"], cfg.get("chat_completions_path")
        )
        self.timeout = cfg.get("request_timeout", DEFAULT_CHAT_COMPLETION_TIMEOUT)

    def completion(self, messages: List[Dict[str, str]]) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "model": self.cfg["model"],
            "messages": messages,
        }
        optional_fields = {
            "temperature": self.cfg.get("temperature"),
            "top_p": self.cfg.get("top_p"),
            "top_k": self.cfg.get("top_k"),
        }
        for key, value in optional_fields.items():
            if value is not None:
                payload[key] = value

        max_tokens = self.cfg.get("max_output_tokens") or self.cfg.get("max_tokens")
        if max_tokens:
            payload["max_tokens"] = max_tokens

        headers = {
            "Authorization": f"Bearer {self.cfg['api_key']}",
            "Content-Type": "application/json",
        }
        try:
            response = requests.post(
                self.chat_url,
                json=payload,
                headers=headers,
                timeout=self.timeout,
            )
            response.raise_for_status()
        except requests.RequestException as exc:  # pragma: no cover - network call
            raise RuntimeError(
                f"Failed calling OpenAI-compatible endpoint {self.chat_url}: {exc}"
            ) from exc
        return response.json()


class LLMClient:
    PROVIDER_HINT = "LLM Provider NOT provided"

    def __init__(self, cfg: Dict[str, Any]) -> None:
        self.cfg = cfg
        self.force_direct = bool(cfg.get("force_direct_http"))
        self.direct_client = OpenAICompatibleClient(cfg)

    def completion(self, messages: List[Dict[str, str]]) -> Dict[str, Any]:
        if not USING_LITELLM or self.force_direct:
            return self.direct_client.completion(messages)
        try:
            return completion(
                model=self.cfg["model"],
                messages=messages,
                api_key=self.cfg["api_key"],
                base_url=self.cfg["base_url"],
                temperature=self.cfg.get("temperature", 0.0),
                custom_llm_provider=self.cfg.get("custom_llm_provider"),
            )
        except Exception as exc:  # pragma: no cover - network call
            if self._should_retry_direct(exc):
                LOG.warning(
                    "litellm failed (%s); retrying via direct HTTP %s",
                    exc,
                    self.direct_client.chat_url,
                )
                return self.direct_client.completion(messages)
            raise

    def _should_retry_direct(self, exc: Exception) -> bool:
        if self.force_direct:
            return True
        if not USING_LITELLM:
            return False
        message = str(exc)
        if self.cfg.get("fallback_to_direct_http"):
            return True
        return self.PROVIDER_HINT in message


def _log_conversation_message(role: str, content: str, buffer: Optional[List[str]] = None) -> None:
    prefix = f"[LLM][{role}]"
    LOG.info("%s %s", prefix, content.rstrip())
    if buffer is not None:
        buffer.append(f"{prefix} {content.rstrip()}")


class LLMPlanner:
    def __init__(self, cfg: Dict[str, Any], sink_context: str, log_buffer: Optional[List[str]] = None) -> None:
        self.cfg = cfg
        self.client = LLMClient(cfg)
        self.log_buffer = log_buffer
        self.max_json_retries = int(cfg.get("max_invalid_json_retries", 3))
        self.messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": sink_context},
        ]
        _log_conversation_message("system", SYSTEM_PROMPT, self.log_buffer)
        _log_conversation_message("user", sink_context, self.log_buffer)
    def request(self) -> Dict[str, Any]:
        attempts = 0
        while True:
            response = self.client.completion(self.messages)
            message = response["choices"][0]["message"]["content"]
            try:
                payload, think_content, assistant_visible = extract_json_block(message)
            except AssistantResponseFormatError as exc:
                assistant_visible = exc.assistant_visible
                think_content = exc.think_content
                self.messages.append({"role": "assistant", "content": assistant_visible})
                _log_conversation_message("assistant", assistant_visible, self.log_buffer)
                if think_content:
                    think_msg = f"<think>{think_content}</think>"
                    _log_conversation_message("assistant-think", think_msg, self.log_buffer)
                attempts += 1
                if attempts >= self.max_json_retries:
                    raise
                warning = "上一条回答不是有效 JSON。请严格按照给定模板，仅输出 JSON。"
                self.messages.append({"role": "user", "content": warning})
                _log_conversation_message("user", warning, self.log_buffer)
                continue

            self.messages.append({"role": "assistant", "content": assistant_visible})
            _log_conversation_message("assistant", assistant_visible, self.log_buffer)
            if think_content:
                think_msg = f"<think>{think_content}</think>"
                _log_conversation_message("assistant-think", think_msg, self.log_buffer)
            if "query" not in payload and "DATAFLOW_JSON" not in payload:
                raise ValueError(
                    f"LLM payload missing 'query'/'DATAFLOW_JSON': {assistant_visible}"
                )
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
        else DEFAULT_CLONE_DIR
    )
    clone_dir = clone_root / args.instance_id
    if clone_dir.exists():
        LOG.info("Directory %s already exists, skipping clone", clone_dir)
    else:
        clone_dir.parent.mkdir(parents=True, exist_ok=True)
        LOG.info("Cloning %s into %s", args.repo_url, clone_dir)
        # 添加GitHub代理
        proxy_repo_url = "https://ghproxy.cn/"+args.repo_url
        subprocess.run(["git", "clone", proxy_repo_url, str(clone_dir)], check=True)

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
Sanitizer crash context (generic; do not assume extra fields):
- Sink function (callee): {args.sink_func}
- Callee implementation file: {args.sink_file}
- Callee internal line (context only; NEVER anchor): {args.sink_line}
- Crashing argument index (0-based as reported): {args.sink_param}

Relevant code context (may include caller/callsite hints):
{snippet}
</SINK_CONTEXT>

<SANITIZER_REPORT>
{SANITIZER_REPORT.strip()}
</SANITIZER_REPORT>

<TASK INSTRUCTIONS>
Follow the **reordered 6-step pipeline** with hard Gates (S1→S6). One JSON per turn.

S1 ArgList Gate — Anchor the REAL callsite (never by the callee’s internal line above). After anchoring, PRINT the full argument list and then lock FOCUS to the correct 1-based index (convert reported 0-based by +1; if output disagrees, trust the printed list; record the correction in "intent").

S2 DDG Gate — In the caller that contains the callsite, run `.ddgIn` on FOCUS (local slice only). If empty → go to S5 immediately.

S3 Assign Gate — List assignments to FOCUS in the current function; if struct-field propagation exists (e.g., `iargs.from`), also list those writes. Use results to prune sources.

S4 Taint Gate (mandatory) — First time you use `.reachableBy*`, include imports IN THE SAME query:
  `import io.shiftleft.semanticcpg.language._`
  `import io.joern.dataflowengineoss.language._`
Then run a **NARROW** `.reachableBy` / `.reachableByFlows` using sources derived from S2/S3 (no global wildcards). Any `.reachableBy*` step must set `"expect_paths": true`.
If empty, slightly broaden the specific source (still narrow). If still empty → S5.

S5 Pivot Gate — If S2 is empty OR S2/S3 show FOCUS is a parameter/return/struct-field OR S4 produced no path:
  • parameter k → pivot to each `caller.argument(k)`;
  • return value → enter callee and set FOCUS to the defining return expression;
  • struct-field → pivot to the caller that populates it and continue S2–S4.
Note new FOCUS and `pivot_reason` in "intent". Pivot at most **one frame** per attempt.

S6 Guard Gate (minimal, non-blocking) — After a concrete data-flow path exists, collect `.controlledBy.isControlStructure.condition.code` on BOTH the call node and the FOCUS argument node (not on methods), and summarize `path_conditions` in "intent".
If guards are found, set `guards_pending=false` and list them in `path_conditions`; if none constrain FOCUS, set `path_conditions=[]` and `guards_pending=true`. Lack of guards **must not** block completion.

First reply must be PLAN_ONLY (no Joern code):
- Output exactly one JSON with `"query": "PLAN_ONLY"`.
- In "intent": state `SINK_NAME={args.sink_func}`, `ARG_IDX_0BASED={args.sink_param}`, plan to compute `ARG_IDX_1BASED=ARG_IDX_0BASED+1` but LOCK only after S1 prints args; how you will anchor (caller+line if known; else caller+arg pattern; else disambiguate then verify by DDG/Taint); and the new step plan S1→S2→S3→S4→S5→S6.
- Keep a small step budget; if two consecutive steps add no new evidence, change strategy (run S4 or pivot S5).

Stopping rule — You may set `"stop": true` once a concrete **Source → … → Sink(FOCUS)** data-flow path is printed. Include any guards found; if none, use `path_conditions=[]` and `guards_pending=true`.

<OUTPUT FORMAT — STRICT JSON ONLY>
{{
  "query": "...",           // "PLAN_ONLY" or a valid Scala query for Joern
  "intent": "...",          // Start with FOCUS=<code> once locked; include new_evidence, path_conditions (may be []), guards_pending=true|false, pivot_reason (if any)
  "expect_paths": false,    // true ONLY when using .reachableBy or .reachableByFlows; set false for all other steps
  "stop": false             // true when data-flow path printed; guards may be empty with guards_pending=true
}}

Finalization — Regardless of success or max-iteration stop, you MUST finish by emitting exactly one top-level JSON:
{{ "DATAFLOW_JSON": {{ ... }} }}
Fill `status.result="complete"` when a concrete path exists; otherwise `status.result="partial"` with `status.reason ∈ {"max_iterations","no_path"}` and a `partial_evidence` block. Then set "stop": true.

No extra prose outside JSON; escape quotes; if imports/helpers are needed, include them inside the same "query".
</TASK INSTRUCTIONS>
"""
)





    conversation_log: List[str] = []
    planner = LLMPlanner(cfg, sink_context, log_buffer=conversation_log)
    collected_paths: List[List[Dict[str, Any]]] = []
    steps_log: List[Dict[str, Any]] = []
    iterations = 0
    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    dataflow_json: Optional[Dict[str, Any]] = None

    while iterations < args.max_iters:
        iterations += 1
        LOG.info("Iteration %s", iterations)
        payload = planner.request()
        if "DATAFLOW_JSON" in payload:
            dataflow_json = payload["DATAFLOW_JSON"]
            append_dataflow_record(output_dir, args.instance_id, dataflow_json)
            steps_log.append(
                {
                    "iteration": iterations,
                    "payload": payload,
                    "status": "DATAFLOW",
                    "expect_paths": False,
                    "query": None,
                    "joern_stdout": "",
                    "joern_flows": [],
                }
            )
            break
        query = payload["query"]
        expect_paths = bool(payload.get("expect_paths"))

        status = QueryStatus.ERROR
        stdout = ""
        flows: List[List[Dict[str, Any]]] = []

        plan_only = query.strip().upper() == "PLAN_ONLY"
        if plan_only:
            status = QueryStatus.SUCCESS
            stdout = "PLAN_ONLY acknowledged; no Joern query executed."
        else:
            status, stdout = manager.execute(query)
            flows = []

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

        if payload.get("stop"):
            break

    contexts: List[Dict[str, Any]] = []
    collected_paths = []
    summary_text = ""

    for ctx in contexts:
        lines = ", ".join(str(num) for num in ctx.get("lines", []))
        snippet = ctx.get("snippet", "").strip()
        ctx_msg = textwrap.dedent(
            f"""\
            PATH_CONTEXT #{ctx.get("path_index")}
            file: {ctx.get("file")}
            lines: {lines or "<unknown>"}
            {snippet or "<empty snippet>"}
            """
        ).strip()
        planner.messages.append({"role": "assistant", "content": ctx_msg})
        _log_conversation_message("assistant", ctx_msg, conversation_log)

    if summary_text:
        summary_msg = "PATH_SUMMARY\n" + summary_text
        planner.messages.append({"role": "assistant", "content": summary_msg})
        _log_conversation_message("assistant", summary_msg, conversation_log)

    return {
        "paths": collected_paths,
        "contexts": contexts,
        "iterations": iterations,
        "completed": iterations > 0,
        "steps": steps_log,
        "conversation": planner.messages,
        "conversation_log": conversation_log,
        "summary": summary_text,
        "dataflow_json": dataflow_json,
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
