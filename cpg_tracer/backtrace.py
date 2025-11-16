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

try:
    from datasets import load_dataset as hf_load_dataset
except ImportError:  # pragma: no cover - optional dependency
    hf_load_dataset = None

import tomllib
import requests

USING_LITELLM = True
try:
    from litellm import completion
except ImportError:  # pragma: no cover - fallback when litellm not installed
    from .litellm_stub import completion
    USING_LITELLM = False

from .joern_manager import JoernManager, QueryStatus
from .prompts import SYSTEM_PROMPT
from .summary_prompt import SYSTEM_PROMPT as SUMMARY_SYSTEM_PROMPT
from .c_parser import analyze_c_code
from .enhancer import get_context

LOG = logging.getLogger("cpg_tracer")

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CLONE_DIR = (PROJECT_ROOT / "evaluation/benchmarks/sec_bench").resolve()
DATAFLOW_STORE_NAME = "data_flow_out.json"
DEFAULT_HF_DATASET = "SEC-bench/SEC-bench"
DEFAULT_HF_SPLIT = "eval"

INSTANCE_METADATA_CACHE: Dict[str, Dict[str, Any]] = {}
METADATA_SOURCE_LABEL: Optional[str] = None


def append_dataflow_record(output_dir: Path, instance_id: Optional[str], dataflow: Dict[str, Any]) -> None:
    """Persist DATAFLOW_JSON results for downstream tooling."""
    record = {
        "instance_id": instance_id or "output",
        "dataflow": dataflow,
    }
    store_path = output_dir / DATAFLOW_STORE_NAME
    payload: List[Dict[str, Any]] = []
    if store_path.exists():
        raw = store_path.read_text().strip()
        if raw:
            try:
                decoded = json.loads(raw)
                if isinstance(decoded, list):
                    payload = decoded
            except json.JSONDecodeError:
                LOG.warning("dataflow store %s is invalid JSON; recreating", store_path)
    payload = [entry for entry in payload if entry.get("instance_id") != record["instance_id"]]
    payload.append(record)
    store_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False))


# ------------------------------------------------------------------ metadata IO
def _load_metadata_from_file(path: Path) -> Dict[str, Dict[str, Any]]:
    text = path.read_text(encoding="utf-8").strip()
    records: List[Dict[str, Any]] = []
    if not text:
        return {}
    if path.suffix.lower() == ".jsonl":
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            records.append(json.loads(line))
    else:
        data = json.loads(text)
        if isinstance(data, list):
            records = data
        elif isinstance(data, dict):
            if "instances" in data and isinstance(data["instances"], list):
                records = data["instances"]
            else:
                records = [data]
        else:
            raise ValueError(f"Unsupported metadata format in {path}")
    return {
        rec["instance_id"]: rec
        for rec in records
        if isinstance(rec, dict) and rec.get("instance_id")
    }


def _load_metadata_from_hf(dataset_name: str, split: str) -> Dict[str, Dict[str, Any]]:
    if hf_load_dataset is None:
        raise RuntimeError(
            "datasets library is not installed. Install `datasets` or provide "
            "--metadata-file to supply SEC-bench instance metadata."
        )
    LOG.info("Loading dataset %s (split=%s) from Hugging Face", dataset_name, split)
    ds = hf_load_dataset(dataset_name, split=split)
    return {
        rec["instance_id"]: rec
        for rec in ds  # type: ignore[assignment]
        if isinstance(rec, dict) and rec.get("instance_id")
    }


def _get_instance_metadata(args: argparse.Namespace) -> Dict[str, Any]:
    if not args.instance_id:
        raise ValueError("instance-id is required to access dataset metadata")
    _ensure_metadata_cache(args)
    meta = INSTANCE_METADATA_CACHE.get(args.instance_id)
    if not meta:
        raise ValueError(
            f"Instance '{args.instance_id}' not found in metadata "
            f"({METADATA_SOURCE_LABEL or 'unknown source'})"
        )
    return meta


def _ensure_metadata_cache(args: argparse.Namespace) -> None:
    global INSTANCE_METADATA_CACHE, METADATA_SOURCE_LABEL
    if INSTANCE_METADATA_CACHE:
        return
    if args.metadata_file:
        path = Path(args.metadata_file).resolve()
        INSTANCE_METADATA_CACHE = _load_metadata_from_file(path)
        METADATA_SOURCE_LABEL = str(path)
    else:
        dataset_name = args.hf_dataset or DEFAULT_HF_DATASET
        split = args.hf_split or DEFAULT_HF_SPLIT
        INSTANCE_METADATA_CACHE = _load_metadata_from_hf(dataset_name, split)
        METADATA_SOURCE_LABEL = f"{dataset_name}:{split}"
    LOG.info(
        "Loaded %s instance metadata entries from %s",
        len(INSTANCE_METADATA_CACHE),
        METADATA_SOURCE_LABEL,
    )


def _derive_repo_url(meta: Dict[str, Any]) -> Optional[str]:
    repo = meta.get("repo")
    if not repo:
        return None
    repo = str(repo).strip()
    if repo.startswith("http://") or repo.startswith("https://"):
        return repo
    if repo.endswith(".git"):
        repo = repo[:-4]
    return f"https://github.com/{repo}"


def _derive_code_subdir(meta: Dict[str, Any]) -> str:
    explicit = meta.get("code_subdir")
    if isinstance(explicit, str) and explicit.strip():
        value = explicit.strip().lstrip("./")
        return value or "."
    work_dir = meta.get("work_dir") or meta.get("workdir")
    if isinstance(work_dir, str) and work_dir.strip():
        wd = work_dir.strip()
        if wd.startswith("/src/"):
            # In SEC-bench images, repos are placed at /src/<project>.
            # This indicates we should operate at repo root.
            return "."
        wd = wd.lstrip("./")
        return wd or "."
    return "."


def _derive_language(meta: Dict[str, Any]) -> Optional[str]:
    lang = meta.get("lang") or meta.get("language")
    if isinstance(lang, str) and lang.strip():
        return lang.strip()
    return None


def populate_instance_defaults(args: argparse.Namespace) -> None:
    """Populate repo/language settings from SEC-bench metadata for given instance."""
    if not args.instance_id:
        return
    need_repo = not args.repo_url
    need_commit = not args.base_commit
    need_code_subdir = args.code_subdir == "." or not args.code_subdir
    need_language = args.language in (None, "", "c")
    if not (need_repo or need_commit or need_code_subdir or need_language):
        return
    meta = _get_instance_metadata(args)
    if need_repo:
        repo_url = _derive_repo_url(meta)
        if not repo_url:
            raise ValueError(f"No 'repo' field for instance '{args.instance_id}'")
        args.repo_url = repo_url
    if need_commit and meta.get("base_commit"):
        args.base_commit = meta["base_commit"]
    if need_code_subdir:
        args.code_subdir = _derive_code_subdir(meta)
    if need_language:
        language = _derive_language(meta)
        if language:
            args.language = language
    if not args.language:
        args.language = "c"


# --------------------------------------------------------------------------- sink helpers
def resolve_sanitizer_report(args: argparse.Namespace) -> str:
    cached = getattr(args, "_cached_sanitizer_report", None)
    if isinstance(cached, str) and cached.strip():
        return cached

    if not args.instance_id:
        raise ValueError("instance-id is required to load sanitizer report metadata")
    meta = _get_instance_metadata(args)
    text: Optional[str] = None
    report_value = meta.get("sanitizer_report") or meta.get("asan_report")
    if isinstance(report_value, str):
        text = report_value.strip()

    if not text:
        raise ValueError(
            "Sanitizer report not found in metadata. Ensure dataset provides "
            "a 'sanitizer_report' (or 'asan_report') field."
        )

    setattr(args, "_cached_sanitizer_report", text)
    return text


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


def _parse_sink_metadata(report: str) -> Dict[str, Optional[str]]:
    """Return sink metadata (function, file, line, column) parsed from sanitizer output."""
    metadata: Dict[str, Optional[str]] = {
        "function": None,
        "file": None,
        "line": None,
        "column": None,
    }
    for raw_line in report.splitlines():
        line = raw_line.strip()
        if not line.startswith("#0 "):
            continue
        _, _, after_in = line.partition(" in ")
        if not after_in:
            continue
        func, _, remainder = after_in.partition(" ")
        remainder = remainder.strip()
        if not remainder:
            continue
        parts = remainder.rsplit(":", 2)
        if len(parts) < 2:
            continue
        path_part = parts[0].strip()
        line_part = parts[1].strip()
        col_part = parts[2].strip() if len(parts) == 3 else None
        metadata["function"] = func
        metadata["file"] = path_part or None
        metadata["line"] = line_part or None
        metadata["column"] = col_part or None
        break
    return metadata


def _resolve_source_path(raw_path: Optional[str], source_root: Path) -> Optional[Path]:
    if not raw_path:
        return None
    candidate = Path(raw_path)
    if candidate.exists():
        return candidate
    parts = candidate.parts
    for idx in range(len(parts)):
        suffix = Path(*parts[idx:])
        test_path = source_root / suffix
        if test_path.exists():
            return test_path
    if candidate.name:
        matches = list(source_root.rglob(candidate.name))
        if len(matches) == 1:
            return matches[0]
    return None


def _build_sink_context_block(source_root: Path, report: str) -> str:
    meta = _parse_sink_metadata(report)
    resolved = _resolve_source_path(meta.get("file"), source_root)
    snippet_text = ""
    if resolved and meta.get("line") and meta["line"].isdigit():
        try:
            snippet_text = read_snippet(resolved, int(meta["line"]))
        except OSError as exc:
            LOG.warning("Failed to read sink snippet from %s: %s", resolved, exc)
    block_lines = ["<SINK_CONTEXT>"]
    block_lines.append(f"sink_function: {meta.get('function') or '<unknown>'}")
    block_lines.append(f"sink_source_file: {meta.get('file') or '<unknown>'}")
    block_lines.append(f"resolved_source_file: {str(resolved) if resolved else '<unresolved>'}")
    block_lines.append(f"sink_line: {meta.get('line') or '<unknown>'}")
    if meta.get("column"):
        block_lines.append(f"sink_column: {meta['column']}")
    if snippet_text:
        block_lines.append("<CODE_SNIPPET>")
        block_lines.append(snippet_text)
        block_lines.append("</CODE_SNIPPET>")
    else:
        block_lines.append("snippet: <unavailable>")
    block_lines.append("</SINK_CONTEXT>")
    return "\n".join(block_lines)


_SANITIZER_KEYWORDS = [
    "heap-use-after-free",
    "stack-use-after-free",
    "heap-buffer-overflow",
    "stack-buffer-overflow",
    "global-buffer-overflow",
    "null pointer",
    "segv",
]


def _build_analysis_hints_block(args: argparse.Namespace, report: str) -> str:
    lines = ["<ANALYSIS_HINTS>"]
    instance_id = args.instance_id or "<unknown>"
    lines.append(f"instance_id: {instance_id}")

    lowered_report = report.lower()
    found_keywords = sorted({kw for kw in _SANITIZER_KEYWORDS if kw in lowered_report})
    if found_keywords:
        lines.append("sanitizer_keywords: " + ", ".join(found_keywords))
    else:
        lines.append("sanitizer_keywords: <none>")

    metadata_notes: List[str] = []
    try:
        meta = _get_instance_metadata(args)
    except Exception:
        meta = None
    if meta:
        entries = [
            ("project", meta.get("project_name")),
            ("repo", meta.get("repo")),
            ("base_commit", meta.get("base_commit")),
            ("language", meta.get("lang") or meta.get("language")),
        ]
        for label, value in entries:
            if isinstance(value, str) and value.strip():
                metadata_notes.append(f"{label}={value.strip()}")
    if metadata_notes:
        lines.append("metadata: " + "; ".join(metadata_notes))
    else:
        lines.append("metadata: <unavailable>")
    lines.append("</ANALYSIS_HINTS>")
    return "\n".join(lines)


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
    "c": "c",
    "cpp": "cpp",
    "c++": "cpp",
    "cxx": "cpp",
    "cc": "cpp",
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


def _log_run_event(tag: str, content: str, buffer: Optional[List[str]] = None) -> None:
    prefix = f"[RUN][{tag}]"
    LOG.info("%s %s", prefix, content.rstrip())
    if buffer is not None:
        buffer.append(f"{prefix} {content.rstrip()}")


class LLMPlanner:
    def __init__(
        self,
        cfg: Dict[str, Any],
        initial_user_content: str,
        log_buffer: Optional[List[str]] = None,
        system_prompt: Optional[str] = None,
        expect_dataflow: bool = False,
    ) -> None:
        self.cfg = cfg
        self.client = LLMClient(cfg)
        self.log_buffer = log_buffer
        self.max_json_retries = int(cfg.get("max_invalid_json_retries", 3))
        self.system_prompt = system_prompt or SYSTEM_PROMPT
        self.expect_dataflow = expect_dataflow
        self.messages = [
            {"role": "system", "content": self.system_prompt},
            {"role": "user", "content": initial_user_content},
        ]
        _log_conversation_message("system", self.system_prompt, self.log_buffer)
        _log_conversation_message("user", initial_user_content, self.log_buffer)
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
            if "query" not in payload:
                if self.expect_dataflow and "DATAFLOW_JSON" in payload:
                    return payload
                raise ValueError(f"LLM payload missing 'query': {assistant_visible}")
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


def run_session(args: argparse.Namespace, cfg: Dict[str, Any], sanitizer_report: str) -> Dict[str, Any]:
    repo_root = prepare_repo(args)
    host_source = get_source_dir(repo_root, args.code_subdir)
    container_repo = map_container_path(host_source, args)
    compose_file = Path(args.compose_file).resolve()
    manager = JoernManager(args.joern_port, str(compose_file), str(repo_root))
    conversation_log: List[str] = []
    language_hint = normalize_language("cpp")
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
    import_stdout = stdout.strip() or "<empty>"
    LOG.info("Joern import stdout:\n%s", import_stdout)
    _log_run_event(
        "joern-import",
        f"status={status.value}\n{import_stdout}",
        conversation_log,
    )

    sink_block = _build_sink_context_block(host_source, sanitizer_report)
    analysis_block = _build_analysis_hints_block(args, sanitizer_report)

    sink_context = textwrap.dedent(
f"""\
{sink_block}

<SANITIZER_REPORT>
{sanitizer_report.strip()}
</SANITIZER_REPORT>

{analysis_block}

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
  - parameter k → pivot to each `caller.argument(k)`;
  - return value → enter callee and set FOCUS to the defining return expression;
  - struct-field → pivot to the caller that populates it and continue S2–S4.
Note new FOCUS and `pivot_reason` in "intent". Pivot at most **one frame** per attempt.

S6 Guard Gate (minimal, non-blocking) — After a concrete data-flow path exists, collect `.controlledBy.isControlStructure.condition.code` on BOTH the call node and the FOCUS argument node (not on methods), and summarize `path_conditions` in "intent".
If guards are found, set `guards_pending=false` and list them in `path_conditions`; if none constrain FOCUS, set `path_conditions=[]` and `guards_pending=true`. Lack of guards **must not** block completion.

First reply must be PLAN_ONLY (no Joern code):
- Output exactly one JSON with `"query": "PLAN_ONLY"`.
- In "intent": include the reasoning fields required by the SYSTEM_PROMPT
  (`BUG_FAMILY`, `SINK_KIND`, `SOURCE_KINDS`, `PLAN`, and optionally `pivot_reason`,
  `path_conditions`), and restate the sink metadata you inferred from the sanitizer report
  (function from stack frame #0, source file + line, crashing arg index if present; if missing,
  use `-1`). Plan to compute `ARG_IDX_1BASED=ARG_IDX_0BASED+1` but LOCK only after S1 prints args;
  describe how you will anchor (caller+line if known; else enumerate and verify) and outline the
  plan S1→S2→S3→S4→S5→S6 with ≤14 steps (Delta rule).
- Keep a small step budget; if two consecutive steps add no new evidence, change strategy
  (run S4 or pivot S5).

Stopping rule — You may set `"stop": true` once a concrete **Source → … → Sink(FOCUS)** data-flow path is printed. Include any guards found; if none, use `path_conditions=[]` and `guards_pending=true`.

<OUTPUT FORMAT — STRICT JSON ONLY>
{{
  "query": "...",           // "PLAN_ONLY" or a valid Scala query for Joern
  "intent": "...",          // Start with FOCUS=<code> once locked; include new_evidence, path_conditions (may be []), guards_pending=true|false, pivot_reason (if any)
  "expect_paths": false,    // true ONLY when using .reachableBy or .reachableByFlows; set false for all other steps
  "stop": false             // true when data-flow path printed; guards may be empty with guards_pending=true
}}

No extra prose outside JSON; escape quotes; if imports/helpers are needed, include them inside the same "query".
</TASK INSTRUCTIONS>
"""
)
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
        validator_hint = ""
        path_result = ""

        plan_only = query.strip().upper() == "PLAN_ONLY"
        if plan_only:
            status = QueryStatus.SUCCESS
            stdout = "PLAN_ONLY acknowledged; no Joern query executed."
        else:
            if expect_paths:
                status, flows, stdout = manager.run_reachable_query(query)
                if status == QueryStatus.SUCCESS and flows:
                    collected_paths.extend(flows)
                    path_result = "success"
                else:
                    path_result = "empty"
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
        if path_result:
            summary_lines.append(f"PATH_RESULT: {path_result}")
        if flows:
            summary_lines.append("PATHS_PREVIEW:\n" + format_paths(flows[:2]))
        if status == QueryStatus.ERROR:
            summary_lines.append("ERROR_INFO: " + summarize_stdout(stdout))
            validator_hint = validator_hint or "error_in_query_syntax_or_runtime"
        elif status == QueryStatus.EMPTY and expect_paths:
            validator_hint = "reachable_query_returned_no_paths"
        elif status == QueryStatus.EMPTY:
            validator_hint = "query_returned_empty"
        if validator_hint:
            summary_lines.append(f"VALIDATOR_HINT: {validator_hint}")
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
    summary_text = ""
    if collected_paths:
        contexts = build_contexts(collected_paths, repo_root)
        summary_text = build_path_summary(collected_paths, contexts)

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
    }


def generate_dataflow_summary(
    cfg: Dict[str, Any],
    summary_path: Path,
    output_dir: Path,
    instance_id: Optional[str],
) -> Tuple[Dict[str, Any], List[str]]:
    data = json.loads(summary_path.read_text())
    sanitized = dict(data)
    sanitized.pop("conversation", None)
    sanitized.pop("conversation_log", None)
    summary_input = "<ANALYSIS_JSON>\n" + json.dumps(sanitized, ensure_ascii=False, indent=2) + "\n</ANALYSIS_JSON>"
    summary_log: List[str] = []
    planner = LLMPlanner(
        cfg,
        summary_input,
        log_buffer=summary_log,
        system_prompt=SUMMARY_SYSTEM_PROMPT,
        expect_dataflow=True,
    )
    payload = planner.request()
    dataflow = payload.get("DATAFLOW_JSON")
    if not isinstance(dataflow, dict):
        raise ValueError("Summary stage did not return DATAFLOW_JSON")
    append_dataflow_record(output_dir, instance_id, dataflow)
    return dataflow, summary_log


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
    # Sink metadata now derived directly from sanitizer report inside prompts
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
    parser.add_argument(
        "--metadata-file",
        help="Path to JSON/JSONL file containing SEC-bench instance metadata (optional)",
    )
    parser.add_argument(
        "--hf-dataset",
        default=DEFAULT_HF_DATASET,
        help=f"Hugging Face dataset to load instance metadata when --metadata-file is not provided (default: {DEFAULT_HF_DATASET})",
    )
    parser.add_argument(
        "--hf-split",
        default=DEFAULT_HF_SPLIT,
        help=f"Dataset split to load from Hugging Face (default: {DEFAULT_HF_SPLIT})",
    )
    return parser


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
    args = build_parser().parse_args()
    if args.instance_id:
        populate_instance_defaults(args)

    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    config_path = Path(args.config).resolve()
    cfg = load_llm_config(config_path, args.llm_profile)

    sanitizer_report = resolve_sanitizer_report(args)
    result = run_session(args, cfg, sanitizer_report)
    suffix = args.instance_id or "output"
    instance_dir = output_dir / suffix
    instance_dir.mkdir(parents=True, exist_ok=True)
    summary_path = instance_dir / f"{suffix}.json"
    summary_path.write_text(json.dumps(result, indent=2, ensure_ascii=False))

    dataflow_json, summary_log = generate_dataflow_summary(
        cfg,
        summary_path,
        output_dir,
        suffix,
    )

    md_path = instance_dir / f"{suffix}.md"
    conversation_lines = result.get("conversation_log", [])
    conversation_text = "\n".join(conversation_lines)
    md_body = result.get("summary", "")
    if conversation_lines:
        md_body += "\n\n---\n## LLM Conversation\n```\n" + conversation_text + "\n```\n"
    if summary_log:
        summary_text = "\n".join(summary_log)
        md_body += "\n\n---\n## DATAFLOW Summary Conversation\n```\n" + summary_text + "\n```\n"
    md_path.write_text(md_body)
    LOG.info("Appended DATAFLOW_JSON for %s", suffix)
    convo_path = instance_dir / f"{suffix}.conversation.log"
    if conversation_lines:
        convo_path.write_text(conversation_text + "\n")
    LOG.info("Wrote %s and %s", summary_path, md_path)


if __name__ == "__main__":
    main()
