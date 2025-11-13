#!/usr/bin/env python3
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path
from typing import Iterable, List, Optional, Sequence, Set

DEFAULT_DATASET_FILE = Path("evaluation/benchmarks/sec_bench/instance_ids.txt")


def read_instance_ids(path: Path) -> List[str]:
    if not path.exists():
        raise FileNotFoundError(f"Instance list file not found: {path}")
    ids: List[str] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        ids.append(line)
    return ids


def apply_slice(ids: Sequence[str], slice_expr: str | None) -> Sequence[str]:
    if not slice_expr:
        return ids
    if ":" not in slice_expr:
        raise ValueError("Slice must be in START:END format (1-based, inclusive).")
    start_str, end_str = slice_expr.split(":", 1)
    if not start_str or not end_str:
        raise ValueError("Slice requires both start and end positions.")
    start = int(start_str)
    end = int(end_str)
    if start < 1 or end < start:
        raise ValueError("Slice positions must satisfy 1 <= start <= end.")
    # Convert to zero-based indices; end is inclusive.
    start_idx = start - 1
    end_idx = min(len(ids), end)
    return ids[start_idx:end_idx]


def deduplicate_preserve_order(values: Iterable[str]) -> List[str]:
    seen: Set[str] = set()
    ordered: List[str] = []
    for item in values:
        if item not in seen:
            seen.add(item)
            ordered.append(item)
    return ordered


def build_instance_list(args: argparse.Namespace) -> List[str]:
    collected: List[str] = []

    if args.instances:
        collected.extend(args.instances)

    if args.config_file:
        collected.extend(read_instance_ids(Path(args.config_file)))

    dataset_ids: List[str] = []
    if args.dataset_file:
        dataset_ids = read_instance_ids(Path(args.dataset_file))
    elif args.all or args.slice:
        dataset_ids = read_instance_ids(DEFAULT_DATASET_FILE)

    if args.slice:
        if not dataset_ids:
            dataset_ids = read_instance_ids(Path(args.dataset_file or DEFAULT_DATASET_FILE))
        dataset_ids = list(apply_slice(dataset_ids, args.slice))

    if args.all and dataset_ids:
        collected.extend(dataset_ids)
    elif not args.all and not args.instances and not args.config_file and dataset_ids and not args.slice:
        # If no explicit selection but dataset file provided, default to entire dataset.
        collected.extend(dataset_ids)

    if not collected:
        raise ValueError(
            "No instance IDs specified. Use --instances, --config-file, "
            "--dataset-file, --all, or --slice."
        )

    return deduplicate_preserve_order(collected)


def run_instance(
    instance_id: str,
    python_exec: str,
    backtrace_args: Sequence[str],
    dry_run: bool = False,
    llm_profile: Optional[str] = None,
) -> int:
    cmd = [python_exec, "-m", "cpg_tracer.backtrace", "--instance-id", instance_id]
    if llm_profile:
        cmd.extend(["--llm-profile", llm_profile])
    cmd.extend(backtrace_args)
    print(f"[run_instances] Starting instance '{instance_id}'")
    if dry_run:
        print(f"[run_instances] DRY RUN: {' '.join(cmd)}")
        return 0
    result = subprocess.run(cmd, check=False)
    if result.returncode == 0:
        print(f"[run_instances] Completed '{instance_id}' successfully")
    else:
        print(f"[run_instances] Instance '{instance_id}' failed with code {result.returncode}")
    return result.returncode


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Batch runner for cpg_tracer/backtrace instances."
    )
    parser.add_argument(
        "--instances",
        nargs="+",
        help="One or more instance IDs to run (in addition to IDs from config/dataset).",
    )
    parser.add_argument(
        "--config-file",
        help="Path to a file containing instance IDs (one per line).",
    )
    parser.add_argument(
        "--dataset-file",
        help=(
            "Path to the dataset instance list (one per line). "
            f"Default: {DEFAULT_DATASET_FILE}"
        ),
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Run every instance from --dataset-file (or the default dataset list).",
    )
    parser.add_argument(
        "--slice",
        help="Run a slice of the dataset in the form START:END (1-based, inclusive).",
    )
    parser.add_argument(
        "--llm-profile",
        help="LLM profile name to pass through to each backtrace invocation.",
    )
    parser.add_argument(
        "--python-exec",
        default=sys.executable,
        help="Python executable to use for invoking backtrace (default: current interpreter).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print commands without executing them.",
    )
    parser.add_argument(
        "backtrace_args",
        nargs=argparse.REMAINDER,
        help=(
            "Arguments passed through to `python -m cpg_tracer.backtrace`. "
            "Use '--' to separate runner options from backtrace options."
        ),
    )
    parsed = parser.parse_args(argv)
    if parsed.backtrace_args and parsed.backtrace_args[0] == "--":
        parsed.backtrace_args = parsed.backtrace_args[1:]
    return parsed


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])

    try:
        instances = build_instance_list(args)
    except Exception as exc:  # noqa: BLE001
        print(f"[run_instances] Error: {exc}", file=sys.stderr)
        return 1

    if not instances:
        print("[run_instances] No instances to run.", file=sys.stderr)
        return 1

    successes = 0
    failures: List[str] = []

    for instance_id in instances:
        code = run_instance(
            instance_id=instance_id,
            python_exec=args.python_exec,
            backtrace_args=args.backtrace_args,
            dry_run=args.dry_run,
            llm_profile=args.llm_profile,
        )
        if code == 0:
            successes += 1
        else:
            failures.append(instance_id)

    print(
        f"[run_instances] Completed {successes}/{len(instances)} instances "
        f"(failures: {len(failures)})"
    )
    if failures:
        print("[run_instances] Failed instances: " + ", ".join(failures))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
