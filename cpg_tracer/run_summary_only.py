#!/usr/bin/env python3
"""
Re-run DATAFLOW_JSON summarization using an existing Joern execution trace JSON.

Example:
python -m cpg_tracer.run_summary_only \
  --summary-json cpg_tracer/output-OOB-v2/njs.cve-2022-38890/njs.cve-2022-38890.json \
  --output-dir cpg_tracer/output-OOB-v2 \
  --instance-id njs.cve-2022-38890
"""
from __future__ import annotations

import argparse
from pathlib import Path

from .backtrace import generate_dataflow_summary, load_llm_config


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Re-run DATAFLOW_JSON summarizer on an existing Joern trace JSON."
    )
    parser.add_argument(
        "--summary-json",
        required=True,
        help="Path to the Joern execution trace JSON (the <instance>.json produced by backtrace).",
    )
    parser.add_argument(
        "--config",
        default="config.toml",
        help="Path to LLM config TOML (default: config.toml).",
    )
    parser.add_argument(
        "--llm-profile",
        default=None,
        help="Optional profile name inside the config TOML.",
    )
    parser.add_argument(
        "--output-dir",
        default="cpg_tracer/output",
        help="Directory where DATAFLOW_JSON records are stored (data_flow_out.json).",
    )
    parser.add_argument(
        "--instance-id",
        default=None,
        help="Instance ID for the record; default derives from summary-json filename stem.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    summary_path = Path(args.summary_json).resolve()
    if not summary_path.exists():
        raise FileNotFoundError(f"summary JSON not found: {summary_path}")

    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    config_path = Path(args.config).resolve()
    cfg = load_llm_config(config_path, args.llm_profile)

    instance_id = args.instance_id or summary_path.stem
    dataflow_json, summary_log = generate_dataflow_summary(
        cfg=cfg,
        summary_path=summary_path,
        output_dir=output_dir,
        instance_id=instance_id,
    )

    print(f"[run_summary_only] DATAFLOW_JSON written for {instance_id}")
    print(f"[run_summary_only] Records store: {output_dir / 'data_flow_out.json'}")
    if summary_log:
        print("[run_summary_only] summary log lines:")
        for line in summary_log:
            print(line)


if __name__ == "__main__":
    main()
