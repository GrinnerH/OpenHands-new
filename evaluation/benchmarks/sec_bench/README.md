# SEC-bench

SEC-bench is a security benchmark for evaluating AI agents on vulnerability patching and proof-of-concept (PoC) generation tasks.

## Quick Start

For simplified execution, use the `run_secb.sh` script from root directory:

```bash
# Run PoC mode with default settings
./run_secb.sh -m poc

# Run patch mode with custom parameters
./run_secb.sh -m patch -l llm.4o -n 100 -i 30 -w 4

# More examples
./run_secb.sh --mode poc --llm llm.eval_sonnet --num-instances 50
./run_secb.sh -m patch -l llm.eval_claude_3_7 -n 200 -t my-experiment

# Show help for all options
./run_secb.sh --help
```

### Available Options

- `-m, --mode`: Mode (required): `poc` or `patch`
- `-l, --llm`: LLM profile name (default: `llm.eval_sonnet`)
- `-n, --num-instances`: Number of instances to evaluate (default: `200`)
- `-i, --iterations`: Maximum iterations (default: `50`)
- `-t, --label`: Label for the run (default: `eval`)
- `-w, --workers`: Number of workers (default: `1`)

## Configuration

### Specify a subset of tasks to run

If you would like to specify a list of tasks you'd like to benchmark on, you could create a `config.toml` under `./evaluation/benchmarks/sec_bench/` folder, and put a list attribute named `selected_ids`, e.g.

```toml
selected_ids = ['openjpeg.cve-2024-56827']
```

Then only these tasks (rows whose `instance_id` is in the above list) will be evaluated. In this case, `eval_limit` option applies to tasks that are in the `selected_ids` list.

After running the inference, you will obtain a `output.jsonl` (by default it will be saved to `evaluation/evaluation_outputs`).

## Manual Execution

### Run Inference

For more granular control, you can run inference directly using the underlying scripts:

#### Patch Mode
```bash
./evaluation/benchmarks/sec_bench/scripts/run_infer.sh llm.sonnet HEAD CodeActAgent 200 50 1 SEC-bench/SEC-bench eval 1.5 patch
```

#### PoC Mode
```bash
./evaluation/benchmarks/sec_bench/scripts/run_infer.sh llm.sonnet HEAD CodeActAgent 200 50 1 SEC-bench/SEC-bench eval 1.5 poc
```

#### Other Model Examples
```bash
./evaluation/benchmarks/sec_bench/scripts/run_infer.sh llm.claude_3_7 HEAD CodeActAgent 10 30 1 hwiwonl/SEC-bench test
./evaluation/benchmarks/sec_bench/scripts/run_infer.sh llm.gpt_4o HEAD CodeActAgent 10 30 1 hwiwonl/SEC-bench test
./evaluation/benchmarks/sec_bench/scripts/run_infer.sh llm.gemini-1-5-pro HEAD CodeActAgent 10 30 1 hwiwonl/SEC-bench test
./evaluation/benchmarks/sec_bench/scripts/run_infer.sh llm.gemini-2-0-flash-thinking-exp HEAD CodeActAgent 10 30 1 hwiwonl/SEC-bench test
```

## Modes

- **Patch Mode**: Generates and applies security patches to fix vulnerabilities
- **PoC Mode**: Generates proof-of-concept exploits to demonstrate vulnerabilities

## Output

Results are saved to `evaluation/evaluation_outputs` with detailed logs and evaluation metrics.
