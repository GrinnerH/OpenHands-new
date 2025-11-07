#!/bin/bash

# Default values
mode="deepseek-chat"
llm_profile="llm.DMXAPI"
num_instances=200
max_iterations=75
label="eval"
num_workers=1

# Usage function
usage() {
    echo "Usage: $0 -m <mode> [options]"
    echo ""
    echo "Required:"
    echo "  -m, --mode MODE           Mode: poc or patch"
    echo ""
    echo "Options:"
    echo "  -l, --llm PROFILE         LLM profile name (default: llm.sonnet)"
    echo "  -n, --num-instances NUM   Number of instances to evaluate (default: 200)"
    echo "  -i, --iterations NUM      Maximum iterations (default: 75)"
    echo "  -t, --label LABEL         Label for the run (default: eval)"
    echo "  -w, --workers NUM         Number of workers (default: 1)"
    echo "  -h, --help                Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 -m poc"
    echo "  $0 -m patch -l llm.4o -n 100 -i 30 -w 4"
    echo "  $0 --mode poc --llm llm.sonnet --num-instances 50"
    exit 1
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -m|--mode)
            mode="$2"
            shift 2
            ;;
        -l|--llm)
            llm_profile="$2"
            shift 2
            ;;
        -n|--num-instances)
            num_instances="$2"
            shift 2
            ;;
        -i|--iterations)
            max_iterations="$2"
            shift 2
            ;;
        -t|--label)
            label="$2"
            shift 2
            ;;
        -w|--workers)
            num_workers="$2"
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "Error: Unknown option $1"
            usage
            ;;
    esac
done

# Validate required arguments
if [ -z "$mode" ]; then
    echo "Error: Mode is required"
    usage
fi

# Validate mode
if [ "$mode" != "poc" ] && [ "$mode" != "patch" ]; then
    echo "Error: Invalid mode '$mode'"
    echo "Valid modes are: poc, patch"
    exit 1
fi

# Validate numeric arguments
if ! [[ "$num_instances" =~ ^[0-9]+$ ]]; then
    echo "Error: Number of instances must be a positive integer"
    exit 1
fi

if ! [[ "$max_iterations" =~ ^[0-9]+$ ]]; then
    echo "Error: Max iterations must be a positive integer"
    exit 1
fi

if ! [[ "$num_workers" =~ ^[0-9]+$ ]]; then
    echo "Error: Number of workers must be a positive integer"
    exit 1
fi

# Display configuration
echo "Running SEC-bench evaluation with:"
echo "  Mode: $mode"
echo "  LLM Profile: $llm_profile"
echo "  Number of instances: $num_instances"
echo "  Max iterations: $max_iterations"
echo "  Label: $label"
echo "  Number of workers: $num_workers"
echo "----------------------------------------"

# Execute based on the mode
case "$mode" in
    "patch")
        echo "Running patch mode..."
        ./evaluation/benchmarks/sec_bench/scripts/run_infer.sh $llm_profile HEAD CodeActAgent $num_instances $max_iterations $num_workers SEC-bench/SEC-bench $label 1.5 patch
        ;;
    "poc")
        echo "Running PoC mode..."
        ./evaluation/benchmarks/sec_bench/scripts/run_infer.sh $llm_profile HEAD CodeActAgent $num_instances $max_iterations $num_workers SEC-bench/SEC-bench $label 1.5 poc
        ;;
esac

echo "----------------------------------------"
echo "Completed $mode mode execution"
