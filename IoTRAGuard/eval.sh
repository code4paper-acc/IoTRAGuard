#!/bin/bash

QUERY_DIR="../query"
GROUND_TRUTH="../Retrieval_eval/ground_truth.csv"
SCRIPT_PATH="./eval.py"
OUTPUT_CSV="final_retrieval_results.csv"

MODELS=("gpt-4o" "deepseek-v3" "deepseek-coder-v2:16b" "qwen2.5-coder:14b")

echo "CVE_ID,Model,Problem,Hit" > "$OUTPUT_CSV"

if [ ! -f "$GROUND_TRUTH" ]; then
    echo "Error: Ground truth file not found at $GROUND_TRUTH"
    exit 1
fi

if [ ! -f "$SCRIPT_PATH" ]; then
    echo "Error: Python script not found at $SCRIPT_PATH"
    exit 1
fi

echo "Start processing queries from $QUERY_DIR..."

for json_file in "$QUERY_DIR"/*.json; do
    
    filename=$(basename "$json_file")
    
    cve_id="${filename%.*}"
    
    target_string=$(grep "^${cve_id}," "$GROUND_TRUTH" | cut -d',' -f2-)
    
    if [ -z "$target_string" ]; then
        echo "[WARN] Skipping $cve_id: No target string found in ground_truth.csv"
        continue
    fi
    
    target_string=$(echo "$target_string" | tr -d '\r')

    for model in "${MODELS[@]}"; do
        echo "Running evaluation for $cve_id with model: $model..."
        
        log_file="run_eval.log"

        output=$(python "$SCRIPT_PATH" "$json_file" \
            --with-vuln \
            --target-string "$target_string" \
            --model "$model" 2>&1 | tee -a "$log_file")
        
        while read -r line; do
            if [[ "$line" =~ Problem([0-9]+)\ :([0-1]) ]]; then
                problem_num="${BASH_REMATCH[1]}"
                is_hit="${BASH_REMATCH[2]}"
                echo "${cve_id},${model},Problem${problem_num},${is_hit}" >> "$OUTPUT_CSV"
            fi
        done <<< "$output"
    done

done

echo "========================================"
echo "Evaluation complete. Results saved to: $OUTPUT_CSV"