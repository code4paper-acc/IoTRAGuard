#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import json
import argparse
from typing import List, Dict, Any
from datetime import datetime
from Filter import Filter 

SECURITYKNOWLEDGEBASE_DIR = "./CodeGuarder.json"
FILTER_TEMP_RESULT = "temp_filter_result_eval.json" # Temp storage for Filter results
EVAL_OUTPUT_DIR = os.path.abspath("./llm_eval") 

os.makedirs(EVAL_OUTPUT_DIR, exist_ok=True)

def process_hit_check(
    idx: int,
    user_question: str,
    security_knowledge: List[Dict[str, Any]],
    target_check_string: str,
    eval_log_path: str
):
    """
    Core hit detection logic: checks if the target string exists in the security knowledge retrieved by Filter.
    """
    is_hit = 0
    
    if security_knowledge and target_check_string:
        
        target = target_check_string.strip()
        
        for task in security_knowledge:
            
            if target in task.get("Description", ""):
                is_hit = 1
                break
                        
            for sk in task.get("Security Knowledge", []):
                if target in sk.get("Description", ""):
                    is_hit = 1
                    break
            
            if is_hit == 1:
                break
        
    print(f"Problem{idx} :{is_hit}")

    
    with open(eval_log_path, "a", encoding="utf-8") as f_eval:
        f_eval.write(f"Problem{idx} :{is_hit}\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="IoT RAG Security Retrieval Evaluator (Batch Mode)")
    parser.add_argument("input_json", help="Path to input query JSON")
    parser.add_argument("--with-vuln", action="store_true", help="Enable security enhancement")
    parser.add_argument("--model", type=str, default="gpt-4o", help="Select model")
    parser.add_argument("--target-string", type=str, required=True, help="Target security knowledge sentence to detect")
    parser.add_argument("-m", type=int, default=2, help="Filter: Number of knowledge items")
    parser.add_argument("-n", type=int, default=2, help="Filter: Number of sub-tasks")
    parser.add_argument("-k", type=int, default=3, help="[Ignored] Number of functional code items")

    args = parser.parse_args()
    json_base_name = os.path.splitext(os.path.basename(args.input_json))[0]
    mode_suffix = "vul" if args.with_vuln else "ori"
    
    eval_filename = f"{json_base_name}_{args.model}_{mode_suffix}_EVAL.txt"
    final_eval_path = os.path.join(EVAL_OUTPUT_DIR, eval_filename)

    with open(final_eval_path, "w", encoding="utf-8") as f:
        f.write(f"EVALUATION RESULTS (Batch Method)\n")
        f.write(f"Date: {datetime.now()}\n")
        f.write(f"Target String: {args.target_string}\n")
        f.write(f"{'-'*40}\n")

    try:
        with open(args.input_json, 'r', encoding='utf-8') as f:
            user_queries = json.load(f)
    except Exception as e:
        print(f"Failed to read input file: {e}"); sys.exit(1)
   
    filter_results_map = {}  

    if args.with_vuln:
        print(f"[Info] Running Filter Batch Process with model {args.model}...")
        try:
            
            filter_processor = Filter(
                queries_path=args.input_json,
                vuln_path=SECURITYKNOWLEDGEBASE_DIR,
                llm_model_name=args.model,
                m=args.m,
                n=args.n
            )
                        
            temp_output = f"{FILTER_TEMP_RESULT}_{json_base_name}.json"
            filter_processor.run(output_path=temp_output)
            
            
            if os.path.exists(temp_output):
                with open(temp_output, 'r', encoding='utf-8') as f:
                    batch_results = json.load(f)
                   
                    for item in batch_results:
                        filter_results_map[item.get("problem")] = item.get("sub_task", [])
                
                
                os.remove(temp_output)
            else:
                print("[Error] Filter finished but no output file generated.")

        except Exception as e:
            print(f"[Error] Filter batch process failed: {e}")
            

    
    for idx, query in enumerate(user_queries, 1):
        user_question = query.get("problem", "")
        
        
        security_knowledge = filter_results_map.get(user_question, [])

        try:
            process_hit_check(
                idx=idx,
                user_question=user_question,
                security_knowledge=security_knowledge,
                target_check_string=args.target_string,
                eval_log_path=final_eval_path
            )
        except Exception as e:
            print(f"Problem{idx} :0")
            with open(final_eval_path, "a", encoding="utf-8") as f_eval:
                f_eval.write(f"Problem{idx} :0 (Error: {str(e)})\n")

    print(f"\nDetection complete. See results at: {final_eval_path}")