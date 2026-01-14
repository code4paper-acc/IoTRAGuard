#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import pickle
import json
import subprocess
import argparse
from typing import List, Dict, Any, Optional
from datetime import datetime

from llm import LLMModel
from vector_base import VectorStore
from chunker_code import split_to_segmenmt
from embeddings import SFRCodeEmbedding
from Filter import Filter 

SECURITYKNOWLEDGEBASE_DIR = "./IoTRAGuard.json"
EXISTING_REPO_DIR = "../zephyr"
VECTOR_STORE_BASE_DIR = os.path.abspath("./vector_stores")
EVAL_OUTPUT_DIR = os.path.abspath("./llm_eval") 

os.makedirs(VECTOR_STORE_BASE_DIR, exist_ok=True)
os.makedirs(EVAL_OUTPUT_DIR, exist_ok=True)

def get_doc_cache_path(version: str) -> str:
    safe_version = version.replace('.', '_').replace('-', '_').replace('/', '_')
    return os.path.join(get_vector_store_dir(version), f"doc_cache_{safe_version}.pkl")

def get_vector_store_dir(version: str) -> str:
    safe_version = version.replace('.', '_').replace('-', '_').replace('/', '_')
    return os.path.join(VECTOR_STORE_BASE_DIR, f"vector_store_{safe_version}")

def git_checkout_version(version: str) -> None:
    try:
        subprocess.run(["git", "fetch", "--all", "--tags"], cwd=EXISTING_REPO_DIR, check=True, capture_output=True)
        subprocess.run(["git", "checkout", version], cwd=EXISTING_REPO_DIR, check=True, capture_output=True)
        subprocess.run(["git", "clean", "-fd"], cwd=EXISTING_REPO_DIR, check=True, capture_output=True)
    except subprocess.CalledProcessError as e:
        raise Exception(f"Git switch failed: {e.stderr.decode()}")

def load_doc_cache(cache_path: str):
    if os.path.exists(cache_path):
        with open(cache_path, 'rb') as f:
            data = pickle.load(f)
            return data[0] if isinstance(data, tuple) else data
    return None

def save_doc_cache(cache_path: str, doc_contents: List[str]):
    with open(cache_path, 'wb') as f:
        pickle.dump((doc_contents, "STABLE"), f)

def format_code_examples(code_texts: List[str]) -> str:
    return "\n".join([f"--- Code Example {i+1} ---\n{c}\n" for i, c in enumerate(code_texts)])

def process_query(
    idx: int,
    query: Dict[str, Any],
    with_vulnerability: bool,
    model: LLMModel,
    filter_processor: Optional[Filter],
    k: int,
    eval_log_path: str,
    target_check_string: str
):
    """Process a single query: Retrieve -> Security Match -> Hit Detection"""
    zephyr_version = query.get("zephyr_version", "main")
    user_question = query.get("problem", "")

    vector_store_dir = os.path.abspath(get_vector_store_dir(zephyr_version))
    doc_cache_path = os.path.abspath(get_doc_cache_path(zephyr_version))
    storage_dir = os.path.join(vector_store_dir, "storage")
    
    os.makedirs(vector_store_dir, exist_ok=True)

    original_cwd = os.getcwd()
    try:
        required_files = ["documents.json", "versions.json", "vectors.npy"]
        all_vector_files_exist = all(
            os.path.exists(os.path.join(storage_dir, f)) for f in required_files
        )
        cached_docs = load_doc_cache(doc_cache_path)

        if all_vector_files_exist and cached_docs:
            os.chdir(vector_store_dir)
            vector_store = VectorStore(documents=cached_docs, versions=[zephyr_version] * len(cached_docs))
            if not vector_store.load_vector(path='storage'):
                cached_docs = None 
        
        if not (all_vector_files_exist and cached_docs):
            print(f"[QuickCache] Rebuilding version {zephyr_version}")
            git_checkout_version(zephyr_version)
            os.chdir(vector_store_dir)
            code_docs = split_to_segmenmt(EXISTING_REPO_DIR, cover_content=50, version=zephyr_version)
            doc_contents = [d.content for d in code_docs]
            all_versions = [d.version for d in code_docs]
            vector_store = VectorStore(documents=doc_contents, versions=all_versions)
            vector_store.get_vector(SFRCodeEmbedding())
            vector_store.persist(path='storage')
            save_doc_cache(doc_cache_path, doc_contents)

        code_text_contents = vector_store.query(
            query=user_question, embedding_model=SFRCodeEmbedding(), k=k, target_version=zephyr_version
        )
        
    finally:
        os.chdir(original_cwd)

    security_knowledge = []
    if with_vulnerability and filter_processor:
        try:
            sub_tasks = model.decompose_query(user_question, format_code_examples(code_text_contents))
            security_result = filter_processor.process_single_query(query=query, sub_tasks=sub_tasks)
            security_knowledge = security_result.get("sub_task", [])
        except Exception as e:
            print(f"Failed to acquire security knowledge: {e}")

    is_hit = 0
    if security_knowledge and target_check_string:
        for task in security_knowledge:
            if target_check_string in task.get("Description", ""):
                is_hit = 1
                break
            for sk in task.get("Security Knowledge", []):
                if target_check_string in sk.get("Description", ""):
                    is_hit = 1
                    break
            if is_hit == 1:
                break
    
    print(f"Problem{idx} :{is_hit}")

    with open(eval_log_path, "a", encoding="utf-8") as f_eval:
        f_eval.write(f"Problem{idx} :{is_hit}\n")

if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(description="IoT RAG Retrieval Tester")
    parser.add_argument("input_json", help="Path to input query JSON")
    parser.add_argument("--with-vuln", action="store_true", help="Enable security enhancement")
    parser.add_argument("--model", type=str, default="gpt-4o", help="Select model")
    parser.add_argument("-k", type=int, default=3, help="Number of functional code items")
    parser.add_argument("-m", type=int, default=1, help="Number of knowledge items")
    parser.add_argument("-n", type=int, default=2, help="Number of sub-tasks")
    parser.add_argument("--target-string", type=str, required=True, help="Target security knowledge sentence to detect")
    
    args = parser.parse_args()

    json_base_name = os.path.splitext(os.path.basename(args.input_json))[0]
    mode_suffix = "vul" if args.with_vuln else "ori"
    
    eval_filename = f"{json_base_name}_{args.model}_{mode_suffix}_EVAL.txt"
    final_eval_path = os.path.join(EVAL_OUTPUT_DIR, eval_filename)

    with open(final_eval_path, "w", encoding="utf-8") as f:
        f.write(f"EVALUATION RESULTS\n")
        f.write(f"Date: {datetime.now()}\n")
        f.write(f"Target String: {args.target_string[:50]}...\n")
        f.write(f"{'-'*40}\n")

    try:
        with open(args.input_json, 'r', encoding='utf-8') as f:
            user_queries = json.load(f)
    except Exception as e:
        print(f"Failed to read input file: {e}"); sys.exit(1)

    model_processor = LLMModel(model=args.model)
    filter_processor = None
    if args.with_vuln:
        filter_processor = Filter(vuln_path=SECURITYKNOWLEDGEBASE_DIR, m=args.m, n=args.n)

    for idx, query in enumerate(user_queries, 1):
        try:
            process_query(
                idx=idx,
                query=query,
                with_vulnerability=args.with_vuln,
                model=model_processor,
                filter_processor=filter_processor,
                k=args.k,
                eval_log_path=final_eval_path,
                target_check_string=args.target_string
            )
        except Exception as e:
            print(f"Error processing item {idx}: {e}")
            print(f"Problem{idx} :0")
            with open(final_eval_path, "a", encoding="utf-8") as f_eval:
                f_eval.write(f"Problem{idx} :0 (Error)\n")

    print(f"\nDetection complete. See statistics at: {final_eval_path}")