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

SECURITYKNOWLEDGEBASE_DIR = "./CodeGuarder.json"
FILTER_TEMP_RESULT = "temp_filter_result.json"
EXISTING_REPO_DIR = "../zephyr"
VECTOR_STORE_BASE_DIR = os.path.abspath("./vector_stores")
OUTPUT_DIR = os.path.abspath("./llm_output")

os.makedirs(VECTOR_STORE_BASE_DIR, exist_ok=True)
os.makedirs(OUTPUT_DIR, exist_ok=True)

def get_doc_cache_path(version: str) -> str:
    safe_version = version.replace('.', '_').replace('-', '_').replace('/', '_')
    return os.path.join(get_vector_store_dir(version), f"doc_cache_version_{safe_version}.pkl")

def get_vector_store_dir(version: str) -> str:
    safe_version = version.replace('.', '_').replace('-', '_').replace('/', '_')
    return os.path.join(VECTOR_STORE_BASE_DIR, f"vector_store_{safe_version}")

def git_checkout_version(version: str) -> None:
    print(f"[Git] Switching to version: {version}")
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

def process_query(
    idx: int,
    query: Dict[str, Any],
    with_security: bool,
    model: LLMModel,
    filter_results: List[Dict[str, Any]],
    k: int,
    final_output_path: str
):
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

        if all_vector_files_exist and cached_docs is not None:
            print(f"[QuickCache] Hit cache for version {zephyr_version}, loading directly...")
            os.chdir(vector_store_dir)
            vector_store = VectorStore(documents=cached_docs, versions=[zephyr_version]*len(cached_docs))
            vector_store.load_vector(path='storage')
        else:
            print(f"[QuickCache] Cache invalid or incomplete, rebuilding vector store for version {zephyr_version}...")
            
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
    if with_security and filter_results:
        for item in filter_results:
            if item["problem"] == user_question:
                security_knowledge = item["sub_task"]
                break

    prompt_parts = [
        "You are an IoT code expert. Output a secure IoT application code based on the following repository version and requirements.",
        json.dumps({"zephyr_version": zephyr_version, "user's requirement": user_question}, ensure_ascii=False)
    ]

    if with_security and security_knowledge:
        prompt_parts.append("\nBefore generating code for the specified repository version, review relevant security guidance to avoid triggering vulnerabilities in the underlying libraries via the public API. If avoidance is not possible, provide a security warning.")
        for i, sub_task in enumerate(security_knowledge, 1):
            prompt_parts.append(f"Sub-Task {i}: {sub_task['Description']}")
            for sk in sub_task["Security Knowledge"]:
                prompt_parts.append(f"- CWE: {sk['CWE']}\n  Description: {sk['Description']}")

    prompt_parts.append("\n# Reference Code Examples:")
    for i, content in enumerate(code_text_contents, 1):
        prompt_parts.append(f"--- Code Example {i} ---\n{content}\n")

    final_prompt = "\n".join(prompt_parts)
    print(f"Final_prompt: {final_prompt}")

    print(f"Getting LLM response for Problem {idx}...")
    response = model.chat(user_question, [], final_prompt)
    print(f"LLM Output: {response}")

    try:
        with open(final_output_path, "a", encoding="utf-8") as f:
            f.write(f"\n\n{'='*80}\n")
            f.write(f" PROBLEM {idx} DETAILS \n")
            f.write(f"{'='*80}\n")
            f.write(f"Zephyr Version: {zephyr_version}\n")
            f.write(f"Problem Content: {user_question}\n")
            f.write(f"{'-'*40} LLM OUTPUT {'-'*40}\n")
            f.write(str(response))
            f.write(f"\n{'='*80}\n")
        print(f"Problem {idx} results saved.")
    except Exception as e:
        print(f"Failed to write file: {e}")

if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(description="IoT RAG Guard Runner")
    parser.add_argument("input_json", help="Path to input query JSON")
    parser.add_argument("--with-sec", action="store_true", help="Enable security enhancement mode")
    parser.add_argument("--model", type=str, default="gpt-4o", 
                        choices=["gpt-4o", "deepseek-v3", "codellama:13b", "deepseek-coder-v2:16b","qwen2.5-coder:14b"],
                        help="Name of LLM model to call")
    parser.add_argument("-k", type=int, default=3, help="Number of retrieved code examples")
    parser.add_argument("-m", type=int, default=2, help="Filter: Number of knowledge items matched per sub-task")
    parser.add_argument("-n", type=int, default=2, help="Filter: Number of sub-tasks")

    args = parser.parse_args()

    json_base_name = os.path.splitext(os.path.basename(args.input_json))[0]
    mode_suffix = "sec" if args.with_sec else "ori"
    output_filename = f"{json_base_name}_{args.model}_{mode_suffix}.txt"
    final_output_path = os.path.join(OUTPUT_DIR, output_filename)

    with open(final_output_path, "w", encoding="utf-8") as f:
        f.write(f"IoT Code Generation Log | {datetime.now()}\n")
        f.write(f"Input: {args.input_json} | Model: {args.model}\n")
        f.write(f"{'#'*80}\n")

    with open(args.input_json, 'r', encoding='utf-8') as f:
        user_queries = json.load(f)

    model_inst = LLMModel(model=args.model)
    filter_results = []

    if args.with_sec:
        print(f"Initializing security filter (m={args.m}, n={args.n})...")
        try:
            filter_processor = Filter(
                queries_path=args.input_json,
                sec_path=SECURITYKNOWLEDGEBASE_DIR,
                llm_model_name=args.model,
                m=args.m,
                n=args.n
            )
            filter_processor.run(output_path=FILTER_TEMP_RESULT)
            if os.path.exists(FILTER_TEMP_RESULT):
                with open(FILTER_TEMP_RESULT, 'r', encoding='utf-8') as f:
                    filter_results = json.load(f)
        except Exception as e:
            print(f"Security preprocessing failed: {e}")
            args.with_sec = False

    for idx, query in enumerate(user_queries, 1):
        print(f"\n>>> Processing Progress: {idx}/{len(user_queries)}")
        try:
            process_query(idx, query, args.with_sec, model_inst, filter_results, args.k, final_output_path)
        except Exception as e:
            print(f"Processing failed: {e}")

    if os.path.exists(FILTER_TEMP_RESULT):
        os.remove(FILTER_TEMP_RESULT)

    print(f"\nTask complete. Results saved to: {final_output_path}")