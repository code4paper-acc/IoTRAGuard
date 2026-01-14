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
OUTPUT_DIR = os.path.abspath("./llm_output")

os.makedirs(VECTOR_STORE_BASE_DIR, exist_ok=True)
os.makedirs(OUTPUT_DIR, exist_ok=True)

def get_doc_cache_path(version: str) -> str:
    safe_version = version.replace('.', '_').replace('-', '_').replace('/', '_')
    return os.path.join(get_vector_store_dir(version), f"doc_cache_{safe_version}.pkl")

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

def format_code_examples(code_texts: List[str]) -> str:
    return "\n".join([f"--- Code Example {i+1} ---\n{c}\n" for i, c in enumerate(code_texts)])

def process_query(
    idx: int,
    query: Dict[str, Any],
    with_security: bool,
    model: LLMModel,
    filter_processor: Optional[Filter],
    k: int,
    output_path: str
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

        if all_vector_files_exist and cached_docs:
            print(f"[QuickCache] Hit cache for version {zephyr_version}.")
            print(f"[QuickCache] Loading vector store from {storage_dir}...")
            
            # Switch to vector store root directory
            os.chdir(vector_store_dir)
            
            # Initialize VectorStore
            vector_store = VectorStore(
                documents=cached_docs, 
                versions=[zephyr_version] * len(cached_docs)
            )
            
            if vector_store.load_vector(path='storage'):
                print(f"[QuickCache] Vector store loaded successfully.")
            else:
                print(f"[Error] Files exist but VectorStore failed to load. Preparing to rebuild...")
                cached_docs = None
        
        # Execute rebuild logic if cache is incomplete
        if not (all_vector_files_exist and cached_docs):
            print(f"[QuickCache] Functional knowledge base cache missing or incomplete. Rebuilding for version {zephyr_version}...")
            
            git_checkout_version(zephyr_version)
            
            os.chdir(vector_store_dir)
            
            code_docs = split_to_segmenmt(EXISTING_REPO_DIR, cover_content=50, version=zephyr_version)
            
            doc_contents = [d.content for d in code_docs]
            all_versions = [d.version for d in code_docs]
            
            vector_store = VectorStore(documents=doc_contents, versions=all_versions)
            vector_store.get_vector(SFRCodeEmbedding())
            
            vector_store.persist(path='storage')
            
            save_doc_cache(doc_cache_path, doc_contents)
            print(f"[QuickCache] Rebuild complete. Data saved to {storage_dir}")

        code_text_contents = vector_store.query(
            query=user_question,
            embedding_model=SFRCodeEmbedding(),
            k=k,
            target_version=zephyr_version
        )
        
    finally:
        os.chdir(original_cwd)

    security_knowledge = []
    if with_security and filter_processor:
        try:
            sub_tasks = model.decompose_query(user_question,format_code_examples(code_text_contents))
            security_result = filter_processor.process_single_query(query=query, sub_tasks=sub_tasks)
            security_knowledge = security_result.get("sub_task", [])
        except Exception as e:
            print(f"Failed to acquire security knowledge: {e}")

    prompt_parts = [
        "You are an IoT code expert. Output a secure IoT application code based on the following repository version and requirements.",
        json.dumps({"zephyr_version": zephyr_version, "user's requirement": user_question}, ensure_ascii=False)
    ]
    
    if with_security and security_knowledge:
        prompt_parts.append("\n[Instruction] Before generating code for the specified repository version, review relevant security guidance to avoid triggering vulnerabilities in the underlying libraries via the public API. If avoidance is not possible, provide a security warning(e.g., The current repository has an XXX vulnerability. Please update to version XXX or later.).")
        for i, sub_task in enumerate(security_knowledge, 1):
            # --- Full field extraction logic start ---
            desc = sub_task.get('Description', 'N/A')
            api = sub_task.get('PublicAPI', 'N/A')
            headers = sub_task.get('HeaderFile', 'N/A')
            
            prompt_parts.append(f"### Sub-Task {i}: {desc}")
            if api and api != 'N/A':
                prompt_parts.append(f"   - **Suggested PublicAPIs**: {api}")
            if headers and headers != 'N/A':
                prompt_parts.append(f"   - **Required Headers**: {headers}")
            
            # Inject relevant security knowledge
            for sk in sub_task.get("Security Knowledge", []):
                prompt_parts.append(f"   - [Security Constraint] [{sk['CWE']}] {sk['Description']}")

    prompt_parts.append(f"\n# Reference Code Examples:")
    for i, content in enumerate(code_text_contents, 1):
        prompt_parts.append(f"## Example {i}:\n{content}\n")
            # --- Full field extraction logic end ---

    final_prompt = "\n".join(prompt_parts)
    
    # 4. Call LLM to generate final code
    print(f"Getting final response for Problem {idx}...")
    print(f"Final Prompt:\n{final_prompt}\n")
    response = model.chat(user_question, [], final_prompt)
    print(f"LLM Response:\n{response}\n")
    
    # 5. Append result to file
    try:
        with open(output_path, "a", encoding="utf-8") as f:
            f.write(f"\n\n{'='*80}\n")
            f.write(f" PROBLEM {idx} DETAILS \n")
            f.write(f"{'='*80}\n")
            f.write(f"Zephyr Version: {zephyr_version}\n")
            f.write(f"User Problem: {user_question}\n")
            f.write(f"{'-'*40} LLM OUTPUT {'-'*40}\n")
            f.write(str(response))
            f.write(f"\n{'='*80}\n")
        print(f"[Success] Problem {idx} processed and saved.")
    except Exception as e:
        print(f"[Error] Failed to write file: {e}")

if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(description="IoT RAG Guard Runner")
    parser.add_argument("input_json", help="Path to input query JSON")
    parser.add_argument("--with-sec", action="store_true", help="Enable security enhancement")
    parser.add_argument("--model", type=str, default="gpt-4o", 
                        choices=["gpt-4o", "deepseek-v3", "codellama:13b", "deepseek-coder-v2:16b","qwen2.5-coder:14b"],
                        help="Select model")
    parser.add_argument("-k", type=int, default=3, help="Number of functional code items")
    parser.add_argument("-m", type=int, default=2, help="Number of knowledge items")
    parser.add_argument("-n", type=int, default=2, help="Number of sub-tasks")
    
    args = parser.parse_args()

    # 1. Determine unified output path
    json_base_name = os.path.splitext(os.path.basename(args.input_json))[0]
    mode_suffix = "sec" if args.with_sec else "ori"
    output_filename = f"{json_base_name}_{args.model}_{mode_suffix}.txt"
    final_output_path = os.path.join(OUTPUT_DIR, output_filename)

    # 2. Reset file if exists (write header)
    with open(final_output_path, "w", encoding="utf-8") as f:
        f.write(f"BATCH PROCESS LOG\n")
        f.write(f"Date: {datetime.now()}\n")
        f.write(f"Input File: {args.input_json}\n")
        f.write(f"Model: {args.model}\n")
        f.write(f"Security Mode: {'Enabled' if args.with_sec else 'Disabled'}\n")
        f.write(f"{'#'*80}\n")

    # Load queries
    try:
        with open(args.input_json, 'r', encoding='utf-8') as f:
            user_queries = json.load(f)
    except Exception as e:
        print(f"Failed to read input file: {e}"); sys.exit(1)

    model_processor = LLMModel(model=args.model)
    filter_processor = None
    if args.with_sec:
        filter_processor = Filter(sec_path=SECURITYKNOWLEDGEBASE_DIR, m=args.m, n=args.n)

    # 3. Loop append
    for idx, query in enumerate(user_queries, 1):
        print(f"\n>>> Processing Problem {idx}/{len(user_queries)}...")
        try:
            process_query(
                idx=idx,
                query=query,
                with_security=args.with_sec,
                model=model_processor,
                filter_processor=filter_processor,
                k=args.k,
                output_path=final_output_path
            )
        except Exception as e:
            print(f"Error processing Problem {idx}: {e}")

    print(f"\nAll tasks completed. See combined results at: {final_output_path}")