#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import json
import re
from typing import List, Dict, Any, Optional
from llm import LLMModel
from vector_base import VectorStore
from chunker_json import JsonChunker
from embeddings import SFRCodeEmbedding
from rerank import Reranker

INDEX_TEXT_SEPARATOR = "|||"


class Filter:
    def __init__(self, queries_path: str, vuln_path: str, llm_model_name: str, m: int = 3, n: int = 5):
        """
        Initialize Filter class (adapted to new CodeGuarder.json format).

        Args:
            queries_path: Path to the query file.
            vuln_path: Path to the vulnerability database file.
            llm_model_name: Name of the LLM used for task decomposition (e.g., "gpt-4o", "deepseek-v3").
            m: Number of retrieval candidates.
            n: Number of top sub-tasks to retain.
        """
        self.queries_path = queries_path
        self.vuln_path = vuln_path
        self.m = m
        self.n = n

        print(f"[Info] Initializing task decomposition model: {llm_model_name}")
        self.model = LLMModel(model=llm_model_name)

        self.vuln_chunker = JsonChunker(vuln_path)
        self.chunker_instance_id = id(self.vuln_chunker)

        self.reranker = Reranker()
        self.vuln_vector_store = self._init_vuln_vector_store()

    def _init_vuln_vector_store(self) -> VectorStore:
        """Initialize global vulnerability vector store (rebuild chunker mapping after loading cache)."""
        cache_dir = "sec_vector_cache"
        os.makedirs(cache_dir, exist_ok=True)
        cache_path = os.path.join(cache_dir, "CodeGuarder")

        if os.path.exists(cache_path):
            print(f"[Info] Vulnerability vector store cache found, attempting to load...")
            vector_store = VectorStore()
            if vector_store.load_vector(cache_path):
                print(f"[Info] Cache loaded successfully (Documents: {len(vector_store.documents)})")
                self.vuln_chunker.get_embed_data_for_vectorstore()
                print(f"[Info] Chunker metadata mapping rebuilt (Vulnerabilities: {len(self.vuln_chunker.index_to_full_metadata)})")
                return vector_store
            else:
                print(f"[Warning] Cache exists but failed to load, regenerating vector store")

        print(f"[Info] No valid cache, generating vulnerability vector store...")
        
        embed_texts, versions, indices = self.vuln_chunker.get_embed_data_for_vectorstore()

        if not embed_texts:
            raise ValueError("No valid vulnerability data extracted (missing core field: Functionality)")

        vector_documents = [f"{idx}{INDEX_TEXT_SEPARATOR}{text}" for idx, text in zip(indices, embed_texts)]
        print(f"[Info] Generated {len(vector_documents)} vector store documents")

        vector_store = VectorStore(documents=vector_documents, versions=versions)
        embedding_model = SFRCodeEmbedding()
        vectors = self._generate_pure_functionality_embeddings(embedding_model, embed_texts)
        vector_store.vectors = vectors

        vector_store.persist(cache_path)
        print(f"[Info] Vector store generation complete and cached at: {cache_path}")
        return vector_store

    def _generate_pure_functionality_embeddings(self, model: SFRCodeEmbedding, texts: List[str]) -> List[List[float]]:
        """Generate embeddings using pure Functionality text (batch processing)."""
        vectors = []
        batch_size = 128
        print(f"[Info] Starting embedding generation (Texts: {len(texts)}, Batch size: {batch_size})")

        if hasattr(model, 'get_embeddings'):
            for i in range(0, len(texts), batch_size):
                batch_texts = texts[i:i + batch_size]
                vectors.extend(model.get_embeddings(batch_texts))
        else:
            model_name = getattr(model, 'default_model', "SFR-Embedding-Code-400M_R")
            for text in texts:
                vectors.append(model.get_embedding(text, model=model_name))

        print(f"[Info] Embedding generation complete (Vectors: {len(vectors)})")
        return vectors

    def load_queries(self) -> List[Dict[str, str]]:
        """Load query data from queries.json."""
        print(f"\n[Info] Loading query file: {self.queries_path}")
        if not os.path.exists(self.queries_path):
            raise FileNotFoundError(f"Query file not found: {self.queries_path}")

        with open(self.queries_path, 'r', encoding='utf-8') as f:
            queries = json.load(f)

        if not isinstance(queries, list):
            raise ValueError("queries.json must be in array format")

        print(f"[Info] Successfully loaded {len(queries)} queries")
        return queries

    def _parse_index_from_vector_doc(self, vector_doc: str) -> Optional[int]:
        """Parse original index from vector store document."""
        if not vector_doc or INDEX_TEXT_SEPARATOR not in vector_doc:
            print(f"[Warning] Invalid vector document format: {vector_doc[:50]}...")
            return None
        try:
            idx_str, _ = vector_doc.split(INDEX_TEXT_SEPARATOR, 1)
            return int(idx_str)
        except ValueError:
            print(f"[Warning] Unable to parse index from document: {vector_doc[:50]}...")
            return None

    def _format_vuln_for_rerank(self, full_vuln: Dict[str, Any]) -> str:
        """Convert new metadata format to plain text string (adapted to CodeGuarder.json)."""
        root_cause = full_vuln.get('Root_Cause', [])
        root_cause_text = "\n".join(root_cause) if isinstance(root_cause, list) else str(root_cause)

        fixing_pattern = full_vuln.get('Fixing_Pattern', [])
        fixing_pattern_text = "\n".join(fixing_pattern) if isinstance(fixing_pattern, list) else str(fixing_pattern)

        sections = [
            f"Functionality: {full_vuln.get('Functionality', 'No description')}",
            f"Root Cause: {root_cause_text}",
            f"Fixing Pattern: {fixing_pattern_text}",
            f"CVE ID: {full_vuln.get('cve_id', 'UNKNOWN')}",
            f"CWE ID: {full_vuln.get('cwe_id', 'UNKNOWN')}",
            f"Vulnerable Version: {full_vuln.get('vulnerable_version', 'Unknown')}"
        ]
        return "\n".join(sections)

    def extract_cwe_from_vuln(self, vuln_content: str) -> str:
        """Extract CWE information from new metadata format."""
        cwe_pattern = re.compile(r"CWE ID: (.*?)(?:\n|$)")
        match = cwe_pattern.search(vuln_content)
        if match:
            cwe_text = match.group(1).strip()
            if cwe_text and cwe_text != 'UNKNOWN':
                first_cwe = cwe_text.split(",")[0].strip()
                if not first_cwe.startswith("CWE-"):
                    first_cwe = f"CWE-{first_cwe}"
                return first_cwe
        return "Unknown"

    def process_single_query(self, query: Dict[str, str]) -> Dict[str, Any]:
        """Process single query with new metadata format."""
        zephyr_version = None
        print(f"\n[Info] Processing query - Zephyr Version: {zephyr_version}")
        problem = query["problem"]

        print(f"\n{'=' * 60}")
        print(f"Processing query - Zephyr Version: {zephyr_version}")
        print(f"Query content: {problem[:80]}...")
        print(f"{'=' * 60}")

        print(f"\n[Info] Starting query decomposition...")
        
        sub_tasks = self.model.decompose_query(problem)
        print(f"[Info] Query decomposition complete, obtained {len(sub_tasks)} sub-tasks")

        task_results = []
        for i, task in enumerate(sub_tasks, 1):
            task_desc = task["Description"]
            print(f"\n{'-' * 50}")
            print(f"Sub-task {i}/{len(sub_tasks)}: {task_desc}")

            print(f"[Info] Retrieving from vulnerability vector store (k={self.m})...")
            raw_vector_docs = self.vuln_vector_store.query(
                query=task_desc,
                embedding_model=SFRCodeEmbedding(),
                k=self.m,
                target_version=zephyr_version
            )
            print(f"[Info] Retrieval complete, returned {len(raw_vector_docs)} matches")

            vuln_texts_for_rerank = []
            full_vuln_map = {}
            for vector_doc in raw_vector_docs:
                idx = self._parse_index_from_vector_doc(vector_doc)
                if idx is None:
                    continue

                full_vuln = self.vuln_chunker.get_full_metadata_by_index(idx)
                if not full_vuln:
                    print(f"[Warning] No metadata found for index {idx}, skipping")
                    continue

                vuln_text = self._format_vuln_for_rerank(full_vuln)
                vuln_texts_for_rerank.append(vuln_text)
                full_vuln_map[vuln_text] = full_vuln

            if not vuln_texts_for_rerank:
                print(f"[Info] No matching vulnerabilities for this sub-task")
                continue

            print(f"[Info] Reranking vulnerabilities (Valid texts: {len(vuln_texts_for_rerank)})")
            ranked_vulns, total_score = self.reranker.rerank_with_sum(vuln_texts_for_rerank, top_n=self.m)

            formatted_vulns = []
            for vuln in ranked_vulns:
                vuln_content = vuln["content"]
                cwe_str = self.extract_cwe_from_vuln(vuln_content)
                full_vuln = full_vuln_map.get(vuln_content, {})

                root_cause = full_vuln.get('Root_Cause', [])
                root_cause_formatted = "\n  - " + "\n  - ".join(root_cause) if isinstance(root_cause, list) else root_cause

                fixing_pattern = full_vuln.get('Fixing_Pattern', [])
                fixing_pattern_formatted = "\n  - " + "\n  - ".join(fixing_pattern) if isinstance(fixing_pattern, list) else fixing_pattern

                formatted_desc = f"""Functionality: {full_vuln.get('Functionality', 'No description')}
Root Cause:{root_cause_formatted}
Fixing Pattern:{fixing_pattern_formatted}
"""
                formatted_vulns.append({
                    "CWE": cwe_str,
                    "Description": formatted_desc
                })

            task_results.append({
                "Description": task_desc,
                "Security Knowledge": formatted_vulns,
                "total_score": total_score
            })

        task_results_sorted = sorted(task_results, key=lambda x: x["total_score"], reverse=True)[:self.n]
        for task in task_results_sorted:
            task.pop("total_score", None)

        print(f"\n[Info] Query processing complete, returning Top-{self.n} sub-task results")
        return {
            "zephyr_version": zephyr_version,
            "problem": problem,
            "sub_task": task_results_sorted
        }

    def run(self, output_path: str):
        """Execute entire filtering process with new metadata format."""
        print("=" * 70)
        print("Starting Filter process execution (adapted to CodeGuarder.json format)")
        print("=" * 70)

        try:
            queries = self.load_queries()
        except Exception as e:
            print(f"[Error] Failed to load queries: {str(e)}")
            return

        results = []
        for idx, query in enumerate(queries, 1):
            print(f"\n{'=' * 60}")
            print(f"Processing query {idx}/{len(queries)}")
            print(f"{'=' * 60}")
            try:
                result = self.process_single_query(query)
                results.append(result)
            except Exception as e:
                print(f"[Error] Error processing query {idx}: {str(e)}")
                import traceback
                traceback.print_exc()
                continue

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)

        print(f"\n" + "=" * 70)
        print(f"All queries processed, results saved to: {output_path}")
        print("=" * 70)