#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import json
import re
from typing import List, Dict, Any, Optional
from vector_base import VectorStore
from chunker_json import JsonChunker
from embeddings import SFRCodeEmbedding
from rerank import Reranker

# Global constant: Separator for index and embedding text
INDEX_TEXT_SEPARATOR = "|||"

class Filter:
    def __init__(self, vuln_path: str, m: int = 1, n: int = 5):
        """Initialize Filter class (only responsible for handling decomposed sub-tasks)"""
        self.vuln_path = vuln_path
        self.m = m  # Number of results returned by vector retrieval
        self.n = n  # Number of final results to retain
        
        self.vuln_chunker = JsonChunker(vuln_path)
        self.reranker = Reranker()
        self.vuln_vector_store = self._init_vuln_vector_store()  # Pre-generate global vulnerability vector store

    def _init_vuln_vector_store(self) -> VectorStore:
        """Initialize global vulnerability vector store (rebuild chunker mapping after loading cache)"""
        cache_dir = "sec_vector_cache"
        os.makedirs(cache_dir, exist_ok=True)
        cache_path = os.path.join(cache_dir, "IoTRAGuard")

        # Check if cache exists
        if os.path.exists(cache_path):
            print(f"[Info] Security knowledge base cache found, attempting to load...")
            vector_store = VectorStore()
            if vector_store.load_vector(cache_path):
                print(f"[Info] Cache loaded successfully (Documents: {len(vector_store.documents)})")
                # Rebuild chunker index mapping
                self.vuln_chunker.get_embed_data_for_vectorstore()
                print(f"[Info] Chunker metadata mapping rebuild complete (Security knowledge items: {len(self.vuln_chunker.index_to_full_metadata)})")
                return vector_store
            else:
                print(f"[Warning] Cache exists but failed to load, regenerating security knowledge base")

        # Generate vector store when no cache or cache load fails
        print(f"[Info] No valid cache, starting generation of security knowledge base...")
        
        embed_texts, versions, indices = self.vuln_chunker.get_embed_data_for_vectorstore()
        
        if not embed_texts:
            raise ValueError("No valid vulnerability data extracted (missing core fields like functionality)")

        vector_documents = [f"{idx}{INDEX_TEXT_SEPARATOR}{text}" for idx, text in zip(indices, embed_texts)]
        print(f"[Info] Generated {len(vector_documents)} security knowledge items")

        vector_store = VectorStore(documents=vector_documents, versions=versions)
        embedding_model = SFRCodeEmbedding()
        vectors = self._generate_pure_functionality_embeddings(embedding_model, embed_texts)
        vector_store.vectors = vectors

        vector_store.persist(cache_path)
        print(f"[Info] Security knowledge base generation complete and cached to: {cache_path}")
        return vector_store

    def _generate_pure_functionality_embeddings(self, model: SFRCodeEmbedding, texts: List[str]) -> List[List[float]]:
        """Batch generate embedding vectors for pure functionality descriptions"""
        vectors = []
        batch_size = 128
        print(f"[Info] Starting embedding generation (Texts: {len(texts)}, Batch size: {batch_size})")
        
        if hasattr(model, 'get_embeddings'):
            for i in range(0, len(texts), batch_size):
                batch_texts = texts[i:i+batch_size]
                vectors.extend(model.get_embeddings(batch_texts))
        else:
            model_name = getattr(model, 'default_model', "SFR-Embedding-Code-400M_R")
            for text in texts:
                vectors.append(model.get_embedding(text, model=model_name))
        
        print(f"[Info] Security knowledge embedding generation complete (Vectors: {len(vectors)})")
        return vectors

    def _parse_index_from_vector_doc(self, vector_doc: str) -> Optional[int]:
        """Parse original index from vector store document"""
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
        """Convert full metadata to plain text for reranking"""
        sections = [
            f"Vulnerability ID: {full_vuln.get('vulnerability_id', 'UNKNOWN')}",
            f"Vulnerability Description: {full_vuln.get('vulnerability_description', 'No description')}",
            f"Affected Functions: {', '.join(map(str, full_vuln.get('affected_functions', [])))}",
            f"Function Functionality: {full_vuln.get('function_functionality', 'No purpose described')}",
            f"Dangerous Call Patterns: {json.dumps(full_vuln.get('call_patterns', []), ensure_ascii=False)}",
            f"Fixing Guideline: {full_vuln.get('fixing_guideline', 'No guideline')}",
            f"Fixing Code Snippet: {full_vuln.get('fixing_code_snippet', 'No code snippet')}",
            f"Exploit Prerequisites: {', '.join(full_vuln.get('exploit_prerequisites', []))}",
            f"Mitigations: {', '.join(full_vuln.get('mitigations', []))}",
            f"Related CVE: {', '.join(full_vuln.get('related_cve', []))}",
            f"Related CWE: {', '.join(map(str, full_vuln.get('related_cwe', [])))}",
            f"Vulnerable Version: {full_vuln.get('vulnerable_version', 'UNKNOWN')}"
        ]
        return "\n".join(sections)

    def extract_cwe_from_vuln(self, vuln_content: str) -> str:
        """Extract CWE information from vulnerability content"""
        cwe_pattern = re.compile(r"Related CWE: (.*?)(?:\n|$)")
        match = cwe_pattern.search(vuln_content)
        if match:
            cwe_text = match.group(1).strip()
            if cwe_text and cwe_text != 'UNKNOWN':
                # Extract first CWE ID
                first_cwe = cwe_text.split(",")[0].strip()
                # Ensure unified format as CWE-XXX
                if not first_cwe.startswith("CWE-"):
                    first_cwe = f"CWE-{first_cwe}"
                return first_cwe
        return "Unknown"

    def process_single_query(self, query: Dict[str, str], sub_tasks: List[Dict[str, str]]) -> Dict[str, Any]:
        """
        Process single query (receive decomposed sub-tasks)
        :param query: Query info (containing zephyr_version and problem)
        :param sub_tasks: List of decomposed sub-tasks
        """
        zephyr_version = query["zephyr_version"]
        problem = query["problem"]
        
        print(f"\n{'='*60}")
        print(f"Processing Query - Zephyr Version: {zephyr_version}")
        print(f"Query Content: {problem[:80]}...")
        print(f"{'='*60}")
        
        # Process each sub-task
        task_results = []
        for i, task in enumerate(sub_tasks, 1):
            task_desc = task["Description"]
            public_api = task.get("PublicAPI", "").strip()
            header_file = task.get("HeaderFile", "").strip()
            # Append description (only if field is not empty)
            if public_api:
                task_desc += f"\nPublic APIs: {public_api}"
            if header_file:
                task_desc += f"\nHeader files: {header_file}"
            print(f"\n{'-'*50}")
            print(f"Sub-task {i}/{len(sub_tasks)}: {task_desc}")
            
            # Vector store retrieval
            print(f"[Info] Retrieving from security knowledge base (k={self.m})...")
            
            raw_vector_docs = self.vuln_vector_store.query(
                query=task_desc,
                embedding_model=SFRCodeEmbedding(),
                k=self.m,
                target_version=zephyr_version
            )
            print(f"[Info] Retrieval complete, returned {len(raw_vector_docs)} matches")
            
            # Parse index + get metadata
            vuln_texts_for_rerank = []
            full_vuln_map = {}
            for vector_doc in raw_vector_docs:
                idx = self._parse_index_from_vector_doc(vector_doc)
                if idx is None:
                    continue
                
                # Get metadata
                full_vuln = self.vuln_chunker.get_full_metadata_by_index(idx)
                if not full_vuln:
                    print(f"[Warning] No metadata found for index {idx}, skipping")
                    continue
                
                # Format text for reranking
                vuln_text = self._format_vuln_for_rerank(full_vuln)
                vuln_texts_for_rerank.append(vuln_text)
                full_vuln_map[vuln_text] = full_vuln
            
            if not vuln_texts_for_rerank:
                print(f"[Info] No matching security knowledge for this sub-task")
                continue
            
            # Rerank
            print(f"[Info] Reranking security knowledge (Valid texts: {len(vuln_texts_for_rerank)})")
            ranked_vulns, total_score = self.reranker.rerank_with_sum(vuln_texts_for_rerank, top_n=self.m)
            
            # Format security knowledge
            formatted_vulns = []
            for vuln in ranked_vulns:
                vuln_content = vuln["content"]
                cwe_str = self.extract_cwe_from_vuln(vuln_content)
                full_vuln = full_vuln_map.get(vuln_content, {})
                formatted_desc = f"""
Exploit Prerequisites: {', '.join(full_vuln.get('exploit_prerequisites', []))}
Affected Public API: {', '.join(map(str, full_vuln.get('affected_functions', [])))}
Function Functionality: {full_vuln.get('function_functionality', '')}
Dangerous Call Patterns: {json.dumps(full_vuln.get('call_patterns', []), ensure_ascii=False, indent=1)}
Fixing Guideline: {full_vuln.get('fixing_guideline', 'No guideline')}
Fixing Code Snippet: {full_vuln.get('fixing_code_snippet', 'No code snippet')}
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
        
        # Sort and keep Top N sub-tasks
        task_results_sorted = sorted(task_results, key=lambda x: x["total_score"], reverse=True)[:self.n]
        for task in task_results_sorted:
            task.pop("total_score", None)
        
        print(f"\n[Info] Query processing complete, returning Top-{self.n} sub-task results")
        return {
            "zephyr_version": zephyr_version,
            "problem": problem,
            "sub_task": task_results_sorted
        }