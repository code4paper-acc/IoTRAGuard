#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import json
from typing import List, Dict, Any, Tuple, Optional


class JsonChunker:
    """
    Chunker for vulnerability JSON files (supports index mapping).
    - Retains original chunking logic, adds support for 'Embedding Text + Index + Full Metadata'.
    - Maintains 'Index -> Full Metadata' mapping for retrieving complete information after search.
    """

    def __init__(self, json_path: str) -> None:
        self.json_path = os.path.expanduser(json_path)
        self.vulnerabilities = self._load_json()
        
        self.index_to_full_metadata: Dict[int, Dict[str, Any]] = {}

    def _load_json(self) -> List[Dict[str, Any]]:
        """Load and parse JSON file content."""
        if not os.path.exists(self.json_path):
            raise FileNotFoundError(f"Vulnerability file does not exist: {self.json_path}")
        
        with open(self.json_path, 'r', encoding='utf-8') as f:
            try:
                data = json.load(f)
                if not isinstance(data, list):
                    raise ValueError("Vulnerability JSON must be in array format")
                return data
            except json.JSONDecodeError as e:
                raise ValueError(f"JSON parse error: {str(e)}")

    def get_embed_data_for_vectorstore(self) -> Tuple[List[str], List[str], List[int]]:
        """
        Generate data required for vector store (core of index mapping).
        :return: (embed_texts, versions, indices)
            - embed_texts: Text used for embedding only (Function Functionality only)
            - versions: Version metadata for each vulnerability
            - indices: Original index for each vulnerability (corresponds to index_to_full_metadata)
        """
        embed_texts = []  
        versions = []     
        indices = []      
        self.index_to_full_metadata.clear()  

        for idx, vuln in enumerate(self.vulnerabilities):            
            required_keys = ['id', 'vulnerable_version', 'functionality']
            if not all(key in vuln for key in required_keys):
                continue              
            func_purpose = vuln.get('functionality', 'No purpose described')
            embed_texts.append(func_purpose)            
            version = vuln.get('vulnerable_version', 'Unknown')
            versions.append(version)            
            indices.append(idx)            
            self.index_to_full_metadata[idx] = self._format_full_metadata(vuln)

        return embed_texts, versions, indices

    @staticmethod
    def _format_full_metadata(vuln: Dict[str, Any]) -> Dict[str, Any]:
        """
        Structure full metadata (for passing to LLM).
        Includes all required fields: Functionality, Fixing Guideline, Code Snippet, etc.
        """
        return {
            "vulnerability_id": vuln.get('id', 'UNKNOWN'),
            "vulnerability_description": vuln.get('vulnerability', 'No description'),
            "affected_functions": vuln.get('affected_functions', []),
            "function_functionality": vuln.get('functionality', 'No purpose described'),
            "call_patterns": [
                {
                    "pattern": p.get('pattern', ''),
                    "description": p.get('description', '')
                } for p in vuln.get('call_patterns', [])
            ],
            "fixing_guideline": vuln.get('fixing_pattern', {}).get('guideline', ''),
            "fixing_code_snippet": vuln.get('fixing_pattern', {}).get('code_snippet', ''),
            "exploit_prerequisites": vuln.get('exploit_prereqs', []),
            "mitigations": vuln.get('mitigations', []),
            "related_cve": vuln.get('related_cve', []),
            "related_cwe": vuln.get('related_cwe', []),
            "vulnerable_version": vuln.get('vulnerable_version', 'UNKNOWN')
        }

    def get_full_metadata_by_index(self, index: int) -> Optional[Dict[str, Any]]:
        metadata = self.index_to_full_metadata.get(index)
        if metadata is None:
            print(f"[Warning] No full metadata found for index {index}. Valid indices: {list(self.index_to_full_metadata.keys())}")
        return metadata