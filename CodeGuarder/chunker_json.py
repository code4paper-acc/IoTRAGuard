#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import json
from typing import List, Dict, Any, Tuple, Optional

class JsonChunker:
    """
    Chunker for vulnerability JSON files (supports index mapping).
    - Adapts to CodeGuarder.json format.
    - Maintains Functionality index mapping logic.
    - Retains vulnerable_version field and sets it to Unknown.
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
                
                if isinstance(data, dict):
                    data = [data]
                elif not isinstance(data, list):
                    raise ValueError("Vulnerability JSON must be an object or array")
                return data
            except json.JSONDecodeError as e:
                raise ValueError(f"JSON parse error: {str(e)}")

    def get_embed_data_for_vectorstore(self) -> Tuple[List[str], List[str], List[int]]:
        """
        Generate data required for vector store (core of index mapping).
        :return: (embed_texts, versions, indices)
            - embed_texts: Text used for embedding only (Functionality only)
            - versions: Version metadata for each vulnerability (unified as Unknown)
            - indices: Original index for each vulnerability (corresponds to index_to_full_metadata)
        """
        embed_texts = []  
        versions = []     
        indices = []      
        self.index_to_full_metadata.clear()  

        for idx, vuln in enumerate(self.vulnerabilities):
            
            if 'Functionality' not in vuln:
                continue  

            func_purpose = vuln.get('Functionality', 'No description')
            embed_texts.append(func_purpose)

            versions.append("Unknown")

            indices.append(idx)

            self.index_to_full_metadata[idx] = self._format_full_metadata(vuln)

        return embed_texts, versions, indices

    @staticmethod
    def _format_full_metadata(vuln: Dict[str, Any]) -> Dict[str, Any]:
        """
        Structure full metadata (adapted to CodeGuarder.json format).
        Includes all required fields: Functionality, Root_Cause, Fixing_Pattern, cve_id, cwe_id, etc.
        """
        return {
            "Functionality": vuln.get('Functionality', 'No description'),
            "Root_Cause": vuln.get('Root_Cause', []),
            "Fixing_Pattern": vuln.get('Fixing_Pattern', []),
            "cve_id": vuln.get('cve_id', 'UNKNOWN'),
            "cwe_id": vuln.get('cwe_id', 'UNKNOWN'),
            "vulnerable_version": "Unknown"  
        }

    def get_full_metadata_by_index(self, index: int) -> Optional[Dict[str, Any]]:
        """Get full metadata by index."""
        metadata = self.index_to_full_metadata.get(index)
        if metadata is None:
            print(f"[Warning] No full metadata found for index {index}. Valid indices: {list(self.index_to_full_metadata.keys())}")
        return metadata