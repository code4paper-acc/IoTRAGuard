#!/usr/bin/env python
# -*- coding: utf-8 -*-

from typing import List, Dict, Union, Tuple
import re

class Reranker:
    def __init__(self):
        
        self.cwe_mapping = {
            # NULL pointer (40.24% → 0.40)
            "391": ("NULL pointer", 0.40),
            "476": ("NULL pointer", 0.40),
            "690": ("NULL pointer", 0.40),
            # Buffer overflow (25.53% → 0.26)
            "120": ("Buffer overflow", 0.26),
            "121": ("Buffer overflow", 0.26),
            "122": ("Buffer overflow", 0.26),
            "628": ("Buffer overflow", 0.26),
            "676": ("Buffer overflow", 0.26),
            "680": ("Buffer overflow", 0.26),
            "787": ("Buffer overflow", 0.26),
            # Invalid pointer (10.42% → 0.10)
            "822": ("Invalid pointer", 0.10),
            "119": ("Invalid pointer", 0.10),
            # Array bounds violated (8.86% → 0.09)
            "125": ("Array bounds violated", 0.09),
            "129": ("Array bounds violated", 0.09),
            "131": ("Array bounds violated", 0.09),
            "193": ("Array bounds violated", 0.09),
            "788": ("Array bounds violated", 0.09),
            # Arithmetic overflow (6.21% → 0.06)
            "191": ("Arithmetic overflow", 0.06),
            "20": ("Arithmetic overflow", 0.06),
            "190": ("Arithmetic overflow", 0.06),
            "192": ("Arithmetic overflow", 0.06),
            "681": ("Arithmetic overflow", 0.06),
            # Resource mismanagement (5.03% → 0.05)
            "825": ("Resource mismanagement", 0.05),
            "401": ("Resource mismanagement", 0.05),
            "404": ("Resource mismanagement", 0.05),
            "459": ("Resource mismanagement", 0.05),
            # Division by zero (1.45% → 0.01)
            "369": ("Division by zero", 0.01),
            "691": ("Division by zero", 0.01)
        }
        self.default_weight = 0.01  
        self.cwe_pattern = re.compile(r"Related CWE: (.*?)(?:\n|$)")

    def get_cwe_weight(self, cwe: str) -> float:
        cwe_clean = cwe.strip()
        return self.cwe_mapping.get(cwe_clean, ("Others", self.default_weight))[1]

    def extract_related_cwes(self, chunked_text: str) -> List[str]:
        match = self.cwe_pattern.search(chunked_text)
        if not match:
            return []
        
        cwe_text = match.group(1).strip()
        cwe_strings = [cwe.strip() for cwe in cwe_text.split(",") if cwe.strip()]
        cleaned_cwes = []
        for cwe in cwe_strings:
            cleaned = cwe.replace("CWE-", "").strip()
            if cleaned.isdigit():
                cleaned_cwes.append(cleaned)
        return cleaned_cwes

    def process_chunked_entries(self, chunked_entries: List[str]) -> Tuple[List[Dict], float]:
        scored_entries = []
        
        for text in chunked_entries:
            cwes = self.extract_related_cwes(text)
            
            if cwes:
                weights = [self.get_cwe_weight(cwe) for cwe in cwes]
                weighted_score = max(weights)
            else:
                weighted_score = self.default_weight
            
            scored_entries.append({
                "content": text,
                "related_cwes": cwes,
                "weighted_score": weighted_score
            })
        
        scored_entries.sort(key=lambda x: -x["weighted_score"])
        total_weighted_sum = sum(entry["weighted_score"] for entry in scored_entries)
        
        return scored_entries, total_weighted_sum

    def rerank_with_sum(self, chunked_entries: List[str], top_n: int = 3) -> Tuple[List[Dict], float]:
        if not chunked_entries:
            return [], 0.0
            
        all_scored, total_sum = self.process_chunked_entries(chunked_entries)
        return all_scored[:top_n], total_sum