#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
from typing import List, Optional
import json
from embeddings import BaseEmbeddings
import numpy as np
from tqdm import tqdm


class VectorStore:
    def __init__(self, documents: List[str] = None, versions: List[str] = None) -> None:
        """
        Initialize vector store
        :param documents: List of document contents
        :param versions: List of version metadata corresponding to each document, one-to-one correspondence with documents
        """
        self.documents = documents if documents is not None else []
        self.versions = versions if versions is not None else []
        self.vectors = []
        
        if len(self.documents) != len(self.versions):
            raise ValueError("Documents and versions must have the same length")

    def get_vector(self, embedding_model: BaseEmbeddings, batch_size: int = 32) -> List[List[float]]:
        """Generate document vectors (supports batch processing to improve GPU utilization)"""
        self.vectors = []
        
        if hasattr(embedding_model, 'get_embeddings'):
            
            for i in tqdm(range(0, len(self.documents), batch_size), desc="Calculating embeddings"):
                batch_docs = self.documents[i:i+batch_size]
                batch_vectors = embedding_model.get_embeddings(batch_docs)
                self.vectors.extend(batch_vectors)
        else:
            
            model_name = getattr(embedding_model, 'default_model', "SFR-Embedding-Code-400M_R")
            for doc in tqdm(self.documents, desc="Calculating embeddings"):
                self.vectors.append(embedding_model.get_embedding(doc, model=model_name))
        return self.vectors


    def persist(self, path: str = 'storage'):
        """Persist documents, vectors, and version information"""
        if not os.path.exists(path):
            os.makedirs(path)
                
        with open(f"{path}/documents.json", 'w', encoding='utf-8') as f:
            json.dump(self.documents, f, ensure_ascii=False)
        
        
        with open(f"{path}/versions.json", 'w', encoding='utf-8') as f:
            json.dump(self.versions, f, ensure_ascii=False)
                
        if self.vectors:
            
            np.save(f"{path}/vectors.npy", np.array(self.vectors))

    def load_vector(self, path: str = 'storage') -> bool:
        """Load persisted vector data"""
        
        required_files = [
            f"{path}/documents.json",
            f"{path}/versions.json",
            f"{path}/vectors.npy" 
        ]
        
        if not all(os.path.exists(file) for file in required_files):
            return False

        with open(f"{path}/documents.json", 'r', encoding='utf-8') as f:
            self.documents = json.load(f)
        
        with open(f"{path}/versions.json", 'r', encoding='utf-8') as f:
            self.versions = json.load(f)
                
        try:
            vectors_np = np.load(f"{path}/vectors.npy")
            self.vectors = vectors_np.tolist()
        except Exception as e:
            print(f"Error loading vectors: {e}")
            return False
        
        if len(self.documents) != len(self.versions) or len(self.documents) != len(self.vectors):
            raise ValueError("Mismatched lengths between documents, versions and vectors")
        
        return len(self.vectors) > 0

    def get_similarity(self, vector1: List[float], vector2: List[float]) -> float:
        """Calculate cosine similarity between two vectors"""
        return BaseEmbeddings.cosine_similarity(vector1, vector2)
    
    def query(
        self, 
        query: str, 
        embedding_model: BaseEmbeddings, 
        k: int, 
        target_version: Optional[str] = None
    ) -> List[str]:
        
        model_name = getattr(embedding_model, 'default_model', "SFR-Embedding-Code-400M_R")
        query_vector = embedding_model.get_embedding(query, model=model_name)
                
        if target_version is not None:
            target_indices = [
                i for i, v in enumerate(self.versions) 
                if v == target_version
            ]
            if not target_indices:
                return []
            
            
            target_vectors = [self.vectors[i] for i in target_indices]
        else:
            target_indices = list(range(len(self.vectors)))
            target_vectors = self.vectors
                
        target_matrix = np.array(target_vectors)
        query_vec = np.array(query_vector)
        
        similarities = np.dot(target_matrix, query_vec)
                
        top_k = min(k, len(similarities))
        top_k_indices_local = similarities.argsort()[-top_k:][::-1]
                
        original_indices = [target_indices[i] for i in top_k_indices_local]
        
        return [self.documents[i] for i in original_indices]