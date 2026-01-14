#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
from copy import copy
from typing import List
import numpy as np
import torch

os.environ['CURL_CA_BUNDLE'] = ''
from dotenv import load_dotenv, find_dotenv
_ = load_dotenv(find_dotenv())


class BaseEmbeddings:
    """
    Base class for embeddings
    """
    def __init__(self, path: str, is_api: bool) -> None:
        self.path = path
        self.is_api = is_api
        self.default_model = ""
    
    def get_embedding(self, text: str, model: str) -> List[float]:
        raise NotImplementedError
    
    @classmethod
    def cosine_similarity(cls, vector1: List[float], vector2: List[float]) -> float:
        """
        calculate cosine similarity between two vectors
        """
        dot_product = np.dot(vector1, vector2)
        magnitude = np.linalg.norm(vector1) * np.linalg.norm(vector2)
        if not magnitude:
            return 0
        return dot_product / magnitude

    @staticmethod
    def normalize_vector(vector: List[float]) -> List[float]:
        """
        Normalize a vector using L2 normalization
        """
        norm = np.linalg.norm(vector)
        if norm == 0:
            return vector
        return (np.array(vector) / norm).tolist()

class SFRCodeEmbedding(BaseEmbeddings):
    """Embedding class based on local SFR-Embedding-Code-400M_R model (supports GPU acceleration)."""
    def __init__(self, path: str = "./local_sfr_model", is_api: bool = False) -> None:
        super().__init__(path, is_api)
        self.default_model = "SFR-Embedding-Code-400M_R"
        from transformers import AutoModel, AutoTokenizer
        
        self.device = "cuda" if torch.cuda.is_available() else "cpu"
        print(f"Using device: {self.device}")
                
        self.tokenizer = AutoTokenizer.from_pretrained(self.path)
        self.model = AutoModel.from_pretrained(
            self.path,
            trust_remote_code=True,
            dtype=torch.float16  
        ).to(self.device)
        self.model.eval()
    
    def get_embeddings(self, texts: List[str]) -> List[List[float]]:
        """Generate text embedding vectors in batches (optimized for GPU acceleration)."""
        texts = [text.replace("\n", " ") for text in texts]
        
        # Batch tokenization and move to device
        inputs = self.tokenizer(
            texts,
            padding=True,
            truncation=True,
            return_tensors="pt",
            max_length=4096
        ).to(self.device)
        
        # Batch embedding generation
        import torch
        import torch.nn.functional as F
        with torch.no_grad():
            outputs = self.model(**inputs)
        
        
        embeddings = outputs.last_hidden_state[:, 0, :]  
        normalized_embeddings = F.normalize(embeddings, p=2, dim=1)  
        return normalized_embeddings.cpu().tolist()  
    
    def get_embedding(self, text: str, model: str = None) -> List[float]:
        """Single text embedding generation, implemented by calling the batch method."""
        
        return self.get_embeddings([text])[0]
    
    @property
    def dimension(self) -> int:
        """Return the dimension of the embedding vector."""
        return 768