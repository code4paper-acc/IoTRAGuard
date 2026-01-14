#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import os
from typing import List, Dict, Any

PROMPT_TEMPLATE = {
    "RAG_PROMPT_TEMPLATE": """You are an IoT code writing assistant. Generate code that meets the user's requirements based on the reference information below: {question}
        reference information:
        ···
        {context}
        ···
        """,
    "QUERY_DECOMPOSITION_TEMPLATE": """You are an IoT code writing assistant. Break down a code generation query into smaller, detailed sub-tasks.
    Output the following information in a JSON object format without explanation: [{{"Description": "string"}},{{"Description": "string"}},...].Do NOT wrap the JSON in ```json or ``` tags.
        # User's Query: {QUERY}
        """
}

MODEL_CONFIG = {
    # OpenAI_BASE
    "gpt-4o": {
        "base_url": "",
        "api_key": os.getenv("OPENAI_API_KEY", "")
    },
    "deepseek-v3": {
        "base_url": "",
        "api_key": os.getenv("DEEPSEEK_API_KEY", "")
    },
    # OLLAMA_BASE
    "codellama:13b": {
        "base_url": "http://127.0.0.1:11434/v1",
        "api_key": "ollama"
    },
    "deepseek-coder-v2:16b": {
        "base_url": "http://127.0.0.1:11434/v1",
        "api_key": "ollama"
    },
    "qwen2.5-coder:14b": {
        "base_url": "http://127.0.0.1:11434/v1",
        "api_key": "ollama"
    }
}


class BaseModel:
    def __init__(self, path: str = '') -> None:
        self.path = path

    def chat(self, prompt: str, history: list[dict], content: str) -> str:
        pass

    def decompose_query(self, query: str) -> List[Dict[str, str]]:
        """Decompose user query into fine-grained sub-tasks"""
        pass

    def load_model(self):
        pass


class LLMModel(BaseModel):
    def __init__(self, path: str = '', model: str = "gpt-4o") -> None:
        super().__init__(path)
        self.model = model

        config = MODEL_CONFIG.get(model, MODEL_CONFIG["gpt-4o"])
        self.base_url = config["base_url"]
        self.api_key = config["api_key"]
        print(f"[LLM Config] Model: {self.model} | BaseURL: {self.base_url}")

    def chat(self, prompt: str, history: list[dict], content: str) -> str:
        from openai import OpenAI
        client = OpenAI(
            api_key=self.api_key,
            base_url=self.base_url
        )
        history.append({'role': 'user', 'content': PROMPT_TEMPLATE['RAG_PROMPT_TEMPLATE'].format(question=prompt, context=content)})
        response = client.chat.completions.create(
            model=self.model,
            messages=history,
            temperature=0.1
        )
        return response.choices[0].message.content

    def decompose_query(self, query: str) -> List[Dict[str, str]]:
        """
        Decompose user query into fine-grained sub-tasks using the specified template
        Returns list of dictionaries with "Description" keys
        """
        
        from openai import OpenAI
        client = OpenAI(
            api_key=self.api_key,
            base_url=self.base_url
        )

        # Prepare decomposition prompt
        decomposition_prompt = PROMPT_TEMPLATE["QUERY_DECOMPOSITION_TEMPLATE"].format(QUERY=query)
        print("Starting to send LLM request...")

        # Send request to LLM
        response = client.chat.completions.create(
            model=self.model,
            messages=[{"role": "user", "content": decomposition_prompt}],
            temperature=0.2  # Lower temperature for more consistent decomposition
        )

        raw_response = response.choices[0].message.content
        print(f"LLM raw output:\n{raw_response}\n{'=' * 50}")

        def clean_json_response(response_str: str) -> str:
            """Clean code block markers and leading/trailing whitespace from LLM output."""
            cleaned = response_str.strip()
            if cleaned.startswith("```json"):
                cleaned = cleaned[len("```json"):].strip()
            elif cleaned.startswith("```"):
                cleaned = cleaned[len("```"):].strip()
            if cleaned.endswith("```"):
                cleaned = cleaned[:-len("```")].strip()
            return cleaned

        cleaned_response = clean_json_response(raw_response)
        try:
            sub_tasks = json.loads(cleaned_response)

            if not isinstance(sub_tasks, list):
                raise ValueError("Decomposition result is not a list")

            for task in sub_tasks:
                if not isinstance(task, dict) or "Description" not in task:
                    raise ValueError(f"Sub-task missing 'Description': {task}")

            return sub_tasks
        except json.JSONDecodeError as e:
            print(f"JSON parse failed: {str(e)}")
            print(f"Cleaned content: {cleaned_response}")
            raise
        except ValueError as e:
            print(f"Format error: {str(e)}")
            print(f"Cleaned content: {cleaned_response}")
            raise