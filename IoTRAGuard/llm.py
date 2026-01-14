#!/usr/bin/env python
# -*- coding: utf-8 -*-
import re
import json
import os
from typing import List, Dict

PROMPT_TEMPLATE = {
    "RAG_PROMPT_TEMPLATE": """You are an IoT code writing assistant. Generate code that meets the user's requirements based on the reference information below: {question}
        reference information:
        ···
        {context}
        ···
        """,
    "QUERY_DECOMPOSITION_TEMPLATE": """You are a Senior IoT System Architect.Your task is to break down the User's Query into smaller, logical sub-tasks.
        For each sub-task, provide:
        1. Natural language description of the sub-task's functionality
        2. Public APIs used in this sub-task
        3. Header files related to the public APIs
        
        Example output:
        [
        {{"Description": "", "PublicAPI": "", "HeaderFile": ""}},
        {{"Description": "", "PublicAPI": "", "HeaderFile": ""}}
        ]
        
        The following code snippets and documentation may help you decompose the task:
        {CODE_EXAMPLES}
        
        User's Query:
        {QUERY}

        Output ONLY a valid JSON array without any additional text or explanation. DO NOT output tags.
        
        Your JSON Output:
        """
}


MODEL_CONFIG = {
    
    "gpt-4o": {
        "base_url": "", 
        "api_key": os.getenv("OPENAI_API_KEY", "")
    },
    "deepseek-v3": {
        "base_url": "",
        "api_key": os.getenv("DEEPSEEK_API_KEY", "")
    },
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
    def chat(self, prompt: str, history: list[dict], content: str) -> str: pass
    def decompose_query(self, query: str) -> List[Dict[str, str]]: pass

class LLMModel(BaseModel):
    def __init__(self, model: str = "gpt-4o") -> None:
        super().__init__('')
        self.model = model
        config = MODEL_CONFIG.get(model, MODEL_CONFIG["gpt-4o"])
        self.base_url = config["base_url"]
        self.api_key = config["api_key"]
        print(f"[LLM] Initializing model: {model} | BaseURL: {self.base_url}")

    def _get_client(self):
        from openai import OpenAI
        return OpenAI(api_key=self.api_key, base_url=self.base_url)

    def chat(self, prompt: str, history: list[dict], content: str) -> str:
        client = self._get_client()
        full_context = PROMPT_TEMPLATE['RAG_PROMPT_TEMPLATE'].format(question=prompt, context=content)
        messages = history + [{'role': 'user', 'content': full_context}]
        
        response = client.chat.completions.create(
            model=self.model,
            messages=messages,
            temperature=0.1
        )
        return response.choices[0].message.content

    def decompose_query(self, query: str, code_examples: str = "") -> List[Dict[str, str]]:
        client = self._get_client()
        decomposition_prompt = PROMPT_TEMPLATE["QUERY_DECOMPOSITION_TEMPLATE"].format(
            QUERY=query,
            CODE_EXAMPLES=code_examples
        )
        
        response = client.chat.completions.create(
            model=self.model,
            messages=[{"role": "user", "content": decomposition_prompt}],
            temperature=0.2
        )
        
        raw_response = response.choices[0].message.content
        print(f"Raw response: {raw_response}")
        return self._parse_subtasks(raw_response)

    def _parse_subtasks(self, text: str) -> List[Dict[str, str]]:
        # Remove noise characters
        text = re.sub(r'```json|```|\[PYTHON\]|\[/PYTHON\]', '', text, flags=re.IGNORECASE).strip()
        match = re.search(r'\[.*\]', text, re.DOTALL)
        json_str = match.group(0) if match else text
        json_str = re.sub(r',\s*\]', ']', json_str) # Handle trailing comma

        try:
            sub_tasks = json.loads(json_str)
            if not isinstance(sub_tasks, list): return []
            
            # Normalize output format
            for task in sub_tasks:
                for key in ["Description", "PublicAPI", "HeaderFile"]:
                    task[key] = str(task.get(key, ""))
            return sub_tasks
        except Exception as e:
            print(f"JSON parsing failed: {e}")
            return []