import requests
import json
from google import genai
from .llm_config import LLM_BACKEND, OLLAMA_MODEL, OLLAMA_URL, GEMINI_MODEL, GEMINI_API_KEY

class PQCSecurityAnalyst:
    def __init__(self):
        self.backend = LLM_BACKEND
        if self.backend == "gemini":
            self.client = genai.Client(api_key=GEMINI_API_KEY)

    def _query_ollama(self, prompt):
        try:
            response = requests.post(
                f"{OLLAMA_URL}/api/generate",
                json={
                    "model": OLLAMA_MODEL,
                    "prompt": prompt,
                    "stream": False
                },
                timeout=30
            )
            if response.status_code == 200:
                return response.json().get("response", "Error: No response from Ollama")
            return f"Error: Ollama returned status {response.status_code}"
        except Exception as e:
            return f"Error querying Ollama: {e}"

    def _query_gemini(self, prompt):
        try:
            response = self.client.models.generate_content(
                model=GEMINI_MODEL,
                contents=prompt
            )
            return response.text
        except Exception as e:
            return f"Error querying Gemini: {e}"

    def chat(self, operator_message, context_data=None):
        """
        Main chat interface for the operator.
        """
        system_prompt = (
            "You are the PQC Gateway Security Analyst, an expert in Post-Quantum Cryptography, "
            "SCTP multihoming, and machine learning-based threat detection. "
            "Your goal is to assist the operator in understanding the gateway's state and security decisions.\n\n"
        )
        
        if context_data:
            system_prompt += f"CURRENT GATEWAY METRICS (Last {len(context_data)} sessions):\n{context_data}\n\n"
        
        full_prompt = f"{system_prompt}Operator asks: {operator_message}\nAnalyst:"
        
        if self.backend == "ollama":
            return self._query_ollama(full_prompt)
        elif self.backend == "gemini":
            return self._query_gemini(full_prompt)
        else:
            return "Error: Unknown LLM backend configured."

    def analyze_metrics(self, metrics_window):
        """
        Background analysis of a window of metrics.
        """
        prompt = (
            f"Analyze the following recent gateway metrics and provide a concise summary of the network health "
            f"and any detected anomalies. Metrics:\n{metrics_window}\n\n"
            "Respond with a short paragraph suitable for a security log."
        )
        if self.backend == "ollama":
            return self._query_ollama(prompt)
        elif self.backend == "gemini":
            return self._query_gemini(prompt)
        return "Error: Backend not configured."
