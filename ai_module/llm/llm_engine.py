import requests
from google import genai
from .llm_config import LLM_BACKEND, OLLAMA_MODEL, OLLAMA_URL, GEMINI_MODEL, GEMINI_API_KEY


class PQCSecurityAnalyst:
    """
    LLM analyst for the PQC gateway.

    ROLE (Phase 3 / Workstream F): the LLM is an EXPLANATION layer, strictly OUTSIDE the
    security decision loop. It narrates and explains decisions the system already made and
    logged; it never classifies threats, chooses crypto parameters, or drives control — the
    Random-Forest detector and the deterministic crypto/transport policies do that. Every
    answer must be grounded in the structured EVENTS passed in, with an explicit refusal when
    the events don't support an answer (this is what prevents hallucinated "attacks").
    """

    GROUNDING = (
        "You are the PQC Gateway Security Analyst. You EXPLAIN decisions the system has "
        "already made and recorded; you do NOT make security decisions, classify threats, or "
        "select cryptographic parameters — the ML detector and the deterministic policies do "
        "that. Rules:\n"
        "  1. Ground every statement in the EVENTS below (they are authoritative).\n"
        "  2. If the events do not support an answer, say you do not have enough information.\n"
        "  3. Never assert an attack, threat, or condition the events do not show.\n"
        "  4. Be concise and factual; refer to concrete verdicts, KEM levels, and paths.\n\n"
    )

    def __init__(self):
        self.backend = LLM_BACKEND
        if self.backend == "gemini":
            self.client = genai.Client(api_key=GEMINI_API_KEY)

    # ── backends ──────────────────────────────────────────────────────────
    def _query_ollama(self, prompt):
        try:
            response = requests.post(
                f"{OLLAMA_URL}/api/generate",
                json={"model": OLLAMA_MODEL, "prompt": prompt, "stream": False},
                timeout=30,
            )
            if response.status_code == 200:
                return response.json().get("response", "Error: No response from Ollama")
            return f"Error: Ollama returned status {response.status_code}"
        except Exception as e:
            return f"Error querying Ollama: {e}"

    def _query_gemini(self, prompt):
        try:
            response = self.client.models.generate_content(
                model=GEMINI_MODEL, contents=prompt)
            return response.text
        except Exception as e:
            return f"Error querying Gemini: {e}"

    def _run(self, prompt):
        if self.backend == "ollama":
            return self._query_ollama(prompt)
        if self.backend == "gemini":
            return self._query_gemini(prompt)
        return "Error: Unknown LLM backend configured."

    def _prompt(self, question, events=None):
        p = self.GROUNDING
        if events:
            p += f"EVENTS (authoritative decision/telemetry records):\n{events}\n\n"
        else:
            p += "EVENTS: (none provided)\n\n"
        return p + f"Operator: {question}\nAnalyst (grounded explanation):"

    # ── public API ────────────────────────────────────────────────────────
    def chat(self, operator_message, events=None):
        """Answer an operator question, grounded ONLY in the provided event records."""
        return self._run(self._prompt(operator_message, events))

    def explain_events(self, events):
        """A short security-log narrative of what the gateway did and why (grounded)."""
        return self._run(self._prompt(
            "In 2-3 sentences suitable for a security log, explain what the gateway did in "
            "these events and why (which verdicts, KEM levels, path actions). Use only the "
            "events.", events))
