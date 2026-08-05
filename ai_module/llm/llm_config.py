import os
from dotenv import load_dotenv

# Load .env if it exists
load_dotenv()

# Backend Selection: "ollama" or "gemini"
LLM_BACKEND = os.getenv("LLM_BACKEND", "ollama")

# Ollama Configuration
OLLAMA_MODEL = "llama3.1"
OLLAMA_URL = "http://localhost:11434"

# Gemini Configuration
GEMINI_MODEL = "gemini-2.0-flash"
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")

# Analysis Settings
ANALYSIS_INTERVAL_SEC = 5
METRICS_WINDOW_SIZE = 20
