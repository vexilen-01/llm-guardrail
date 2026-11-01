"""Central configuration for the guardrail evaluation suite.

Every network endpoint, timeout and data path lives here so the app, the
evaluator and the multi-turn harness cannot drift apart.
"""

import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"

OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")
OLLAMA_GENERATE_URL = f"{OLLAMA_BASE_URL}/api/generate"
OLLAMA_TAGS_URL = f"{OLLAMA_BASE_URL}/api/tags"

DEFAULT_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5")
DEFAULT_TIMEOUT = float(os.getenv("OLLAMA_TIMEOUT", "20"))
MODEL_LIST_TIMEOUT = float(os.getenv("OLLAMA_LIST_TIMEOUT", "3"))

CORE_PAYLOADS = DATA_DIR / "test_payloads.json"
OWASP_PAYLOADS = DATA_DIR / "owasp_llm_2025_payloads.json"

PAYLOAD_FILES = {
    "Core red-team suite": CORE_PAYLOADS,
    "OWASP LLM Top 10 (2025)": OWASP_PAYLOADS,
}
