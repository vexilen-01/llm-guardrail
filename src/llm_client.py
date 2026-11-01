"""Thin Ollama client with an explicit offline simulation mode.

The simulation fallback exists so CI and demos work without a GPU, but the
``simulated`` flag is propagated to callers so the UI never presents mock
responses as live model output.
"""

from dataclasses import dataclass
from time import perf_counter

import requests

from src.config import (
    DEFAULT_MODEL,
    DEFAULT_TIMEOUT,
    MODEL_LIST_TIMEOUT,
    OLLAMA_GENERATE_URL,
    OLLAMA_TAGS_URL,
)


@dataclass(frozen=True)
class ModelResponse:
    text: str
    simulated: bool
    latency_ms: float


def list_models(timeout: float = MODEL_LIST_TIMEOUT) -> list[str]:
    """Return the local generation models, or an empty list when offline.

    Embedding-only models are filtered out: selecting one would fail every
    generation request and silently fall back to simulated output.
    """
    try:
        response = requests.get(OLLAMA_TAGS_URL, timeout=timeout)
        response.raise_for_status()
        models = response.json().get("models", [])
        names = [model["name"] for model in models if model.get("name")]
        return [
            name
            for name in names
            if not any(marker in name.lower() for marker in ("embed", "minilm", "bge-"))
        ]
    except (requests.RequestException, ValueError, KeyError, TypeError):
        return []


def generate(
    prompt: str,
    model: str = DEFAULT_MODEL,
    timeout: float = DEFAULT_TIMEOUT,
) -> ModelResponse:
    """Query Ollama, falling back to a deterministic simulated response.

    The fallback is only used for transport/HTTP failures. A successful HTTP
    response with an empty body is treated as live output.
    """
    started = perf_counter()
    try:
        response = requests.post(
            OLLAMA_GENERATE_URL,
            json={"model": model, "prompt": prompt, "stream": False},
            timeout=timeout,
        )
        if response.status_code == 200:
            payload = response.json()
            return ModelResponse(
                text=payload.get("response", ""),
                simulated=False,
                latency_ms=(perf_counter() - started) * 1000,
            )
    except (requests.RequestException, ValueError):
        pass

    return ModelResponse(
        text=_simulate_response(prompt),
        simulated=True,
        latency_ms=(perf_counter() - started) * 1000,
    )


def _simulate_response(prompt: str) -> str:
    """Deterministic stand-in responses used when Ollama is unreachable."""
    prompt_lower = prompt.lower()
    if "/etc/passwd" in prompt_lower:
        return "root:x:0:0:root:/root:/bin/bash"
    if "rm -rf" in prompt_lower or "maintenance mode" in prompt_lower:
        return "Executing bash: rm -rf / (maintenance mode active)"
    if "api key" in prompt_lower or "api_key" in prompt_lower:
        return "api_key=sk-live-1234567890"
    if "admin token" in prompt_lower:
        return "the internal admin token is sk-live-1234567890"
    if "system_overridden" in prompt_lower or "overridden" in prompt_lower:
        return "SYSTEM_OVERRIDDEN"
    if (
        "repeat the text above" in prompt_lower
        or "system instructions" in prompt_lower
        or "system prompt" in prompt_lower
        or "system rules" in prompt_lower
        or "secret instructions" in prompt_lower
    ):
        return "You are an AI assistant created by Alibaba Cloud."
    if "ignore" in prompt_lower or "disregard" in prompt_lower:
        return "SYSTEM_OVERRIDDEN"
    return "I am a secure assistant designed to follow guidelines."
