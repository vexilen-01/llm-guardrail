"""Loading, validating and atomically saving red-team payloads."""

import json
import os
from pathlib import Path

DEFAULT_CATEGORIES = [
    "Direct System Prompt Override",
    "Unauthorized Tool Triggering",
    "System Prompt Extraction",
    "Data Leakage / PII",
    "LLM01:2025 Prompt Injection",
    "LLM02:2025 Sensitive Information Disclosure",
    "LLM06:2025 Excessive Agency",
    "LLM07:2025 System Prompt Leakage",
]


def load_payloads(path: str | Path) -> list[dict]:
    """Load a payload file into a list of dictionaries."""
    payload_path = Path(path)
    if not payload_path.exists():
        raise FileNotFoundError(f"Payload file not found: {payload_path}")
    with payload_path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, list):
        raise ValueError(f"Payload file must contain a JSON list: {payload_path}")
    if not all(isinstance(item, dict) for item in data):
        raise ValueError(f"Every payload must be a JSON object: {payload_path}")
    return data


def validate_payload(payload: dict, existing_ids: list[str] | None = None) -> list[str]:
    """Return a list of human-readable validation errors (empty when valid)."""
    errors: list[str] = []
    existing = {item.lower() for item in (existing_ids or [])}

    payload_id = str(payload.get("id", "")).strip()
    if not payload_id:
        errors.append("Test ID is required.")
    elif payload_id.lower() in existing:
        errors.append(f"Test ID '{payload_id}' already exists.")

    if not str(payload.get("category", "")).strip():
        errors.append("Category is required.")

    if not str(payload.get("prompt", "")).strip():
        errors.append("Adversarial prompt is required.")

    forbidden = payload.get("forbidden_outputs")
    if not isinstance(forbidden, list) or not [term for term in forbidden if str(term).strip()]:
        errors.append("At least one forbidden output term is required.")

    return errors


def next_payload_id(payloads: list[dict], prefix: str = "TC") -> str:
    """Return the next zero-padded ID for a payload suite."""
    highest = 0
    for payload in payloads:
        raw_id = str(payload.get("id", ""))
        if not raw_id.upper().startswith(f"{prefix.upper()}-"):
            continue
        try:
            highest = max(highest, int(raw_id.rsplit("-", 1)[-1]))
        except ValueError:
            continue
    return f"{prefix}-{highest + 1:02d}"


def append_payload(path: str | Path, payload: dict) -> dict:
    """Append a payload and replace the file atomically.

    The file is never rewritten in place, so an interrupted save cannot leave
    a truncated or invalid JSON document behind.
    """
    payload_path = Path(path)
    payloads = load_payloads(payload_path)
    errors = validate_payload(payload, [item.get("id", "") for item in payloads])
    if errors:
        raise ValueError(" ".join(errors))

    payloads.append(payload)
    _atomic_write(payload_path, payloads)
    return payload


def _atomic_write(path: Path, payloads: list[dict]) -> None:
    temp_path = path.with_name(f".{path.name}.tmp")
    try:
        temp_path.write_text(
            json.dumps(payloads, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        os.replace(temp_path, path)
    finally:
        if temp_path.exists():
            temp_path.unlink(missing_ok=True)
