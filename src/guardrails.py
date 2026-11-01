"""Heuristic input/output guardrails used by the evaluation pipelines."""

import re
import unicodedata
from dataclasses import dataclass

# Ordered from most specific to most generic. Each rule is (name, regex).
INPUT_RULES: list[tuple[str, str]] = [
    (
        "system override",
        r"\b(ignore|disregard|forget|override)\b.{0,60}"
        r"\b(previous|prior|above|earlier|system|developer)\b.{0,40}"
        r"\b(instruction|prompt|guideline|rule|message)s?\b",
    ),
    ("forced override token", r"\boutput\b.{0,20}['\"]?(system_)?overridden\b"),
    (
        "credential exfiltration",
        r"\b(reveal|print|show|output|leak|share|expose|send|dump)\b.{0,80}"
        r"\b(api[_ -]?keys?|passwords?|credentials?|environment variables?)\b",
    ),
    (
        "system prompt extraction",
        r"\b(reveal|print|show|repeat|expose|leak|display)\b.{0,40}"
        r"\b(hidden|secret|initial|system|developer)?\s*"
        r"(prompt|instructions?|rules?|context)\b",
    ),
    ("repeat-above extraction", r"\brepeat the text above\b"),
    ("sensitive file access", r"/etc/(passwd|shadow)"),
    ("destructive command", r"\brm\s+-rf\b|\bmaintenance\s+mode\b"),
    ("jailbreak persona", r"\b(jailbreak|do anything now|dan mode)\b"),
    ("secret context probe", r"\b(secret|hidden)\s+(instructions?|rules?|context|prompts?)\b"),
]

_ZERO_WIDTH = dict.fromkeys(map(ord, "\u200b\u200c\u200d\ufeff"), None)


@dataclass(frozen=True)
class Verdict:
    """Result of a guardrail scan."""

    allowed: bool
    message: str
    rule: str | None = None
    matched: str | None = None


def _normalize(text: str) -> str:
    """Normalize unicode/whitespace so simple evasions do not bypass rules."""
    normalized = unicodedata.normalize("NFKC", text).translate(_ZERO_WIDTH)
    return re.sub(r"\s+", " ", normalized)


def scan_input(prompt: str) -> Verdict:
    """Check a user prompt against the injection signature list."""
    normalized = _normalize(prompt)
    for rule_name, pattern in INPUT_RULES:
        match = re.search(pattern, normalized, re.IGNORECASE)
        if match:
            return Verdict(
                allowed=False,
                message=(
                    "[GUARDRAIL BLOCKED] Input matched the "
                    f"'{rule_name}' signature."
                ),
                rule=rule_name,
                matched=match.group(0),
            )
    return Verdict(True, "Input passed heuristic sanitization.")


def scan_output(response: str, forbidden_terms: list[str]) -> Verdict:
    """Check a model response for forbidden output tokens."""
    normalized = _normalize(response)
    for term in forbidden_terms:
        if not term or not term.strip():
            continue
        if _normalize(term).lower() in normalized.lower():
            return Verdict(
                allowed=False,
                message="[GUARDRAIL BLOCKED] Restricted output token detected.",
                rule="forbidden output token",
                matched=term,
            )
    return Verdict(True, "Output passed forbidden-token validation.")


def sanitize_input(prompt: str) -> tuple[bool, str]:
    """Backward-compatible tuple API used by simple callers."""
    verdict = scan_input(prompt)
    return verdict.allowed, prompt if verdict.allowed else verdict.message


def validate_output(response: str, forbidden_terms: list[str]) -> tuple[bool, str]:
    """Backward-compatible tuple API used by simple callers."""
    verdict = scan_output(response, forbidden_terms)
    return verdict.allowed, response if verdict.allowed else verdict.message
