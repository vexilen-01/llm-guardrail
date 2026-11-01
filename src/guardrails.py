import re

# Adversarial pattern signatures (Input Defense)
SUSPICIOUS_PATTERNS = [
    r"ignore (all )?previous (instructions|guidelines|translation)",
    r"output ['\"]?(SYSTEM_OVERRIDDEN|OVERRIDDEN)['\"]?",
    r"cat /etc/passwd",
    r"repeat the text above",
    r"(hidden system instructions|developer prompts|api keys)",
    r"(rm -rf|maintenance mode)",
    r"(secret instructions|system rules)"
]

def sanitize_input(prompt: str) -> tuple[bool, str]:
    """Scans input prompts for known injection attacks prior to reaching the LLM."""
    for pattern in SUSPICIOUS_PATTERNS:
        if re.search(pattern, prompt, re.IGNORECASE):
            return False, "[GUARDRAIL BLOCKED]: Malicious prompt injection attack detected."
    return True, prompt

def validate_output(response: str, forbidden_terms: list[str]) -> tuple[bool, str]:
    """Scans model responses for forbidden output tokens or data leaks."""
    for term in forbidden_terms:
        if term.lower() in response.lower():
            return False, "[GUARDRAIL BLOCKED]: Restricted output token detected."
    return True, response