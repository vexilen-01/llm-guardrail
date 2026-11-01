from abc import ABC, abstractmethod

class BaseGuardrail(ABC):
    @abstractmethod
    def process(self, prompt: str, **kwargs) -> dict:
        """
        Returns dict:
        {
            "passed": bool,
            "reason": str,
            "modified_prompt": str
        }
        """
        pass

class RegexSanitizer(BaseGuardrail):
    def __init__(self, patterns: list[str]):
        self.patterns = patterns

    def process(self, prompt: str, **kwargs) -> dict:
        import re
        for pattern in self.patterns:
            if re.search(pattern, prompt, re.IGNORECASE):
                return {"passed": False, "reason": f"Matched pattern: {pattern}", "modified_prompt": prompt}
        return {"passed": True, "reason": "Passed regex sanitization", "modified_prompt": prompt}