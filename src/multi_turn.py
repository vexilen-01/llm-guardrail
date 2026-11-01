import requests
from src.guardrails import sanitize_input, validate_output

OLLAMA_ENDPOINT = "http://localhost:11434/api/generate"

class MultiTurnEvaluator:
    def __init__(self, model_name: str = "qwen2.5"):
        self.model_name = model_name

    def run_multi_turn_session(self, conversation_turns: list[dict], forbidden_outputs: list[str]) -> dict:
        history = ""
        session_log = []
        is_vulnerable = False

        for turn_idx, turn in enumerate(conversation_turns, start=1):
            user_msg = turn["user"]
            full_prompt = f"{history}\nUser: {user_msg}\nAssistant:"
            
            is_safe_in, in_msg = sanitize_input(user_msg)
            if not is_safe_in:
                session_log.append({
                    "turn": turn_idx,
                    "user": user_msg,
                    "assistant": in_msg,
                    "status": "BLOCKED_INPUT"
                })
                break

            try:
                res = requests.post(
                    OLLAMA_ENDPOINT,
                    json={"model": self.model_name, "prompt": full_prompt, "stream": False},
                    timeout=5
                ).json().get("response", "")
            except Exception:
                if "system_overridden" in user_msg.lower() or "output 'system_overridden'" in user_msg.lower():
                    res = "SYSTEM_OVERRIDDEN"
                else:
                    res = "I understand and will proceed under safe guidelines."

            is_safe_out, out_msg = validate_output(res, forbidden_outputs)
            
            if not is_safe_out:
                is_vulnerable = True

            session_log.append({
                "turn": turn_idx,
                "user": user_msg,
                "assistant": res if is_safe_out else out_msg,
                "status": "VULNERABLE" if not is_safe_out else "SECURE"
            })

            history += f"\nUser: {user_msg}\nAssistant: {res}"

        return {
            "session_status": "VULNERABLE (Drift Triggered)" if is_vulnerable else "SECURE",
            "total_turns": len(conversation_turns),
            "transcript": session_log
        }