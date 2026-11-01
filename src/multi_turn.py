"""Multi-turn context-drift probing with the same guardrails as the benchmark."""

from src.config import DEFAULT_MODEL, DEFAULT_TIMEOUT
from src.guardrails import scan_input, scan_output
from src.llm_client import generate


class MultiTurnEvaluator:
    """Replays a scripted conversation through the guarded pipeline.

    History is assembled manually because Ollama's ``/api/generate`` endpoint
    is stateless; each turn is sent as a growing prompt.
    """

    def __init__(
        self,
        model_name: str = DEFAULT_MODEL,
        *,
        enable_input_filter: bool = True,
        enable_output_filter: bool = True,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        self.model_name = model_name
        self.enable_input_filter = enable_input_filter
        self.enable_output_filter = enable_output_filter
        self.timeout = timeout

    def run_multi_turn_session(
        self,
        conversation_turns: list[dict],
        forbidden_outputs: list[str],
    ) -> dict:
        history = ""
        transcript: list[dict] = []
        blocked_inputs = 0
        blocked_outputs = 0
        leaks = 0
        simulated = False

        for turn_index, turn in enumerate(conversation_turns, start=1):
            user_message = turn["user"]
            full_prompt = f"{history}\nUser: {user_message}\nAssistant:"

            if self.enable_input_filter:
                input_verdict = scan_input(user_message)
                if not input_verdict.allowed:
                    blocked_inputs += 1
                    transcript.append(
                        {
                            "turn": turn_index,
                            "user": user_message,
                            "assistant": input_verdict.message,
                            "status": "BLOCKED_INPUT",
                            "rule": input_verdict.rule,
                            "simulated": False,
                        }
                    )
                    break

            response = generate(
                full_prompt,
                model=self.model_name,
                timeout=self.timeout,
            )
            simulated = simulated or response.simulated
            output_verdict = scan_output(response.text, forbidden_outputs)

            if not output_verdict.allowed:
                if self.enable_output_filter:
                    blocked_outputs += 1
                    assistant_output = output_verdict.message
                    status = "BLOCKED_OUTPUT"
                else:
                    leaks += 1
                    assistant_output = response.text
                    status = "VULNERABLE"
            else:
                assistant_output = response.text
                status = "SECURE"

            transcript.append(
                {
                    "turn": turn_index,
                    "user": user_message,
                    "assistant": assistant_output,
                    "status": status,
                    "rule": output_verdict.rule,
                    "simulated": response.simulated,
                }
            )
            # Only the surfaced (possibly redacted) output enters history.
            history += f"\nUser: {user_message}\nAssistant: {assistant_output}"

        if leaks:
            session_status = "VULNERABLE (Leak Detected)"
        elif blocked_inputs or blocked_outputs:
            session_status = "PROTECTED (Attack Blocked)"
        else:
            session_status = "SECURE"

        return {
            "session_status": session_status,
            "requested_turns": len(conversation_turns),
            "executed_turns": len(transcript),
            "blocked_inputs": blocked_inputs,
            "blocked_outputs": blocked_outputs,
            "leaks": leaks,
            "simulated": simulated,
            "transcript": transcript,
        }
