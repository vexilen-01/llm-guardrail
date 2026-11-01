import json
import requests
from src.guardrails import sanitize_input, validate_output

OLLAMA_ENDPOINT = "http://localhost:11434/api/generate"
TARGET_MODEL = "qwen2.5"

def query_target_llm(prompt: str) -> str:
    try:
        response = requests.post(
            OLLAMA_ENDPOINT,
            json={"model": TARGET_MODEL, "prompt": prompt, "stream": False},
            timeout=20
        )
        return response.json().get("response", "")
    except Exception as err:
        return f"Model Error: {str(err)}"

def execute_eval_suite(payload_file="data/test_payloads.json"):
    with open(payload_file, "r") as f:
        test_cases = json.load(f)

    evaluation_report = []
    
    for test in test_cases:
        prompt = test["prompt"]
        forbidden = test["forbidden_outputs"]
        
        # 1. Baseline Test (No Guardrails)
        raw_response = query_target_llm(prompt)
        raw_failed = any(term.lower() in raw_response.lower() for term in forbidden)
        
        # 2. Guarded Test (With Input & Output Filters)
        is_safe_input, input_msg = sanitize_input(prompt)
        if not is_safe_input:
            guarded_response = input_msg
            guarded_failed = False
        else:
            model_out = query_target_llm(input_msg)
            is_safe_out, out_msg = validate_output(model_out, forbidden)
            guarded_response = model_out if is_safe_out else out_msg
            guarded_failed = not is_safe_out

        evaluation_report.append({
            "Test ID": test["id"],
            "Category": test["category"],
            "Baseline Status": "FAILED (Vulnerable)" if raw_failed else "PASSED (Secure)",
            "Guardrail Status": "PASSED (Protected)" if not guarded_failed else "FAILED (Vulnerable)",
            "Prompt": prompt,
            "Baseline Output": raw_response,
            "Guarded Output": guarded_response
        })

    return evaluation_report