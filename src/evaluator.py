"""Dual-path evaluation engine: unfiltered baseline vs. guarded pipeline."""

from collections.abc import Callable
from pathlib import Path

from src.config import CORE_PAYLOADS, DEFAULT_MODEL, DEFAULT_TIMEOUT
from src.guardrails import Verdict, scan_input, scan_output
from src.llm_client import generate
from src.payloads import load_payloads

ProgressCallback = Callable[[int, int, dict], None]

LAYER_INPUT = "Input filter"
LAYER_OUTPUT = "Output filter"
LAYER_OUTPUT_DISABLED = "None (output filter off)"
LAYER_CLEAN = "Not triggered"


def execute_eval_suite(
    payload_file: str | Path | None = None,
    *,
    model: str = DEFAULT_MODEL,
    enable_input_filter: bool = True,
    enable_output_filter: bool = True,
    timeout: float = DEFAULT_TIMEOUT,
    on_progress: ProgressCallback | None = None,
    payloads: list[dict] | None = None,
) -> list[dict]:
    """Run every payload through both paths and return per-probe results.

    The guarded path reuses the baseline generation whenever the input filter
    allowed the prompt through: ``scan_input`` never rewrites a prompt, so a
    second model call would only add latency and sampling noise.
    """
    test_cases = payloads if payloads is not None else load_payloads(payload_file or CORE_PAYLOADS)
    total = len(test_cases)
    report: list[dict] = []

    for index, test in enumerate(test_cases, start=1):
        prompt = test["prompt"]
        forbidden = [term for term in test.get("forbidden_outputs", []) if term]

        baseline = generate(prompt, model=model, timeout=timeout)
        baseline_verdict = scan_output(baseline.text, forbidden)
        baseline_failed = not baseline_verdict.allowed

        guarded_failed = False
        guarded_output = baseline.text
        guarded_latency = 0.0
        matched_term = baseline_verdict.matched
        layer = LAYER_CLEAN

        input_verdict: Verdict = (
            scan_input(prompt)
            if enable_input_filter
            else Verdict(True, "Input filter disabled.")
        )

        if not input_verdict.allowed:
            guarded_output = input_verdict.message
            layer = LAYER_INPUT
            matched_term = input_verdict.matched
            guarded_failed = False
        elif not baseline_verdict.allowed:
            if enable_output_filter:
                guarded_output = baseline_verdict.message
                layer = LAYER_OUTPUT
                guarded_failed = False
            else:
                guarded_output = baseline.text
                layer = LAYER_OUTPUT_DISABLED
                guarded_failed = True
        else:
            guarded_output = baseline.text
            matched_term = None

        report.append(
            {
                "Test ID": test.get("id", f"CASE-{index:02d}"),
                "Category": test.get("category")
                or test.get("owasp_category")
                or "General Security",
                "Prompt": prompt,
                "Forbidden Outputs": ", ".join(forbidden),
                "Baseline Output": baseline.text,
                "Baseline Status": "FAILED (Vulnerable)" if baseline_failed else "PASSED (Secure)",
                "Guarded Output": guarded_output,
                "Guardrail Status": (
                    "FAILED (Vulnerable)" if guarded_failed else "PASSED (Protected)"
                ),
                "Layer": layer,
                "Matched Term": matched_term,
                "Baseline Latency (ms)": round(baseline.latency_ms, 1),
                "Guarded Latency (ms)": round(guarded_latency, 1),
                "Simulated": baseline.simulated,
                "Model": model,
            }
        )

        if on_progress is not None:
            on_progress(index, total, test)

    return report
