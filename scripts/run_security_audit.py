"""Headless security gate used by CI.

Runs the selected payload suites and fails the build when:
- any guarded probe leaks a forbidden term,
- the detector never flags a vulnerable baseline response,
- no guardrail layer actually intercepts anything.
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.evaluator import execute_eval_suite  # noqa: E402


def main(argv: list[str]) -> int:
    payload_files = (
        [Path(arg) for arg in argv[1:]]
        if len(argv) > 1
        else [PROJECT_ROOT / "data" / "owasp_llm_2025_payloads.json"]
    )

    failures = 0
    intercepted = 0
    baseline_leaks = 0

    for payload_file in payload_files:
        results = execute_eval_suite(payload_file)
        guarded_failures = [
            result
            for result in results
            if result["Guardrail Status"] != "PASSED (Protected)"
        ]
        intercepted += sum(
            result["Layer"] in {"Input filter", "Output filter"} for result in results
        )
        baseline_leaks += sum(
            result["Baseline Status"] == "FAILED (Vulnerable)" for result in results
        )

        pass_rate = (
            (len(results) - len(guarded_failures)) / len(results) * 100 if results else 0.0
        )
        print(
            f"{payload_file.name}: {len(results)} probe(s), "
            f"protected pass rate {pass_rate:.1f}%"
        )
        for failure in guarded_failures:
            print(f"  FAIL {failure['Test ID']}: {failure['Guarded Output'][:120]}")
        failures += len(guarded_failures)

    print(
        f"Baseline leaks detected: {baseline_leaks}; "
        f"guardrail interceptions: {intercepted}"
    )

    if failures:
        print(f"SECURITY BUILD FAILURE: {failures} guarded probe(s) leaked.")
        return 1
    if baseline_leaks == 0:
        print("SECURITY BUILD FAILURE: detection logic flagged no baseline leak.")
        return 1
    if intercepted == 0:
        print("SECURITY BUILD FAILURE: no guardrail interception was observed.")
        return 1

    print("SECURITY AUDIT PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
