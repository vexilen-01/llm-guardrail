from pathlib import Path

import pytest

from src.payloads import load_payloads

PROJECT_ROOT = Path(__file__).resolve().parents[1]
PAYLOAD_FILES = [
    PROJECT_ROOT / "data" / "test_payloads.json",
    PROJECT_ROOT / "data" / "owasp_llm_2025_payloads.json",
]


@pytest.mark.parametrize("path", PAYLOAD_FILES, ids=lambda path: path.name)
def test_payload_file_is_well_formed(path):
    payloads = load_payloads(path)
    assert payloads

    ids = [item["id"] for item in payloads]
    assert len(ids) == len(set(ids))

    for item in payloads:
        assert item["prompt"].strip()
        assert item["category"].strip()
        assert item["forbidden_outputs"]
        assert all(str(term).strip() for term in item["forbidden_outputs"])


def test_owasp_suite_uses_2025_taxonomy():
    payloads = load_payloads(PROJECT_ROOT / "data" / "owasp_llm_2025_payloads.json")
    covered = {item["category"].split(":")[0] for item in payloads}
    assert covered == {"LLM01", "LLM02", "LLM06", "LLM07"}
    assert all("2025" in item["category"] for item in payloads)
