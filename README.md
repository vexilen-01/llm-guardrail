python -c "
content = '''# 🛡️ LLM Guardrail & Red-Teaming Suite

![CI/CD Security Audit](https://github.com/vexilen-01/llm-guardrail/actions/workflows/security_eval.yml/badge.svg)
![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)
![Streamlit](https://img.shields.io/badge/Streamlit-1.30%2B-FF4B4B?logo=streamlit)
![Ollama](https://img.shields.io/badge/Model-Ollama%20%2F%20Qwen%202.5-black)
![Security](https://img.shields.io/badge/OWASP-LLM%20Top%2010%20(2026)-green)

An automated security evaluation and defense benchmarking platform for local Large Language Models (LLMs). Built to probe, quantify, and mitigate AI risks including adversarial prompt injection, system prompt exfiltration, context drift, and excessive agency.

---

## 📌 Executive Summary

As LLM applications gain agency and integrate into production workflows, securing model context boundaries becomes critical. This platform provides a **dual-path evaluation framework** (Unfiltered Baseline vs. Protected Guardrail Layer) to stress-test models against security benchmarks. It features real-time input sanitization, dynamic output token filtering, multi-turn context-drift probing, and automated CI/CD security regression auditing.

---

## 📐 Architecture & Defense Pipeline

\`\`\`mermaid
graph TD
    A[User / Adversarial Prompt Payload] --> B{Input Guardrail Filter}
    B -- Injection Signature Detected --> C[Block & Return Incident Notice]
    B -- Safe Prompt --> D[Target LLM: Ollama / Qwen 2.5]
    D --> E{Output Guardrail Scanner}
    E -- Restricted Token Leak Detected --> F[Block Output & Log Incident]
    E -- Safe Response --> G[Return Verified Response]
\`\`\`

---

## ✨ Key Features

* **Dual-Path Security Benchmarking**: Simultaneously evaluates raw model responses against guarded pipelines to measure defense mitigation efficacy.
* **OWASP LLM (2026) Threat Taxonomy Mapping**: Covers primary risk vectors including \`LLM01: Prompt Injection\`, \`LLM02: Sensitive Information Disclosure\`, \`LLM03: Excessive Agency\`, and \`LLM08: Hidden Context Exposure\`.
* **Multi-Turn Context Drift Probing**: Simulates multi-step adversarial dialogues to catch gradual context manipulation and privilege escalation over long sessions.
* **Interactive Streamlit Dashboard**: Provides real-time interactive probing sandboxes, Plotly defense analytics, and CSV security report exporters.
* **Automated CI/CD Pipeline**: Integrated GitHub Actions workflow running headless security regression testing on every repository push and pull request.
* **Offline & CI Resilience**: Built-in mock LLM fallback layer ensuring automated security pipeline checks succeed cleanly in CI environments without requiring live GPU servers.

---

## 🗂️ Repository Structure

\`\`\`text
llm-guardrail/
├── .github/
│   └── workflows/
│       └── security_eval.yml     # Automated CI/CD security pipeline
├── .streamlit/
│   └── config.toml               # Custom cyber dark visual theme
├── data/
│   ├── test_payloads.json        # Core red-teaming test suite
│   └── owasp_2026_payloads.json  # OWASP LLM 2026 threat benchmark payloads
├── src/
│   ├── __init__.py               # Package initializer
│   ├── evaluator.py              # Dual-path evaluation engine & CI fallback
│   ├── guardrails.py             # Heuristic regex input & token output filters
│   └── multi_turn.py             # Multi-turn context-drift evaluator logic
├── app.py                        # Interactive Streamlit dashboard application
├── requirements.txt              # Project dependencies
└── README.md                     # Documentation
\`\`\`

---

## 🛡️ OWASP LLM 2026 Vulnerability Coverage

| Vulnerability ID | OWASP Category (2026) | Defense Strategy |
| :--- | :--- | :--- |
| **LLM01:2026** | Prompt Injection | Pattern signature regex matching & instruction boundary isolation |
| **LLM02:2026** | Sensitive Information Disclosure | Output token matching & systemic prompt leakage scanning |
| **LLM03:2026** | Excessive Agency | Destructive command signature blocking (\`rm -rf\`, raw shell executions) |
| **LLM08:2026** | Hidden Context Exposure | Context isolation & system rule protection verification |

---

## 🚀 Quick Start & Installation

### Prerequisites
* **Python 3.10+**
* **Ollama** (optional, for local LLM execution with \`qwen2.5\`)

### 1. Clone & Set Up Environment

\`\`\`powershell
# Clone repository
git clone https://github.com/vexilen-01/llm-guardrail.git
cd llm-guardrail

# Create and activate virtual environment
python -m venv venv
.\\venv\\Scripts\\Activate.ps1
\`\`\`

\`\`\`powershell
# Install dependencies
pip install -r requirements.txt
\`\`\`

### 2. Launch Local LLM (Optional)
If running Ollama locally:
\`\`\`powershell
ollama pull qwen2.5
ollama run qwen2.5
\`\`\`
*(Note: If Ollama is offline, the suite automatically falls back to internal mock model responses for seamless execution.)*

### 3. Run the Dashboard
\`\`\`powershell
streamlit run app.py
\`\`\`
Open \`http://localhost:8501\` in your browser to interact with the security suite.

---

## ⚙️ Automated CI/CD Regression Audit

This project includes a **GitHub Actions** pipeline configured in \`.github/workflows/security_eval.yml\`. On every **push** or **pull_request** to **main**, the runner automatically executes a headless security audit to ensure that defense rules maintain a 100% pass rate before code merges.

## 📄 License

Distributed under the MIT License. See \`LICENSE\` for more information.
'''

with open('README.md', 'w', encoding='utf-8') as f:
    f.write(content)
print('README.md generated successfully!')
"