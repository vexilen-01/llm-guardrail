# LLM Guardrail & Red-Teaming Suite

An automated security evaluation and defense benchmarking platform for local Large Language Models (Ollama / Qwen 2.5).

## Features
* **Dual-Path Security Benchmarking**: Stress-tests unfiltered baseline responses against guardrail-protected outputs.
* **OWASP LLM (2026) Coverage**: Probes prompt injection, sensitive data disclosure, and context drift.
* **Streamlit Dashboard**: Real-time evaluation interface with Plotly charts and report exporters.
* **Automated CI/CD**: GitHub Actions pipeline for continuous security regression testing.

## Quick Start

### 1. Clone & Setup Enviornment
```powershell
git clone https://github.com/vexilen-01/llm-guardrail.git
cd llm-guardrail
```
### 2. Create and activate Virtual Enviornment
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```
### 3. Install Dependencies
```powershell
pip install -r requirements.txt
```
### 2. Run the App
```powershell
streamlit run app.py
```
## 🗂️ Repository Structure

```text
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
```
## License
MIT License
