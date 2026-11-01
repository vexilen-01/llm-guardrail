# LLM Guardrail & Red-Teaming Suite

An automated security evaluation and defense benchmarking platform for local Large Language Models (Ollama / Qwen 2.5).

## Features
* **Dual-Path Security Benchmarking**: Stress-tests unfiltered baseline responses against guardrail-protected outputs.
* **OWASP LLM (2026) Coverage**: Probes prompt injection, sensitive data disclosure, and context drift.
* **Streamlit Dashboard**: Real-time evaluation interface with Plotly charts and report exporters.
* **Automated CI/CD**: GitHub Actions pipeline for continuous security regression testing.

## Quick Start

### 1. Installation
git clone https://github.com/vexilen-01/llm-guardrail.git  
cd llm-guardrail  
python -m venv venv  
.\venv\Scripts\Activate.ps1  
pip install -r requirements.txt  

### 2. Run the App
streamlit run app.py

## Repository Structure
- app.py: Streamlit web interface
- src/evaluator.py: Dual-path evaluation engine
- src/guardrails.py: Regex input & output token filters
- src/multi_turn.py: Context-drift test evaluator
- data/test_payloads.json: Adversarial test suite
- .github/workflows/security_eval.yml: CI/CD workflow

## License
MIT License
