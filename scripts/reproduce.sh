#!/usr/bin/env bash
# Reproduce every Review 2 result from scratch (Linux / macOS / Git Bash).
# Usage:  bash scripts/reproduce.sh          (run from the repository root, venv activated)
set -euo pipefail
export PYTHONIOENCODING=utf-8

python -m lexer.build_automata
python -m lexer.export
python -m ml.data_pipeline --download --tranco-top 60000
python -m ml.train
python -m ml.train --domain-only
python -m ml.ablation
python -m ml.ablation --domain-only
python -m ml.explain
python -m ml.explain --domain-only
python -m adversarial.evaluate --n 1000
python -m bench.latency --n 1000
python -m bench.redos
pytest -q
