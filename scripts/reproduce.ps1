# Reproduce every Review 2 result from scratch (Windows PowerShell).
# Usage:  .\scripts\reproduce.ps1            (run from the repository root, venv activated)
$ErrorActionPreference = "Stop"
$env:PYTHONIOENCODING = "utf-8"

python -m lexer.build_automata                      # offline: regex -> NFA -> DFA -> min-DFA tables
python -m lexer.export                              # DOT files for every rule and stage
python -m ml.email_links --enron-sample 100000     # benign links from legitimate mail (Enron + SpamAssassin ham in data/raw/email_ham/)
python -m ml.data_pipeline --download --tranco-top 60000 --benign-urls data/raw/email_ham_urls.txt
python -m ml.train                                  # LR / RF / LightGBM / XGBoost, calibration, thresholds
python -m ml.train --domain-only                    # path-bias control
python -m ml.ablation
python -m ml.ablation --domain-only
python -m ml.explain
python -m ml.explain --domain-only
python -m adversarial.evaluate --n 1000
python -m bench.latency --n 1000
python -m bench.redos
pytest -q
