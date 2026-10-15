# Intelligent Malicious URL & Phishing Detection via Automata-Based Lexical Analysis

A phishing and malicious-URL detection system where **compiler lexical analysis is the first and most
security-sensitive stage**. Instead of generic string splitting, URLs and email headers are scanned by a
custom lexer built from formal regular definitions:

**Regex → Thompson NFA → Subset-construction DFA → Hopcroft-minimized DFA → table-driven scanner**

The scanner emits typed tokens, a symbol table, and **security-aware anomaly flags** (punycode/IDN,
mixed-script homoglyphs, percent/double encoding, IP-host obfuscation, `@` and `//` delimiter abuse,
control bytes, excessive subdomains). These, together with automata-derived features such as DFA
state-visit statistics, feed a gradient-boosted classifier. The classifier's score is mapped to a
Safe / Suspicious / Malicious verdict, with explanations that point back to the exact tokens and
DFA states involved.

> BCSE307P Compiler Design Lab, School of Computer Science and Engineering, VIT Vellore.
> Guide: Nithya K, Assistant Professor Senior Grade II.

### Highlights
- **Pure automata engine.** No `re` inside the lexer (CI enforces it); Python's `re` is used only as a test oracle.
  Property-based tests check that L(regex) = L(NFA) = L(DFA) = L(minDFA) = L(Moore-minDFA) for every rule.
- **Linear-time, ReDoS-resistant scanning.** One DFA transition per input character, with no backtracking regex.
- **Explainable ML.** Logistic Regression, Random Forest, LightGBM and XGBoost with isotonic calibration and
  thresholds chosen on validation data. SHAP contributions are mapped back to the tokens and states they came from.
- **Adversarial evaluation.** A mutation engine applies encoding, homoglyph, subdomain-insertion, `@`-injection
  and IP-obfuscation evasions and measures what the lexer catches and what slips past the model.
- **Glass-box dashboard.** A React UI shows token highlighting, step-by-step NFA/DFA construction, and a live
  animation of the scanner's path through the minimal DFA.
- **Safe by design.** The system never fetches or resolves URLs, and all URLs are displayed defanged.

---

## Pipeline

```
 raw URL / email
      │
      ▼  Tier 1 — compiler (lexer/)
 regex_parser ─► thompson ─► subset ─► alphabet ─► hopcroft (≡ moore) ─► lexer_tables.json   [offline]
                                                                              │
 scanner: maximal munch · rule priority · 5 lexer modes · panic-mode ERROR · state trace   [runtime, O(m)]
      │  tokens + lexemes + flags (DFA states + attribute checks) + symbol table + trace
      ▼  Tier 2 — features (ml/features.py, ml/feature_registry.py)
 6 groups: lexical · domain · encoding · automata (incl. per-state visit vector) · path/query · symbol table
      ▼  Tier 3 — model (ml/train.py, ml/calibrate.py)
 LightGBM / XGBoost / RF / LR → isotonic calibration → thresholds at FPR ≤ 1 % / ≤ 5 %
      ▼  Tier 4 — policy + explanation (api/, ml/explain.py, web/)
 Safe / Suspicious / Malicious + SHAP → features → tokens/spans → min-DFA states
```

### Lexer modes (flex-style start conditions, RFC 3986 order)

| Mode | Rules (priority) | Anomaly accept states |
|---|---|---|
| START | `SCHEME` (50), `SCHEME_OPAQUE` (40), `CTRL` | `S_CONTROL_ANOMALY` |
| AUTHORITY | `HOST_LABEL` (10), `PUNY_LABEL` (30), `IPV4`/`IPV6` (30), `PORT` (20), `AT` (30), `DOT`, `COLON`, `DSLASH`, `SLASH`, `QMARK`, `HASH`, `PCT_ENC`, `DOUBLE_ENC`, `CTRL` | `S_PUNY_DETECT`, `S_IP_HOST`, `S_AT_ABUSE`, `S_REDIRECT_ABUSE`, `S_PCT_ENCODE`, `S_DOUBLE_ENCODE`, `S_CONTROL_ANOMALY` |
| PATH | `PATH_SEG`, `SLASH`, `DSLASH` (20), `QMARK`, `HASH`, `PCT_ENC`, `DOUBLE_ENC`, `CTRL` | `S_REDIRECT_ABUSE`, `S_PCT_ENCODE`, `S_DOUBLE_ENCODE`, `S_CONTROL_ANOMALY` |
| QUERY | `QTEXT`, `EQ`, `AMP`, `HASH`, `PCT_ENC`, `DOUBLE_ENC`, `CTRL` | encoding + control |
| FRAGMENT | `FTEXT`, `PCT_ENC`, `DOUBLE_ENC`, `CTRL` | encoding + control |

Flags that a regular language cannot express are **attribute checks** after lexing and are labelled `source: "attr"`:
`S_PORT_ANOMALY` (allowlist), `S_SUBDOMAIN_DEPTH` (threshold), `S_MIXED_SCRIPT` (Unicode scripts),
`S_IP_OBFUSCATED` (decimal/hex/octal IPv4 arithmetic), `S_OPEN_REDIRECT_PARAM`, `S_HOMOGLYPH` (TS #39 skeleton vs brands).
The email lexer adds `S_FROM_REPLYTO_MISMATCH`, `S_RETURNPATH_MISMATCH`, `S_DISPLAYNAME_SPOOF`.

---

## Quick start

Requirements: Python 3.11+ (tested on 3.13), Node.js 20+.

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate      Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt

python -m lexer.build_automata        # offline construction -> artifacts/lexer_tables.json
pytest -q                             # 530 tests: equivalence, golden tokens, flags, scanner, email, API
```

Run the demo (two terminals):

```bash
uvicorn api.main:app --port 8000      # API (uses a heuristic until a model is trained)
cd web && npm install && npm run dev  # dashboard at http://localhost:5173
```

Train on real data and regenerate every result (downloads PhishTank, URLhaus, OpenPhish, Tranco and Hacker News link lists; no listed URL is ever visited):

```bash
bash scripts/reproduce.sh             # or  .\scripts\reproduce.ps1  on Windows
```

| Command | Output |
|---|---|
| `python -m ml.data_pipeline --download` | `data/processed/dataset.csv`, `dataset_stats.json` |
| `python -m ml.train [--domain-only]` | `artifacts/model.joblib`, `results/model_comparison*.json` |
| `python -m ml.ablation [--domain-only]` | `results/ablation*.json/.md` |
| `python -m ml.explain [--domain-only]` | `results/shap_global*.json`, `figures/shap_global*.png` |
| `python -m adversarial.evaluate` | `results/adversarial.json/.md` |
| `python -m bench.redos` | `results/redos.json`, `figures/redos.png` |
| `python -m bench.latency` | `results/latency.json`, `figures/scaling.png` |
| `python -m lexer.export` | `artifacts/dot/*.dot` (render with Graphviz) |

## API

| Method | Path | Purpose |
|---|---|---|
| POST | `/analyze` `{url}` | verdict, score, tokens, flags, trace, steps, symbol table, `explanation[]` |
| POST | `/analyze/batch` `{urls}` | up to 500 URLs |
| POST | `/analyze/email` `{raw}` | header tokens, address checks, flags, scanned body URLs |
| GET | `/automata/{rule}?stage=nfa\|dfa\|min` | graph JSON for any rule, Review 1 example, or `mode:<MODE>` |
| POST | `/automata/custom` `{pattern, stage}` | build any regex live (blow-up guarded) |
| GET | `/scanner/states` | minimal DFA of every mode (Live Trace) |
| GET | `/results`, `/results/figures/{name}` | experiment results |
| GET | `/health` | status |

Hardening (details and STRIDE in [docs/SECURITY.md](docs/SECURITY.md)): 2048-character URL cap, Pydantic
validation, slowapi rate limits, CORS allowlist, security headers, defanged security log, and no URL is ever fetched (no SSRF surface).

## Dashboard pages

| Page | What it shows |
|---|---|
| **Analyze** | verdict gauge, colour-coded token chips, flags highlighted inside the URL, symbol table |
| **Explain** | SHAP bar chart; clicking a feature highlights the characters and DFA states it came from |
| **Automata Lab** | any rule or custom regex: syntax tree/postfix → Thompson NFA → subset DFA → minimal DFA, with state counts |
| **Live Trace** | the scanner animated one character at a time over the minimal DFA; anomaly states turn red |
| **Batch** | CSV upload, summary charts, defanged CSV export |
| **Results** | model comparison, ROC, policy confusion, ablation, adversarial, latency, ReDoS figures (read from JSON) |

## Repository layout

```
core/types.py                  shared interfaces (NFA, DFA, Token, Flag, ScanResult)        [joint]
lexer/  regex_parser.py thompson.py rules.py email_lexer.py                               [Prakhar]
        subset.py symtab.py                                                               [Ishitwo]
        hopcroft.py moore.py alphabet.py scanner.py build_automata.py export.py           [Amrita]
security/ anomaly.py ip_decode.py idn.py defang.py                                        [Prakhar]
adversarial/ mutate.py evaluate.py        bench/ redos.py [Prakhar]  latency.py [Ishitwo]
ml/     data_pipeline.py features.py feature_registry.py train.py calibrate.py metrics.py
        explain.py ablation.py                                                            [Ishitwo]
api/    main.py [Amrita]  security.py [Prakhar]
web/    React + TypeScript + Vite + Tailwind + Cytoscape.js                               [Amrita]
tests/  test_equivalence.py test_golden_tokens.py [I]  test_flags.py test_email.py
        test_regex_parser.py test_security_modules.py [P]  test_scanner.py test_api.py [A]
docs/   SECURITY.md CONTRIBUTIONS.md WORKLOG.md
```

## Data and honesty notes

- **Sources:** PhishTank (verified phishing) and URLhaus (malware URLs) with timestamps, the OpenPhish community feed,
  Tranco top sites, and Hacker News story links via the public Algolia API (real benign URLs *with paths*).
- **Leakage control:** split by registered domain (no domain in two splits); the test set holds malicious domains
  *first seen* after the 80th percentile of first-seen time, so it measures detection of future campaigns.
- **Known bias:** Tranco gives bare domains while feeds give full URLs, so "has a path" leaks the label.
  Hacker News links reduce the gap, and `--domain-only` re-runs everything on `scheme://host/` only, where
  the shortcut is impossible. Both result sets are reported.
- **Limitations:** Hacker News links skew towards tech and news sites; the curated confusables table and
  public-suffix list are subsets of the Unicode and PSL originals; flags are evidence, not verdicts.

## Team

| Member | Role |
|---|---|
| Prakhar Tandon (24BCI0222) | Regex parser, Thompson NFA, security states, email lexer, adversarial testing |
| Ishitwo Khanra (24BCE2975) | Subset construction, symbol table, equivalence testing, dataset, ML and explainability |
| Amrita Bhatia (24BCI0215) | Hopcroft minimization, runtime scanner, API, web dashboard and visualizer |

*Guide: Nithya K, Assistant Professor Senior Grade II, SCOPE, VIT Vellore. Course: BCSE307P Compiler Design Lab.*
