# Contribution table (Review 2)

Every module header names its author. Each member demos and answers questions on their own modules.

| Member | Compiler stage | Domain work | Files | Report sections |
|---|---|---|---|---|
| **Prakhar Tandon** (24BCI0222), Cybersecurity | Regex parser (tokenize → explicit concat → shunting-yard → AST, positioned syntax errors), Thompson NFA, lexical specification | 13 anomaly flags (7 DFA-state, 6 attribute), IP/IDN decoders, confusables skeleton, email header lexer, adversarial mutation engine, ReDoS benchmark, API hardening, STRIDE | `lexer/regex_parser.py`, `lexer/thompson.py`, `lexer/rules.py`, `lexer/email_lexer.py`, `security/*`, `adversarial/*`, `bench/redos.py`, `api/security.py`, `tests/test_flags.py`, `tests/test_email.py`, `tests/test_regex_parser.py`, `tests/test_security_modules.py`, `docs/SECURITY.md` | 3.4, 4.1, 4.4, 4.7, 5.4, 5.5 |
| **Ishitwo Khanra** (24BCE2975), AIML | Subset construction (bitmask sets, worklist, explicit dead state, priority resolution), symbol tables, equivalence testing | Data pipeline (domain + time split, bias control), ~190 features in 6 groups, feature registry, LR/RF/LightGBM/XGBoost, isotonic calibration and thresholds, SHAP → tokens/states, ablation, latency | `lexer/subset.py`, `lexer/symtab.py`, `ml/*`, `bench/latency.py`, `tests/test_equivalence.py`, `tests/test_golden_tokens.py` | 4.2, 4.5, 5.1, 5.2, 5.3, 5.6 |
| **Amrita Bhatia** (24BCI0215), Frontend | Hopcroft minimisation (token-type initial partition), Moore cross-check, alphabet compression, table-driven scanner (maximal munch, modes, panic mode, state path), offline build + export | FastAPI service, React dashboard (Analyze, Explain, Automata Lab, Live Trace, Batch, Results) | `lexer/hopcroft.py`, `lexer/moore.py`, `lexer/alphabet.py`, `lexer/scanner.py`, `lexer/build_automata.py`, `lexer/export.py`, `api/main.py`, `web/*`, `tests/test_scanner.py`, `tests/test_api.py` | 4.3, 4.6, 4.8, architecture figure |
| Joint | `core/types.py` (shared interfaces) | | | Ch. 6, contribution table |

Signatures:

Prakhar Tandon ______________  Ishitwo Khanra ______________  Amrita Bhatia ______________
