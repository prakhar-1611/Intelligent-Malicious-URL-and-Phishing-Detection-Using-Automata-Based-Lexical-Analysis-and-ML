| Config | Feature groups | #features | CV PR-AUC (5-fold grouped) | Test PR-AUC | Test F1 | Test FPR |
|---|---|---|---|---|---|---|
| A_lexical | lexical | 14 | 0.9333 ± 0.0520 | 0.8526 | 0.5273 | 0.0727 |
| B_lexical+domain | lexical, domain | 28 | 0.9680 ± 0.0229 | 0.8573 | 0.5535 | 0.0396 |
| C_+automata | lexical, domain, automata | 161 | 0.9739 ± 0.0094 | 0.9233 | 0.6222 | 0.0248 |
| D_all | lexical, domain, encoding, automata, path_query, symtab | 187 | 0.9588 ± 0.0159 | 0.9949 | 0.9676 | 0.0194 |
