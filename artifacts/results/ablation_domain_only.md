| Config | Feature groups | #features | CV PR-AUC (5-fold grouped) | Test PR-AUC | Test F1 | Test FPR |
|---|---|---|---|---|---|---|
| A_lexical | lexical | 14 | 0.9281 ± 0.0154 | 0.8932 | 0.7989 | 0.0308 |
| B_lexical+domain | lexical, domain | 28 | 0.9497 ± 0.0100 | 0.9206 | 0.8366 | 0.0232 |
| C_+automata | lexical, domain, automata | 161 | 0.9502 ± 0.0101 | 0.92 | 0.8339 | 0.0231 |
| D_all | lexical, domain, encoding, automata, path_query, symtab | 187 | 0.9276 ± 0.0455 | 0.9211 | 0.8277 | 0.022 |
