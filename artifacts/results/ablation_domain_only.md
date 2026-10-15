| Config | Feature groups | #features | CV PR-AUC (5-fold grouped) | Test PR-AUC | Test F1 | Test FPR |
|---|---|---|---|---|---|---|
| A_lexical | lexical | 14 | 0.9312 ± 0.0154 | 0.8954 | 0.8064 | 0.0317 |
| B_lexical+domain | lexical, domain | 28 | 0.9528 ± 0.0091 | 0.9234 | 0.8402 | 0.0234 |
| C_+automata | lexical, domain, automata | 161 | 0.9528 ± 0.0095 | 0.9232 | 0.8375 | 0.0231 |
| D_all | lexical, domain, encoding, automata, path_query, symtab | 187 | 0.9250 ± 0.0488 | 0.9222 | 0.8296 | 0.0235 |
