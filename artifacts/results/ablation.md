| Config | Feature groups | #features | CV PR-AUC (5-fold grouped) | Test PR-AUC | Test F1 | Test FPR |
|---|---|---|---|---|---|---|
| A_lexical | lexical | 14 | 0.9166 ± 0.0595 | 0.8491 | 0.5162 | 0.0713 |
| B_lexical+domain | lexical, domain | 28 | 0.9679 ± 0.0214 | 0.8864 | 0.5275 | 0.0367 |
| C_+automata | lexical, domain, automata | 161 | 0.9768 ± 0.0118 | 0.9277 | 0.5835 | 0.0244 |
| D_all | lexical, domain, encoding, automata, path_query, symtab | 187 | 0.9433 ± 0.0501 | 0.9925 | 0.9643 | 0.0226 |
