| Operator | Expected flag | Applied | Flag recall | Evasion rate | Mean Δscore |
|---|---|---|---|---|---|
| percent_encoding | S_PCT_ENCODE | 1000 | 1.0 | 0.0308 | -0.0253 |
| double_encoding | S_DOUBLE_ENCODE | 1000 | 1.0 | 0.0195 | 0.002 |
| homoglyph_swap | S_MIXED_SCRIPT | 844 | 0.936 | 0.0 | 0.0183 |
| punycode | S_PUNY_DETECT | 844 | 1.0 | 0.0012 | 0.0354 |
| subdomain_insertion | S_SUBDOMAIN_DEPTH | 1000 | 1.0 | 0.0 | 0.0482 |
| at_injection | S_AT_ABUSE | 1000 | 1.0 | 0.0 | 0.0339 |
| ip_form | S_IP_OBFUSCATED | 1000 | 1.0 | 0.0492 | -0.06 |
| port_insertion | S_PORT_ANOMALY | 879 | 1.0 | 0.0 | 0.0368 |
| case_toggle | — | 850 | — | 0.0 | 0.0276 |
| dslash_injection | S_REDIRECT_ABUSE | 1000 | 1.0 | 0.0 | 0.0144 |
