| Operator | Expected flag | Applied | Flag recall | Evasion rate | Mean Δscore |
|---|---|---|---|---|---|
| percent_encoding | S_PCT_ENCODE | 1000 | 1.0 | 0.0308 | -0.0113 |
| double_encoding | S_DOUBLE_ENCODE | 1000 | 1.0 | 0.0092 | 0.0109 |
| homoglyph_swap | S_MIXED_SCRIPT | 844 | 0.936 | 0.0 | 0.0074 |
| punycode | S_PUNY_DETECT | 844 | 1.0 | 0.0037 | 0.0067 |
| subdomain_insertion | S_SUBDOMAIN_DEPTH | 1000 | 1.0 | 0.0 | 0.0375 |
| at_injection | S_AT_ABUSE | 1000 | 1.0 | 0.0 | 0.0266 |
| ip_form | S_IP_OBFUSCATED | 1000 | 1.0 | 0.0 | 0.0167 |
| port_insertion | S_PORT_ANOMALY | 879 | 1.0 | 0.0012 | 0.0234 |
| case_toggle | — | 850 | — | 0.0 | 0.0311 |
| dslash_injection | S_REDIRECT_ABUSE | 1000 | 1.0 | 0.0 | 0.0144 |
