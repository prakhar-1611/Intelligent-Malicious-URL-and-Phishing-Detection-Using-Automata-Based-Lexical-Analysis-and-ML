# Security design of the detector itself

Owner: Prakhar Tandon (24BCI0222)

The detector handles attacker-controlled input by design, so it has to be safe to run.

## Safe handling of malicious data

| Rule | Where it is enforced |
|---|---|
| A submitted URL is never resolved, fetched or redirected to | No HTTP client in `api/`, `lexer/`, `security/`, `ml/features.py`; only `ml/data_pipeline.py` downloads the public *lists* |
| URLs are shown defanged (`hxxp`, `[.]`, `[@]`) | `security/defang.py`, `url_defanged` in every API response |
| The UI renders URLs as text only, never as `<a href>` | `web/src/components/common.tsx` (`SafeText`, `HighlightedUrl`) |
| Logs never contain a live URL | `api/security.py: log_verdict` writes the defanged URL and a salted hash of the client IP |
| Adversarial IP mutations use RFC 5737 TEST-NET addresses | `adversarial/mutate.py: op_ip_form` |

## API hardening

* **Input caps** (Pydantic): URL ≤ 2048 characters, batch ≤ 500 URLs, email ≤ 1 MB, custom regex ≤ 120 characters.
* **Construction blow-up guard**: user-typed regexes in the Automata Lab stop at 400 DFA / 600 NFA states (`StateExplosion`).
* **Rate limiting**: slowapi, `RATE_LIMIT` (default `60/minute`) per client, tighter on batch, email and custom-regex routes.
* **CORS allowlist**: `ALLOWED_ORIGINS` (default the local Vite dev server only), GET/POST only, no credentials.
* **Security headers**: `nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `default-src 'none'` CSP on API responses, `no-store`.
* **Path traversal**: `/results/figures/{name}` accepts only a bare `*.png` name.
* **No ReDoS**: the scanner is a DFA (one table lookup per character, see `bench/redos.py`). The engine does not use Python's `re`; CI fails if `import re` appears outside `tests/` and `bench/`.

## STRIDE

| Threat | Example against this app | Mitigation |
|---|---|---|
| **S**poofing | Forged client identity to dodge rate limits | Per-IP limits; no auth secrets are stored; the API is read-only |
| **T**ampering | Modified `lexer_tables.json` / `model.joblib` changes verdicts | Artifacts are rebuilt from source (`build_automata`, `train`); joblib files are only loaded from the local `artifacts/` directory, never from user input |
| **R**epudiation | Denying that a malicious URL was submitted | Append-only JSON-lines security log of every Malicious verdict (defanged URL, time, hashed client) |
| **I**nformation disclosure | Leaking stack traces or file paths | FastAPI validation errors only; figure names validated; client IPs hashed in logs |
| **D**enial of service | Catastrophic-backtracking input; huge batch; regex state explosion | DFA scanning is linear; size caps; rate limits; subset-construction state cap |
| **E**levation of privilege | SSRF via the URL field; XSS via a URL rendered in the UI | No fetching at all (no SSRF surface); React escapes text and URLs are never links |

## Known limits

* Rate limiting is in-memory (per process); a multi-instance deployment needs a shared store (Redis).
* `joblib` deserialisation executes code: only load model files you built yourself.
