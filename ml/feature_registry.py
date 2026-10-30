"""Feature registry: every feature knows which tokens, lexemes, flags or DFA
states it was computed from, so an explanation can point back at the input.

Author: Ishitwo Khanra (24BCE2975)

    SHAP says "auto_visit_g41 pushed the score up"
      -> registry: that feature counts visits to global min-DFA state 41
      -> trace: state 41 was visited at characters 20..25
      -> UI highlights those characters and the state in the Live Trace graph
"""
from __future__ import annotations

from dataclasses import dataclass, field

from core.types import ScanResult

GROUPS = ["lexical", "domain", "encoding", "automata", "path_query", "symtab"]

# ablation configurations (ablation.py)
ABLATION = {
    "A_lexical": ["lexical"],
    "B_lexical+domain": ["lexical", "domain"],
    "C_+automata": ["lexical", "domain", "automata"],
    "D_all": GROUPS,
}


@dataclass
class FeatureSpec:
    name: str
    group: str
    description: str
    token_types: tuple[str, ...] = ()
    lexeme_types: tuple[str, ...] = ()
    flags: tuple[str, ...] = ()
    state: int | None = None  # global min-DFA state id (visit-count features)
    whole_url: bool = False
    meta: dict = field(default_factory=dict)


def _runs(positions: list[int]) -> list[tuple[int, int]]:
    out: list[tuple[int, int]] = []
    for p in sorted(positions):
        if out and out[-1][1] == p:
            out[-1] = (out[-1][0], p + 1)
        else:
            out.append((p, p + 1))
    return out


def evidence(spec: FeatureSpec, scan: ScanResult, text: str) -> dict:
    """Spans of the input (and DFA states / flags) that a feature was computed from."""
    spans: list[tuple[int, int]] = []
    states: list[int] = []
    flags: list[str] = []
    if spec.whole_url:
        spans.append((0, len(text)))
    for t in scan.tokens:
        if t.type in spec.token_types:
            spans.append((t.start, t.end))
    for lx in scan.lexemes:
        if lx.type in spec.lexeme_types:
            spans.append((lx.start, lx.end))
    for f in scan.flags:
        if f.code in spec.flags:
            spans.append((f.start, f.end))
            flags.append(f.code)
    if spec.state is not None:
        states.append(spec.state)
        spans.extend(_runs([i for i, g in enumerate(scan.trace) if g == spec.state]))
    if spec.group == "automata" and spec.name in ("n_anomaly_state_visits", "n_distinct_anomaly_states"):
        anomalous = [s["i"] for s in scan.steps if s.get("anomaly")]
        spans.extend(_runs(anomalous))
        states.extend(sorted({s["g"] for s in scan.steps if s.get("anomaly")}))
    uniq = sorted(set(spans))
    return {"spans": [{"start": a, "end": b, "text": text[a:b]} for a, b in uniq][:12],
            "states": sorted(set(states)), "flags": sorted(set(flags))}


def build_registry(state_meta: list[dict]) -> list[FeatureSpec]:
    from lexer.rules import EMAIL_FLAGS, SEVERITY, UNTRAINED_FLAGS

    S = FeatureSpec
    host_tokens = ("SUBDOMAIN", "BASE_DOMAIN", "TLD", "IP_HOST")
    reg: list[FeatureSpec] = [
        # ---------------- lexical statistics
        S("url_len", "lexical", "Total URL length", whole_url=True),
        S("n_tokens", "lexical", "Number of high-level tokens", whole_url=True),
        S("avg_token_len", "lexical", "Average token length", whole_url=True),
        S("max_token_len", "lexical", "Longest token length", whole_url=True),
        S("n_digits", "lexical", "Digit count", whole_url=True),
        S("digit_ratio", "lexical", "Digits / length", whole_url=True),
        S("letter_ratio", "lexical", "Letters / length", whole_url=True),
        S("upper_ratio", "lexical", "Upper-case letters / length", whole_url=True),
        S("special_ratio", "lexical", "Non-alphanumeric characters / length", whole_url=True),
        S("n_delims", "lexical", "Count of . / ? = & - _ @ ~ %", whole_url=True),
        S("entropy", "lexical", "Shannon entropy of the characters", whole_url=True),
        S("n_nonascii", "lexical", "Non-ASCII characters", whole_url=True),
        S("n_sus_words", "lexical", "Phishing keywords (login, verify, secure, ...)", whole_url=True),
        S("is_https", "lexical", "Scheme is https", token_types=("SCHEME",)),
        # ---------------- domain structure
        S("host_len", "domain", "Host length", token_types=host_tokens),
        S("n_labels", "domain", "Number of domain labels", token_types=host_tokens),
        S("n_subdomains", "domain", "Number of subdomain labels", token_types=("SUBDOMAIN",)),
        S("max_label_len", "domain", "Longest domain label", token_types=host_tokens),
        S("mean_label_len", "domain", "Mean domain label length", token_types=host_tokens),
        S("is_ip_host", "domain", "Host is an IP address", token_types=("IP_HOST",)),
        S("tld_len", "domain", "Public suffix length", token_types=("TLD",)),
        S("tld_category", "domain", "0 common gTLD, 1 ccTLD, 2 new gTLD, 3 often-abused, 4 none",
          token_types=("TLD",)),
        S("n_hyphens_host", "domain", "Hyphens in host", token_types=host_tokens),
        S("n_digits_host", "domain", "Digits in host", token_types=host_tokens),
        S("base_len", "domain", "Registered-domain label length", token_types=("BASE_DOMAIN",)),
        S("has_port", "domain", "Explicit port", token_types=("PORT",)),
        S("has_userinfo", "domain", "userinfo@ before the host", token_types=("USERINFO",)),
        S("www_prefix", "domain", "Host starts with www", token_types=("SUBDOMAIN",)),
        # ---------------- encoding / obfuscation
        S("n_pct", "encoding", "Percent-encoded bytes", lexeme_types=("PCT_ENC", "DOUBLE_ENC")),
        S("pct_ratio", "encoding", "Encoded bytes / length", lexeme_types=("PCT_ENC", "DOUBLE_ENC")),
        S("n_double_enc", "encoding", "Double-encoded bytes (%25xx)", lexeme_types=("DOUBLE_ENC",)),
        S("n_pct_host", "encoding", "Percent-encoding inside the host", token_types=host_tokens),
        S("n_nonascii_host", "encoding", "Non-ASCII characters in host", token_types=host_tokens),
        S("n_puny_labels", "encoding", "xn-- labels", lexeme_types=("PUNY_LABEL",)),
        S("n_ctrl", "encoding", "Control characters", lexeme_types=("CTRL",)),
        S("n_error_tokens", "encoding", "Characters no rule matched (panic-mode ERROR)", token_types=("ERROR",)),
        # ---------------- automata
        S("n_anomaly_state_visits", "automata", "Characters consumed in anomaly states"),
        S("n_distinct_anomaly_states", "automata", "Distinct anomaly DFA states reached"),
        S("state_entropy", "automata", "Entropy of the state-visit distribution", whole_url=True),
        S("transition_entropy", "automata", "Entropy of the (state, next state) pairs", whole_url=True),
        S("n_distinct_states", "automata", "Distinct min-DFA states visited", whole_url=True),
        S("dead_state_hits", "automata", "Times the scanner hit the dead state with no match", token_types=("ERROR",)),
        S("backtracked_chars", "automata", "Characters re-scanned after maximal-munch backup", whole_url=True),
        S("n_mode_switches", "automata", "Lexer mode changes", whole_url=True),
        S("n_flags_dfa", "automata", "Flags raised by DFA anomaly states"),
        S("n_flags_attr", "automata", "Flags raised by attribute checks"),
        S("flag_severity_sum", "automata", "Sum of flag severities"),
    ]
    for code in SEVERITY:
        if code.startswith("S_") and code not in EMAIL_FLAGS | UNTRAINED_FLAGS:
            reg.append(S("flag_" + code[2:].lower(), "automata", f"Flag {code} raised", flags=(code,)))
    reg += [
        # ---------------- path / query
        S("path_len", "path_query", "Path length", token_types=("PATH",)),
        S("path_depth", "path_query", "Number of '/' in the path", token_types=("PATH",)),
        S("max_seg_len", "path_query", "Longest path segment", token_types=("PATH",)),
        S("has_dslash", "path_query", "'//' inside the path", lexeme_types=("DSLASH",)),
        S("file_ext_risky", "path_query", "Path ends in .exe/.php/.zip/.apk/...", token_types=("PATH",)),
        S("n_params", "path_query", "Query parameters", token_types=("QUERY_PARAM",)),
        S("query_len", "path_query", "Total query length", token_types=("QUERY_PARAM",)),
        S("max_param_val_len", "path_query", "Longest parameter value", token_types=("QUERY_PARAM",)),
        S("has_fragment", "path_query", "Fragment present", token_types=("FRAGMENT",)),
        S("frag_len", "path_query", "Fragment length", token_types=("FRAGMENT",)),
        S("url_in_path_or_query", "path_query", "Embedded http(s):// after the authority",
          token_types=("PATH", "QUERY_PARAM")),
        # ---------------- symbol table / corpus
        S("base_label_rarity", "symtab", "Corpus rarity of the registered-domain label", token_types=("BASE_DOMAIN",)),
        S("max_label_rarity", "symtab", "Rarest host label", token_types=host_tokens),
        S("mean_label_rarity", "symtab", "Mean host-label rarity", token_types=host_tokens),
        S("brand_in_subdomain", "symtab", "A brand name is a subdomain label", token_types=("SUBDOMAIN",)),
        S("brand_in_path", "symtab", "A brand name appears in the path or query", token_types=("PATH", "QUERY_PARAM")),
        S("brand_is_base", "symtab", "Registered domain is a known brand", token_types=("BASE_DOMAIN",)),
        S("n_symbols", "symtab", "Distinct symbols in the URL symbol table", whole_url=True),
    ]
    for st in state_meta:
        tag = f" (accepts {st['accept']})" if st["accept"] else ""
        reg.append(S(f"auto_visit_g{st['g']}", "automata",
                     f"Visits to {st['mode']} state M{st['state']}{tag}, per character",
                     state=st["g"], meta={"mode": st["mode"], "local": st["state"], "accept": st["accept"]}))
    return reg
