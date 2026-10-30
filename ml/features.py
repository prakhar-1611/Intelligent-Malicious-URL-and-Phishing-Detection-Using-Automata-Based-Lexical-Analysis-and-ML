"""Feature extraction from the scanner output.

Author: Ishitwo Khanra (24BCE2975)

Six groups (Review 1 section 3.2.9): lexical, domain, encoding, automata,
path_query, symtab (corpus symbol table). The automata group contains the
project's main novelty: a fixed-length vector of per-character visit counts
over every state of the minimal DFAs (fixed because the minimal DFA is fixed),
plus anomaly-state hits, state/transition entropy and dead-state hits.

The extractor never reparses the URL: everything comes from tokens, lexemes,
flags, the state trace and the symbol table.
"""
from __future__ import annotations

import math
from collections import Counter

import numpy as np

from core.types import ScanResult
from lexer.rules import UNTRAINED_FLAGS
from lexer.scanner import Scanner, get_scanner
from lexer.symtab import CorpusSymbolTable
from ml.feature_registry import ABLATION, build_registry
from security import idn
from security.anomaly import pct_decode

SUS_WORDS = ("login", "log-in", "signin", "sign-in", "verify", "verification", "secure", "account", "update",
             "banking", "confirm", "password", "webscr", "wp-admin", "wp-includes", "invoice", "billing",
             "unlock", "suspend", "recover", "wallet", "auth", "session", "token", "free", "bonus")
COMMON_GTLD = {"com", "net", "org", "edu", "gov", "mil", "int"}
ABUSED_TLD = {"tk", "ml", "ga", "cf", "gq", "xyz", "top", "club", "online", "site", "icu", "buzz", "click",
              "link", "work", "info", "shop", "rest", "cam", "monster", "cyou", "sbs", "zip", "mov", "live", "ru"}
RISKY_EXT = (".exe", ".php", ".zip", ".rar", ".apk", ".scr", ".js", ".jar", ".bat", ".sh", ".bin", ".msi",
             ".dll", ".vbs", ".ps1", ".doc", ".docm", ".xls", ".xlsm", ".i", ".mips", ".arm7", ".x86")


def _entropy(counter: Counter) -> float:
    n = sum(counter.values())
    if n == 0:
        return 0.0
    return -sum((c / n) * math.log2(c / n) for c in counter.values())


class FeatureExtractor:
    def __init__(self, scanner: Scanner | None = None, corpus: CorpusSymbolTable | None = None):
        self.scanner = scanner or get_scanner()
        self.corpus = corpus
        self.state_meta = self.scanner.state_names()
        self.registry = build_registry(self.state_meta)
        self.names = [s.name for s in self.registry]
        self.index = {n: i for i, n in enumerate(self.names)}
        self.groups = [s.group for s in self.registry]
        self.anomaly_states = {m["g"] for m in self.state_meta if m["anomaly"]}
        self.n_states = len(self.state_meta)
        self.brands = set(idn.brands())

    def columns_for(self, config: str) -> list[int]:
        groups = set(ABLATION[config])
        return [i for i, g in enumerate(self.groups) if g in groups]

    def extract(self, url: str, scan: ScanResult | None = None) -> tuple[np.ndarray, ScanResult]:
        r = scan or self.scanner.scan(url)
        f: dict[str, float] = {}
        n = max(len(url), 1)
        toks = r.tokens
        by_type: dict[str, list] = {}
        for t in toks:
            by_type.setdefault(t.type, []).append(t)
        low = url.lower()

        # ---- lexical
        lens = [len(t.value) for t in toks] or [0]
        f["url_len"] = len(url)
        f["n_tokens"] = len(toks)
        f["avg_token_len"] = sum(lens) / len(lens)
        f["max_token_len"] = max(lens)
        digits = sum(c.isdigit() for c in url)
        letters = sum(c.isalpha() for c in url)
        f["n_digits"] = digits
        f["digit_ratio"] = digits / n
        f["letter_ratio"] = letters / n
        f["upper_ratio"] = sum(c.isupper() for c in url) / n
        f["special_ratio"] = sum(not c.isalnum() for c in url) / n
        f["n_delims"] = sum(url.count(c) for c in "./?=&-_@~%")
        f["entropy"] = _entropy(Counter(url))
        f["n_nonascii"] = sum(ord(c) > 127 for c in url)
        f["n_sus_words"] = sum(w in low for w in SUS_WORDS)
        f["is_https"] = float(any(t.value.lower() == "https" for t in by_type.get("SCHEME", [])))

        # ---- domain
        labels = [t.value for t in by_type.get("SUBDOMAIN", []) + by_type.get("BASE_DOMAIN", [])]
        tld = by_type.get("TLD", [])
        all_labels = labels + [x for t in tld for x in t.value.split(".")]
        host = r.host
        f["host_len"] = len(host)
        f["n_labels"] = len(all_labels)
        f["n_subdomains"] = len(by_type.get("SUBDOMAIN", []))
        f["max_label_len"] = max((len(x) for x in all_labels), default=0)
        f["mean_label_len"] = (sum(len(x) for x in all_labels) / len(all_labels)) if all_labels else 0.0
        f["is_ip_host"] = float("IP_HOST" in by_type)
        tld_val = tld[0].value.lower() if tld else ""
        last = tld_val.split(".")[-1] if tld_val else ""
        f["tld_len"] = len(tld_val)
        f["tld_category"] = (4 if not last else 3 if last in ABUSED_TLD else 0 if last in COMMON_GTLD
                             else 1 if len(last) == 2 else 2)
        f["n_hyphens_host"] = host.count("-")
        f["n_digits_host"] = sum(c.isdigit() for c in host)
        base = by_type.get("BASE_DOMAIN", [])
        base_val = base[0].value.lower() if base else ""
        f["base_len"] = len(base_val)
        f["has_port"] = float("PORT" in by_type)
        f["has_userinfo"] = float("USERINFO" in by_type)
        subs = [t.value.lower() for t in by_type.get("SUBDOMAIN", [])]
        f["www_prefix"] = float(bool(subs) and subs[0] == "www")

        # ---- encoding
        lex_types = Counter(lx.type for lx in r.lexemes)
        n_pct = lex_types["PCT_ENC"] + lex_types["DOUBLE_ENC"]
        f["n_pct"] = n_pct
        f["pct_ratio"] = 3 * n_pct / n
        f["n_double_enc"] = lex_types["DOUBLE_ENC"]
        f["n_pct_host"] = host.count("%")
        f["n_nonascii_host"] = sum(ord(c) > 127 for c in host)
        f["n_puny_labels"] = lex_types["PUNY_LABEL"]
        f["n_ctrl"] = lex_types["CTRL"]
        f["n_error_tokens"] = lex_types["ERROR"]

        # ---- automata
        trace = r.trace
        visits = np.zeros(self.n_states)
        for g in trace:
            if g >= 0:
                visits[g] += 1
        anom = [g for g in trace if g in self.anomaly_states]
        f["n_anomaly_state_visits"] = len(anom)
        f["n_distinct_anomaly_states"] = len(set(anom))
        f["state_entropy"] = _entropy(Counter(g for g in trace if g >= 0))
        f["transition_entropy"] = _entropy(Counter(zip(trace, trace[1:])))
        f["n_distinct_states"] = len({g for g in trace if g >= 0})
        f["dead_state_hits"] = r.stats.get("errors", 0)
        f["backtracked_chars"] = r.stats.get("backtracked", 0)
        f["n_mode_switches"] = sum(1 for a, b in zip(r.lexemes, r.lexemes[1:]) if a.mode != b.mode)
        flags = [fl for fl in r.flags if fl.code not in UNTRAINED_FLAGS]
        f["n_flags_dfa"] = sum(fl.source == "dfa" for fl in flags)
        f["n_flags_attr"] = sum(fl.source == "attr" for fl in flags)
        f["flag_severity_sum"] = sum(fl.severity for fl in flags)
        codes = Counter(fl.code for fl in flags)
        for spec in self.registry:
            if spec.name.startswith("flag_") and spec.flags:
                f[spec.name] = float(codes[spec.flags[0]] > 0)

        # ---- path / query
        path = by_type.get("PATH", [])
        pval = path[0].value if path else ""
        segs = [s for s in pval.split("/") if s]
        f["path_len"] = len(pval)
        f["path_depth"] = pval.count("/")
        f["max_seg_len"] = max((len(s) for s in segs), default=0)
        f["has_dslash"] = float(lex_types["DSLASH"] > 0)
        f["file_ext_risky"] = float(pval.lower().endswith(RISKY_EXT))
        params = by_type.get("QUERY_PARAM", [])
        f["n_params"] = len(params)
        f["query_len"] = sum(len(p.value) for p in params)
        f["max_param_val_len"] = max((len(p.value.split("=", 1)[-1]) for p in params), default=0)
        frag = by_type.get("FRAGMENT", [])
        f["has_fragment"] = float(bool(frag))
        f["frag_len"] = len(frag[0].value) if frag else 0
        tail = pct_decode(pval + "?" + "&".join(p.value for p in params)).lower()
        f["url_in_path_or_query"] = float("http://" in tail or "https://" in tail or "www." in tail)

        # ---- symbol table / corpus
        low_labels = [x.lower() for x in labels]
        if self.corpus is not None and low_labels:
            rar = [self.corpus.label_rarity(x) for x in low_labels]
            f["base_label_rarity"] = self.corpus.label_rarity(base_val) if base_val else 0.0
            f["max_label_rarity"] = max(rar)
            f["mean_label_rarity"] = sum(rar) / len(rar)
        else:
            f["base_label_rarity"] = f["max_label_rarity"] = f["mean_label_rarity"] = 0.0
        f["brand_in_subdomain"] = float(any(s in self.brands for s in subs))
        f["brand_in_path"] = float(any(b in tail for b in self.brands if len(b) >= 5))
        f["brand_is_base"] = float(base_val in self.brands)
        f["n_symbols"] = r.symtab.get("size", 0)

        vec = np.zeros(len(self.names), dtype=np.float32)
        for k, v in f.items():
            vec[self.index[k]] = v
        first_visit = self.index[f"auto_visit_g{self.state_meta[0]['g']}"]
        vec[first_visit:first_visit + self.n_states] = visits / n
        return vec, r

    def transform(self, urls, progress: bool = False) -> np.ndarray:
        out = np.zeros((len(urls), len(self.names)), dtype=np.float32)
        for i, u in enumerate(urls):
            out[i] = self.extract(u)[0]
            if progress and i and i % 20000 == 0:
                print(f"    features: {i}/{len(urls)}")
        return out


def build_corpus(urls, scanner: Scanner | None = None) -> CorpusSymbolTable:
    """Corpus-wide symbol table from TRAINING URLs only (no test leakage)."""
    sc = scanner or get_scanner()
    brands = set(idn.brands())
    corpus = CorpusSymbolTable()
    for u in urls:
        r = sc.scan(u)
        labels = [t.value.lower() for t in r.tokens if t.type in ("SUBDOMAIN", "BASE_DOMAIN")]
        subs = [t.value.lower() for t in r.tokens if t.type == "SUBDOMAIN"]
        corpus.add(labels, subs, brands)
    return corpus
