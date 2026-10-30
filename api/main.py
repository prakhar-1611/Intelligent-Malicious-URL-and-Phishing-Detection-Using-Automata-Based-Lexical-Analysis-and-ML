"""FastAPI service: lexer + features + model + explanations behind one API.

Author: Amrita Bhatia (24BCI0215)   (hardening: Prakhar Tandon, see api/security.py)

    uvicorn api.main:app --reload --port 8000

Endpoints
    POST /analyze            {url}        -> verdict, score, tokens, flags, trace, steps, explanation[]
    POST /analyze/batch      {urls: [..]} -> one summary row per URL
    POST /analyze/email      {raw}        -> header tokens, address checks, MIME part tree, HTML links,
                                             flags, scanned body URLs, combined verdict with its rule
    GET  /samples/emails                  -> the demo .eml files in data/samples/emails
    GET  /automata                        -> available rules / examples / modes
    GET  /automata/{rule}?stage=nfa|dfa|min
    POST /automata/custom    {pattern, stage}
    GET  /results                         -> experiment result JSON files
    GET  /results/figures/{name}          -> PNG figures
    GET  /health

The API never fetches, resolves or redirects to a submitted URL.
If no trained model exists yet, a transparent heuristic (flag severities) is
used and the response says so in "model".
"""
from __future__ import annotations

import json
import math
import time
from functools import lru_cache
from pathlib import Path
from typing import Literal

import numpy as np
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from api import security as sec
from lexer.email_lexer import EmailScanResult, combine_verdict, registered_domain, same_org, scan_email
from lexer.export import automaton_view, custom_pattern_view, list_automata
from lexer.rules import EMAIL_FLAGS, FLAG_DESCRIPTIONS, RULES, SEVERITY
from lexer.scanner import get_scanner
from ml.calibrate import DEFAULT_THRESHOLDS, verdict
from security.defang import defang

ROOT = Path(__file__).resolve().parent.parent
ART = ROOT / "artifacts"
RESULTS = ART / "results"
SAMPLE_EMAILS = ROOT / "data" / "samples" / "emails"

app = FastAPI(title="Automata-based Phishing URL Detector", version="2.0.0",
              description="BCSE307P Compiler Design Lab project, VIT Vellore")
limiter = sec.install(app)


# ------------------------------------------------------------------ schemas
class AnalyzeRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=sec.MAX_URL_LEN)


class BatchRequest(BaseModel):
    urls: list[str] = Field(..., min_length=1, max_length=sec.MAX_BATCH)


class EmailRequest(BaseModel):
    raw: str = Field(..., min_length=1, max_length=sec.MAX_EMAIL_BYTES)


class PatternRequest(BaseModel):
    pattern: str = Field(..., min_length=1, max_length=120)
    stage: Literal["nfa", "dfa", "min"] = "min"


# ------------------------------------------------------------------ engine
class Engine:
    def __init__(self) -> None:
        import joblib

        from lexer.symtab import CorpusSymbolTable
        from ml.explain import Explainer
        from ml.features import FeatureExtractor

        self.scanner = get_scanner()
        self.bundle = None
        path = ART / "model.joblib"
        corpus = None
        if path.exists():
            try:
                self.bundle = joblib.load(path)
                cp = Path(self.bundle["corpus_path"])
                corpus = CorpusSymbolTable.load(cp) if cp.exists() else None
            except Exception as e:  # incompatible / corrupt artifact -> heuristic mode
                print("model not loaded:", e)
                self.bundle = None
        self.fx = FeatureExtractor(self.scanner, corpus)
        if self.bundle and self.bundle["feature_names"] != self.fx.names:
            print("model feature names do not match the current lexer: retrain (python -m ml.train)")
            self.bundle = None
        self.explainer = Explainer(self.bundle, self.fx) if self.bundle else None
        self.thresholds = self.bundle["thresholds"] if self.bundle else DEFAULT_THRESHOLDS
        # second opinion for links inside emails: the scheme+host model (train.py --domain-only)
        self.dom_bundle, self.dom_fx = None, None
        dpath = ART / "model_domain_only.joblib"
        if self.bundle and dpath.exists():
            try:
                b = joblib.load(dpath)
                cp = Path(b["corpus_path"])
                fx = FeatureExtractor(self.scanner, CorpusSymbolTable.load(cp) if cp.exists() else None)
                if b["feature_names"] == fx.names:
                    self.dom_bundle, self.dom_fx = b, fx
            except Exception as e:
                print("domain-only model not loaded:", e)

    def email_link(self, url: str, first_party: str = "") -> dict:
        """Verdict for a link inside an email. Tracking links are long and percent-encoded, which the
        full-URL model reads as obfuscation, so a full-model verdict stands only when the domain-only
        model finds the host risky too or a strong (severity >= 2) flag fires; otherwise the link
        takes the domain-only verdict. ``first_party``: the registered domain of a DMARC-verified
        sender; its own links are as trustworthy as the sender itself."""
        a = self.analyze(url, detail=False)
        if first_party and same_org(a["registered_domain"].lower(), first_party):
            return a | {"verdict": "Safe", "basis": "first-party link of a DMARC-verified sender"}
        if not self.dom_bundle or a["verdict"] == "Safe":
            return a | {"basis": "full URL"}
        from ml.train import domain_only

        x, _ = self.dom_fx.extract(domain_only(url))
        raw = self.dom_bundle["model"].predict_proba(x[None])[:, 1]
        d = float(self.dom_bundle["calibrator"].transform(raw)[0])
        dth = self.dom_bundle["thresholds"]
        if d >= dth["suspicious"] or any(f["severity"] >= 2 for f in a["flags"]):
            return a | {"basis": "full URL, confirmed by host or flag", "host_score": round(d, 4)}
        return a | {"verdict": verdict(d, dth), "basis": "host only (path not trusted alone)",
                    "host_score": round(d, 4)}

    @property
    def model_name(self) -> str:
        return f"{self.bundle['name']} (calibrated)" if self.bundle else "heuristic-fallback (no trained model)"

    def score(self, x: np.ndarray, flags) -> float:
        if self.bundle:
            raw = self.bundle["model"].predict_proba(x[None])[:, 1]
            return float(self.bundle["calibrator"].transform(raw)[0])
        # transparent fallback: 1 - prod(1 - w(severity))
        w = {1: 0.15, 2: 0.3, 3: 0.5}
        return float(1 - math.prod(1 - w.get(f.severity, 0.2) for f in flags))

    def analyze(self, url: str, detail: bool = True) -> dict:
        t0 = time.perf_counter()
        r = self.scanner.scan(url)
        t1 = time.perf_counter()
        x, _ = self.fx.extract(url, r)
        t2 = time.perf_counter()
        score = self.score(x, r.flags)
        t3 = time.perf_counter()
        v = verdict(score, self.thresholds)
        out = {
            "url_defanged": defang(url),
            "verdict": v,
            "score": round(score, 4),
            "thresholds": self.thresholds,
            "model": self.model_name,
            "registered_domain": r.registered_domain,
            "flags": [{**f.__dict__, "description": FLAG_DESCRIPTIONS.get(f.code, "")} for f in r.flags],
            "timing_ms": {"lex": round((t1 - t0) * 1000, 3), "features": round((t2 - t1) * 1000, 3),
                          "model": round((t3 - t2) * 1000, 3)},
        }
        if detail:
            explanation = self.explainer.explain(x, r, url) if self.explainer else [
                {"feature": "flag_" + f.code[2:].lower(), "group": "automata", "description": f.evidence,
                 "value": 1.0, "contribution": None, "direction": "towards malicious",
                 "spans": [{"start": f.start, "end": f.end, "text": url[f.start:f.end]}], "states": [],
                 "flags": [f.code]} for f in r.flags]
            out.update({
                "input": url,  # rendered as text only by the UI
                "tokens": [t.__dict__ for t in r.tokens],
                "lexemes": [lx.__dict__ for lx in r.lexemes],
                "trace": r.trace, "steps": r.steps, "symtab": r.symtab, "scan_stats": r.stats,
                "explanation": explanation,
            })
        return out


@lru_cache(maxsize=1)
def engine() -> Engine:
    return Engine()


def _limit(rate: str):
    """Apply a per-route limit when slowapi is installed; otherwise no-op."""
    if limiter is None:
        return lambda f: f
    return limiter.limit(rate)


# ------------------------------------------------------------------ routes
@app.get("/health")
def health() -> dict:
    e = engine()
    return {"status": "ok", "model": e.model_name, "dfa_states": e.scanner.total_states,
            "modes": e.scanner.tables["mode_order"], "features": len(e.fx.names), "rules": len(RULES),
            "url_flags": sum(1 for c in SEVERITY if c not in EMAIL_FLAGS)}


@app.post("/analyze")
@_limit(sec.RATE_LIMIT)
def analyze(req: AnalyzeRequest, request: Request) -> dict:
    out = engine().analyze(req.url)
    sec.log_verdict(req.url, out["verdict"], out["score"], [f["code"] for f in out["flags"]], request)
    return out


@app.post("/analyze/batch")
@_limit("10/minute")
def analyze_batch(req: BatchRequest, request: Request) -> dict:
    rows = []
    for u in req.urls:
        if not u or len(u) > sec.MAX_URL_LEN:
            rows.append({"url_defanged": defang(u[:80]), "error": f"length must be 1..{sec.MAX_URL_LEN}"})
            continue
        r = engine().analyze(u, detail=False)
        sec.log_verdict(u, r["verdict"], r["score"], [f["code"] for f in r["flags"]], request)
        rows.append({k: r[k] for k in ("url_defanged", "verdict", "score", "registered_domain")} |
                    {"flags": [f["code"] for f in r["flags"]]})
    counts = {v: sum(1 for r in rows if r.get("verdict") == v) for v in ("Safe", "Suspicious", "Malicious")}
    return {"model": engine().model_name, "summary": counts, "results": rows}


@app.post("/analyze/email")
@_limit("20/minute")
def analyze_email(req: EmailRequest, request: Request) -> dict:
    res: EmailScanResult = scan_email(req.raw)
    out = res.to_dict()
    authenticated = res.auth_results.get("dmarc") == "pass"
    sender = registered_domain(res.addresses["from"]["domain"]) if authenticated else ""
    for u in out["urls"]:
        a = engine().email_link(u["url"][:sec.MAX_URL_LEN], first_party=sender)
        u.update({k: a[k] for k in ("url_defanged", "verdict", "score", "basis")})
        u.pop("url")
    for f in out["flags"]:
        f["description"] = FLAG_DESCRIPTIONS.get(f["code"], "")
    body = {"S_LINK_MISMATCH", "S_RISKY_ATTACHMENT"}
    out["summary"] = combine_verdict(res.flags, [u["score"] for u in out["urls"]], engine().thresholds,
                                     authenticated=authenticated,
                                     url_verdicts=[u["verdict"] for u in out["urls"]]) | {
        "header_flags": [f.code for f in res.flags if f.code not in body],
        "body_flags": [f.code for f in res.flags if f.code in body]}
    return out


@app.get("/samples/emails")
def sample_emails() -> dict:
    return {p.stem: p.read_text(encoding="utf-8") for p in sorted(SAMPLE_EMAILS.glob("*.eml"))}


@app.get("/automata")
def automata_list() -> dict:
    return list_automata()


@app.get("/automata/{name}")
def automata(name: str, stage: Literal["regex", "nfa", "dfa", "min"] = "min") -> dict:
    try:
        return automaton_view(name, stage)
    except KeyError:
        raise HTTPException(404, f"unknown automaton {name!r}") from None


@app.post("/automata/custom")
@_limit("30/minute")
def automata_custom(req: PatternRequest, request: Request) -> dict:
    try:
        return custom_pattern_view(req.pattern, req.stage)
    except Exception as e:  # syntax errors, blow-up guard
        raise HTTPException(400, str(e)) from None


@app.get("/scanner/states")
def scanner_states() -> dict:
    """Minimal DFA of every lexer mode (graph + global state ids) for the Live Trace page."""
    sc = engine().scanner
    modes = {}
    for m in sc.tables["mode_order"]:
        view = automaton_view(f"mode:{m}", "min")
        off = sc.modes[m].offset
        for n in view["graph"]["nodes"]:
            n["g"] = off + int(n["id"][1:])
        modes[m] = {"graph": view["graph"], "offset": off, "n_states": sc.modes[m].n_states}
    return {"modes": modes, "order": sc.tables["mode_order"]}


@app.get("/results")
def results() -> dict:
    out: dict = {"files": {}, "figures": []}
    if RESULTS.exists():
        for p in sorted(RESULTS.glob("*.json")):
            out["files"][p.stem] = json.loads(p.read_text(encoding="utf-8"))
        fig = RESULTS / "figures"
        if fig.exists():
            out["figures"] = sorted(p.name for p in fig.glob("*.png"))
    stats = ART / "automata_stats.json"
    if stats.exists():
        out["files"]["automata_stats"] = json.loads(stats.read_text(encoding="utf-8"))
    return out


@app.get("/results/figures/{name}")
def figure(name: str):
    if "/" in name or "\\" in name or ".." in name or not name.endswith(".png"):
        raise HTTPException(400, "bad figure name")
    p = RESULTS / "figures" / name
    if not p.exists():
        raise HTTPException(404, "not found")
    return FileResponse(p, media_type="image/png")
