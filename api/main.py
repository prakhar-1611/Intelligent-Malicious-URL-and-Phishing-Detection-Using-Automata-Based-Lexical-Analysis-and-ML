"""FastAPI service: lexer + features + model + explanations behind one API.

Author: Amrita Bhatia (24BCI0215)   (hardening: Prakhar Tandon, see api/security.py)

    uvicorn api.main:app --reload --port 8000

Endpoints
    POST /analyze            {url}        -> verdict, score, tokens, flags, trace, steps, explanation[]
    POST /analyze/batch      {urls: [..]} -> one summary row per URL
    POST /analyze/email      {raw}        -> header tokens, address checks, flags, scanned body URLs
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
from lexer.email_lexer import scan_email
from lexer.export import automaton_view, custom_pattern_view, list_automata
from lexer.rules import FLAG_DESCRIPTIONS
from lexer.scanner import get_scanner
from ml.calibrate import DEFAULT_THRESHOLDS, verdict
from security.defang import defang

ROOT = Path(__file__).resolve().parent.parent
ART = ROOT / "artifacts"
RESULTS = ART / "results"

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
            "modes": e.scanner.tables["mode_order"], "features": len(e.fx.names)}


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
    res = scan_email(req.raw)
    out = res.to_dict()
    for u in out["urls"]:
        a = engine().analyze(u["url"][:sec.MAX_URL_LEN], detail=False)
        u.update({"url_defanged": a["url_defanged"], "verdict": a["verdict"], "score": a["score"]})
        u.pop("url")
    flags = [f["code"] for f in out["flags"]]
    worst = max((u["score"] for u in out["urls"]), default=0.0)
    out["summary"] = {"header_flags": flags, "max_url_score": worst,
                      "verdict": "Malicious" if worst >= engine().thresholds["malicious"] else
                      "Suspicious" if flags or worst >= engine().thresholds["suspicious"] else "Safe"}
    return out


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
