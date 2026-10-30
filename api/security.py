"""API hardening.

Author: Prakhar Tandon (24BCI0222)

* Input caps: URL <= 2048 chars, batch <= 500 URLs, email <= 1 MB (Pydantic models in main.py)
* Rate limiting: slowapi (per client IP), configurable with RATE_LIMIT, default 60/minute
* CORS allowlist: ALLOWED_ORIGINS (comma-separated), default the local Vite dev server
* Security headers on every response (nosniff, frame deny, strict CSP, no referrer)
* No SSRF surface: the API never resolves, fetches or redirects to a submitted URL
* Security log: every Malicious verdict is appended as one JSON line with the URL
  *defanged* and the client IP hashed (artifacts/logs/security.log)

STRIDE summary for the app itself is in docs/SECURITY.md.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from security.defang import defang

ROOT = Path(__file__).resolve().parent.parent
LOG_DIR = ROOT / "artifacts" / "logs"

MAX_URL_LEN = 2048
MAX_BATCH = 500
MAX_EMAIL_BYTES = 1_000_000  # real HTML mail is often 100-500 kB
RATE_LIMIT = os.environ.get("RATE_LIMIT", "60/minute")
ALLOWED_ORIGINS = [o.strip() for o in os.environ.get(
    "ALLOWED_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173").split(",") if o.strip()]

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    "Cache-Control": "no-store",
}

_security_logger: logging.Logger | None = None


def security_logger() -> logging.Logger:
    global _security_logger
    if _security_logger is None:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        lg = logging.getLogger("phish.security")
        lg.setLevel(logging.INFO)
        lg.propagate = False
        h = logging.FileHandler(LOG_DIR / "security.log", encoding="utf-8")
        h.setFormatter(logging.Formatter("%(message)s"))
        lg.addHandler(h)
        _security_logger = lg
    return _security_logger


def client_hash(request: Request | None) -> str:
    ip = request.client.host if request and request.client else "unknown"
    return hashlib.sha256(("phish-salt:" + ip).encode()).hexdigest()[:16]


def log_verdict(url: str, verdict: str, score: float, flags: list[str], request: Request | None) -> None:
    if verdict != "Malicious":
        return
    security_logger().info(json.dumps({
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "event": "malicious_verdict",
        "url": defang(url), "score": round(score, 4), "flags": flags, "client": client_hash(request)}))


def install(app: FastAPI) -> object | None:
    """Attach CORS, security headers and (if available) rate limiting. Returns the limiter."""
    app.add_middleware(CORSMiddleware, allow_origins=ALLOWED_ORIGINS, allow_methods=["GET", "POST"],
                       allow_headers=["Content-Type"], allow_credentials=False, max_age=600)

    @app.middleware("http")
    async def _headers(request: Request, call_next):
        response = await call_next(request)
        for k, v in SECURITY_HEADERS.items():
            response.headers.setdefault(k, v)
        return response

    try:
        from slowapi import Limiter, _rate_limit_exceeded_handler
        from slowapi.errors import RateLimitExceeded
        from slowapi.middleware import SlowAPIMiddleware
        from slowapi.util import get_remote_address
    except ImportError:
        return None
    enabled = os.environ.get("RATE_LIMIT_ENABLED", "1") != "0"
    limiter = Limiter(key_func=get_remote_address, default_limits=[RATE_LIMIT], enabled=enabled)
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    app.add_middleware(SlowAPIMiddleware)
    return limiter
