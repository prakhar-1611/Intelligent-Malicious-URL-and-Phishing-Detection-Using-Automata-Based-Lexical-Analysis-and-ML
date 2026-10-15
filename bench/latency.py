"""Latency per stage (lexing, features, inference) and scanner scaling with input length.

Author: Ishitwo Khanra (24BCE2975)   (scanner scaling: Amrita Bhatia)

    python -m bench.latency --n 1000   -> artifacts/results/latency.json + figures/scaling.png
"""
from __future__ import annotations

import argparse
import json
import random
import time
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "artifacts" / "results"


def pct(a: list[float]) -> dict:
    x = np.array(a) * 1000
    return {"mean_ms": round(float(x.mean()), 4), "p50_ms": round(float(np.percentile(x, 50)), 4),
            "p95_ms": round(float(np.percentile(x, 95)), 4), "max_ms": round(float(x.max()), 4)}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=1000)
    a = ap.parse_args()

    import joblib

    from lexer.scanner import get_scanner
    from lexer.symtab import CorpusSymbolTable
    from ml.data_pipeline import load_dataset
    from ml.features import FeatureExtractor

    sc = get_scanner()
    model_path = ROOT / "artifacts" / "model.joblib"
    bundle = joblib.load(model_path) if model_path.exists() else None
    fx = FeatureExtractor(corpus=CorpusSymbolTable.load(bundle["corpus_path"]) if bundle else None)
    df = load_dataset()
    urls = df[df.split == "test"].sample(n=min(a.n, int((df.split == "test").sum())), random_state=1)["url"].tolist()

    t_lex, t_feat, t_inf = [], [], []
    for u in urls:
        t0 = time.perf_counter()
        r = sc.scan(u)
        t1 = time.perf_counter()
        x, _ = fx.extract(u, r)
        t2 = time.perf_counter()
        if bundle:
            bundle["calibrator"].transform(bundle["model"].predict_proba(x[None])[:, 1])
        t3 = time.perf_counter()
        t_lex.append(t1 - t0)
        t_feat.append(t2 - t1)
        t_inf.append(t3 - t2)

    # scaling: random URL-like strings of growing length
    rng = random.Random(0)
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789-._~/?=&%"
    scaling = []
    for n in [100, 1_000, 5_000, 10_000, 50_000, 100_000]:
        body = "".join(rng.choice(alphabet) for _ in range(n))
        text = "https://example.com/" + body
        best = min(_timed(sc.lex, text) for _ in range(3))
        _, _, _, st = sc.lex(text)
        scaling.append({"n": len(text), "seconds": best, "us_per_char": round(best / len(text) * 1e6, 4),
                        "transitions": st["transitions"], "backtracked": st["backtracked"]})
    xs = np.array([s["n"] for s in scaling], dtype=float)
    ys = np.array([s["seconds"] for s in scaling])
    slope, intercept = np.polyfit(xs, ys, 1)
    r2 = 1 - np.sum((ys - (slope * xs + intercept)) ** 2) / np.sum((ys - ys.mean()) ** 2)

    out = {"n_urls": len(urls), "model": bundle["name"] if bundle else None,
           "lexing": pct(t_lex), "features": pct(t_feat), "inference": pct(t_inf),
           "total": pct([x + y + z for x, y, z in zip(t_lex, t_feat, t_inf)]),
           "scaling": scaling, "linear_fit_r2": round(float(r2), 5)}
    RESULTS.mkdir(parents=True, exist_ok=True)
    (RESULTS / "latency.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(json.dumps({k: v for k, v in out.items() if k != "scaling"}, indent=2))
    for s in scaling:
        print(f"  n={s['n']:<7} {s['seconds'] * 1000:8.2f} ms  {s['us_per_char']} µs/char  backtracked={s['backtracked']}")
    print(f"  linear fit R^2 = {r2:.5f}")
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        fig, ax = plt.subplots(figsize=(6, 4))
        ax.plot(xs, ys * 1000, "o-")
        ax.set_xlabel("input length (characters)")
        ax.set_ylabel("scan time (ms)")
        ax.set_title(f"Scanner time vs input length (linear fit R² = {r2:.4f})")
        ax.grid(alpha=0.3)
        fig.tight_layout()
        (RESULTS / "figures").mkdir(parents=True, exist_ok=True)
        fig.savefig(RESULTS / "figures" / "scaling.png", dpi=150)
    except Exception as e:
        print("plot skipped:", e)


def _timed(fn, arg) -> float:
    t0 = time.perf_counter()
    fn(arg)
    return time.perf_counter() - t0


if __name__ == "__main__":
    main()
