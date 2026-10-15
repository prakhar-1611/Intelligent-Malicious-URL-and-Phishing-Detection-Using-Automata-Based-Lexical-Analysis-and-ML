"""Adversarial evaluation: which evasions does the lexer catch, and which get past the model?

Author: Prakhar Tandon (24BCI0222)   (model scoring: Ishitwo Khanra)

For every mutation operator, over N malicious URLs from the time-based test split:

    flag recall   fraction of mutated URLs where the operator's expected lexer
                  flag is raised (lexer-level detection, no ML involved)
    evasion rate  among URLs the model flagged (>= Suspicious) BEFORE mutation,
                  the fraction it scores Safe AFTER mutation
    mean delta    mean change in calibrated malicious probability

    python -m adversarial.evaluate --n 1000
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np

from adversarial.mutate import OPERATORS, mutate
from lexer.scanner import scan

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "artifacts" / "results"


def load_model():
    import joblib

    from lexer.symtab import CorpusSymbolTable
    from ml.features import FeatureExtractor

    path = ROOT / "artifacts" / "model.joblib"
    if not path.exists():
        return None, None
    bundle = joblib.load(path)
    fx = FeatureExtractor(corpus=CorpusSymbolTable.load(bundle["corpus_path"]))
    return bundle, fx


def score(bundle, fx, urls: list[str]) -> np.ndarray:
    X = fx.transform(urls)
    raw = bundle["model"].predict_proba(X)[:, 1]
    return bundle["calibrator"].transform(raw)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=1000)
    ap.add_argument("--seed", type=int, default=7)
    a = ap.parse_args()

    from ml.data_pipeline import load_dataset

    df = load_dataset()
    mal = df[(df.split == "test") & (df.label == 1)].sample(frac=1.0, random_state=a.seed)
    urls = mal["url"].tolist()[:a.n]
    bundle, fx = load_model()
    base_scores = score(bundle, fx, urls) if bundle else None
    thr = bundle["thresholds"] if bundle else None

    rows = []
    corpus_out = []
    for op in OPERATORS:
        pairs = [(u, m) for u in urls if (m := mutate(u, op, a.seed)) and m != u]
        if not pairs:
            continue
        originals = [u for u, _ in pairs]
        mutated = [m for _, m in pairs]
        row = {"operator": op.name, "description": op.description, "expected_flag": op.expected_flag,
               "applied": len(pairs), "of": len(urls)}
        if op.expected_flag:
            hit = [any(f.code == op.expected_flag for f in scan(m).flags) for m in mutated]
            already = [any(f.code == op.expected_flag for f in scan(u).flags) for u in originals]
            row["flag_recall"] = round(float(np.mean(hit)), 4)
            row["flag_present_before"] = round(float(np.mean(already)), 4)
        else:
            row["flag_recall"] = None
        if bundle:
            idx = {u: i for i, u in enumerate(urls)}
            before = np.array([base_scores[idx[u]] for u in originals])
            after = score(bundle, fx, mutated)
            detected = before >= thr["suspicious"]
            evaded = detected & (after < thr["suspicious"])
            row["detected_before"] = int(detected.sum())
            row["evasion_rate"] = round(float(evaded.sum() / max(detected.sum(), 1)), 4)
            row["mean_score_delta"] = round(float(np.mean(after - before)), 4)
        rows.append(row)
        corpus_out += [{"operator": op.name, "mutated_defanged": m.replace(".", "[.]")} for m in mutated[:5]]
        print(f"  {op.name:<20} applied {len(pairs):>5}  flag recall {row['flag_recall']}  "
              f"evasion {row.get('evasion_rate')}  Δscore {row.get('mean_score_delta')}")

    RESULTS.mkdir(parents=True, exist_ok=True)
    out = {"n_urls": len(urls), "seed": a.seed, "model": bundle["name"] if bundle else None, "rows": rows,
           "examples": corpus_out}
    (RESULTS / "adversarial.json").write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
    md = ["| Operator | Expected flag | Applied | Flag recall | Evasion rate | Mean Δscore |", "|---|---|---|---|---|---|"]
    for r in rows:
        md.append(f"| {r['operator']} | {r['expected_flag'] or '—'} | {r['applied']} | "
                  f"{r['flag_recall'] if r['flag_recall'] is not None else '—'} | {r.get('evasion_rate', '—')} | "
                  f"{r.get('mean_score_delta', '—')} |")
    (RESULTS / "adversarial.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    print("\n".join(md))


if __name__ == "__main__":
    main()
