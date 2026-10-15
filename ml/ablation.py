"""Ablation study: do the automata-derived features add anything?

Author: Ishitwo Khanra (24BCE2975)

    (A) lexical features only
    (B) A + domain-structure features
    (C) B + automata features (DFA state-visit vector, anomaly-state hits,
        state/transition entropy, dead-state hits, flags)
    (D) everything (adds encoding, path/query and corpus symbol-table features)

Same model family and hyper-parameters for every row (the best gradient-boosting
parameters found by train.py), 5-fold GroupKFold CV on train, plus the
time-based test split. This table is the project's scientific claim, so it is
reported exactly as measured, including when the difference is small.

    python -m ml.ablation [--domain-only]
"""
from __future__ import annotations

import argparse
import json

import numpy as np
from sklearn.base import clone
from sklearn.metrics import average_precision_score
from sklearn.model_selection import GroupKFold

from ml.data_pipeline import load_dataset
from ml.feature_registry import ABLATION
from ml.metrics import binary_metrics
from ml.train import RESULTS, domain_only, featurize, model_zoo


def base_model(tag: str, seed: int):
    zoo = model_zoo(seed)
    name = "lightgbm" if "lightgbm" in zoo else "random_forest"
    est = zoo[name][0]
    path = RESULTS / f"model_comparison{tag}.json"
    if path.exists():
        params = json.loads(path.read_text(encoding="utf-8"))["models"].get(name, {}).get("params")
        if params:
            est = est.set_params(**params)
    return name, est


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--domain-only", action="store_true")
    ap.add_argument("--seed", type=int, default=42)
    a = ap.parse_args()
    tag = "_domain_only" if a.domain_only else ""

    df = load_dataset()
    if a.domain_only:
        df["url"] = df["url"].map(domain_only)
        df = df.drop_duplicates(subset=["url", "label"]).reset_index(drop=True)
    X, fx = featurize(df, tag, a.seed)
    y = df["label"].to_numpy().astype(int)
    g = df["domain"].to_numpy()
    tr, te = (df.split == "train").to_numpy(), (df.split == "test").to_numpy()
    name, est = base_model(tag, a.seed)

    rows = []
    for config in ABLATION:
        cols = fx.columns_for(config)
        Xc = X[:, cols]
        cv = []
        for f_tr, f_va in GroupKFold(n_splits=5).split(Xc[tr], y[tr], g[tr]):
            m = clone(est).fit(Xc[tr][f_tr], y[tr][f_tr])
            cv.append(average_precision_score(y[tr][f_va], m.predict_proba(Xc[tr][f_va])[:, 1]))
        m = clone(est).fit(Xc[tr], y[tr])
        test = binary_metrics(y[te], m.predict_proba(Xc[te])[:, 1])
        rows.append({"config": config, "groups": ABLATION[config], "n_features": len(cols),
                     "cv_pr_auc_mean": round(float(np.mean(cv)), 4), "cv_pr_auc_std": round(float(np.std(cv)), 4),
                     "test": test})
        print(f"  {config:<18} d={len(cols):<4} CV PR-AUC {np.mean(cv):.4f}±{np.std(cv):.4f}  "
              f"test PR-AUC {test['pr_auc']}  F1 {test['f1']}  FPR {test['fpr']}")

    RESULTS.mkdir(parents=True, exist_ok=True)
    out = {"model": name, "domain_only": a.domain_only, "rows": rows}
    (RESULTS / f"ablation{tag}.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
    md = ["| Config | Feature groups | #features | CV PR-AUC (5-fold grouped) | Test PR-AUC | Test F1 | Test FPR |",
          "|---|---|---|---|---|---|---|"]
    for r in rows:
        md.append(f"| {r['config']} | {', '.join(r['groups'])} | {r['n_features']} | "
                  f"{r['cv_pr_auc_mean']:.4f} ± {r['cv_pr_auc_std']:.4f} | {r['test']['pr_auc']} | "
                  f"{r['test']['f1']} | {r['test']['fpr']} |")
    (RESULTS / f"ablation{tag}.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    print("\n".join(md))


if __name__ == "__main__":
    main()
