"""Explanations: SHAP contributions mapped back to tokens and DFA states.

Author: Ishitwo Khanra (24BCE2975)

Per-URL (used by the API):
    contributions in log-odds space come from exact TreeSHAP
      LightGBM  predict(..., pred_contrib=True)
      XGBoost   Booster.predict(..., pred_contribs=True)
      RF        shap.TreeExplainer
      LogReg    coefficient x standardised value (exact for a linear model)
    each top feature is resolved through the feature registry to the input
    spans, flags and min-DFA states it was computed from.

Global (python -m ml.explain): mean |SHAP| over a sample of the test split,
per feature and per feature group -> artifacts/results/shap_global*.json + PNG.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np

from core.types import ScanResult
from ml.feature_registry import evidence
from ml.features import FeatureExtractor

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "artifacts" / "results"


class Explainer:
    def __init__(self, bundle: dict, fx: FeatureExtractor):
        self.model = bundle["model"]
        self.name = bundle["name"]
        self.fx = fx
        self._tree_explainer = None

    def contributions(self, X: np.ndarray) -> np.ndarray:
        X = np.atleast_2d(X)
        if self.name == "lightgbm":
            return np.asarray(self.model.predict(X, pred_contrib=True))[:, :-1]
        if self.name == "xgboost":
            import xgboost as xgb

            return self.model.get_booster().predict(xgb.DMatrix(X), pred_contribs=True)[:, :-1]
        if self.name == "logreg":
            scaler, lr = self.model.steps[0][1], self.model.steps[-1][1]
            return (X - scaler.mean_) / scaler.scale_ * lr.coef_[0]
        if self._tree_explainer is None:
            import shap

            self._tree_explainer = shap.TreeExplainer(self.model)
        sv = self._tree_explainer.shap_values(X, check_additivity=False)
        sv = np.asarray(sv)
        if sv.ndim == 3:  # (n, d, classes) or (classes, n, d)
            sv = sv[..., 1] if sv.shape[-1] == 2 else sv[1]
        return sv

    def explain(self, x: np.ndarray, scan: ScanResult, url: str, top_k: int = 8) -> list[dict]:
        c = self.contributions(x)[0]
        order = np.argsort(-np.abs(c))
        out = []
        for i in order[:top_k]:
            if abs(c[i]) < 1e-6:
                break
            spec = self.fx.registry[i]
            out.append({
                "feature": spec.name, "group": spec.group, "description": spec.description,
                "value": round(float(x[i]), 4), "contribution": round(float(c[i]), 4),
                "direction": "towards malicious" if c[i] > 0 else "towards benign",
                **evidence(spec, scan, url),
            })
        return out


def global_importance(tag: str = "", sample: int = 2000, seed: int = 42) -> dict:
    import joblib

    from lexer.symtab import CorpusSymbolTable
    from ml.data_pipeline import load_dataset
    from ml.train import ART, domain_only

    bundle = joblib.load(ART / f"model{tag}.joblib")
    fx = FeatureExtractor(corpus=CorpusSymbolTable.load(bundle["corpus_path"]))
    ex = Explainer(bundle, fx)
    df = load_dataset()
    te = df[df.split == "test"].sample(n=min(sample, int((df.split == "test").sum())), random_state=seed)
    urls = te["url"].map(domain_only).tolist() if tag else te["url"].tolist()
    X = fx.transform(urls)
    sv = ex.contributions(X)
    mean_abs = np.abs(sv).mean(axis=0)
    order = np.argsort(-mean_abs)
    groups: dict[str, float] = {}
    for i, gname in enumerate(fx.groups):
        groups[gname] = groups.get(gname, 0.0) + float(mean_abs[i])
    total = sum(groups.values()) or 1.0
    res = {
        "model": bundle["name"], "rows": len(urls),
        "top_features": [{"feature": fx.names[i], "group": fx.groups[i], "mean_abs_shap": round(float(mean_abs[i]), 5)}
                         for i in order[:25]],
        "group_share": {k: round(v / total, 4) for k, v in sorted(groups.items(), key=lambda kv: -kv[1])},
    }
    RESULTS.mkdir(parents=True, exist_ok=True)
    (RESULTS / f"shap_global{tag}.json").write_text(json.dumps(res, indent=2), encoding="utf-8")
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        top = res["top_features"][:20][::-1]
        fig, ax = plt.subplots(figsize=(8, 6))
        ax.barh([t["feature"] for t in top], [t["mean_abs_shap"] for t in top], color="#4C6EF5")
        ax.set_xlabel("mean |SHAP| (log-odds)")
        ax.set_title(f"Global feature importance ({bundle['name']}{', domain-only' if tag else ''})")
        fig.tight_layout()
        (RESULTS / "figures").mkdir(exist_ok=True)
        fig.savefig(RESULTS / "figures" / f"shap_global{tag}.png", dpi=150)
    except Exception as e:  # plotting is optional
        print("plot skipped:", e)
    return res


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--domain-only", action="store_true")
    ap.add_argument("--sample", type=int, default=2000)
    a = ap.parse_args()
    res = global_importance("_domain_only" if a.domain_only else "", a.sample)
    print(json.dumps(res["group_share"], indent=2))
    for t in res["top_features"][:15]:
        print(f"  {t['feature']:<32}{t['group']:<12}{t['mean_abs_shap']}")


if __name__ == "__main__":
    main()
