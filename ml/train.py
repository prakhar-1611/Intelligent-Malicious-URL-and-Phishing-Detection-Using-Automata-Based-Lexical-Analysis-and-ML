"""Train and compare LR, Random Forest, LightGBM and XGBoost on the lexer features.

Author: Ishitwo Khanra (24BCE2975)

    python -m ml.train                  # full URLs
    python -m ml.train --domain-only    # scheme + host only (path-bias control)

Steps
    1. corpus symbol table from the TRAIN split only
    2. features for every URL (cached in data/processed/)
    3. per model: randomized search with 5-fold GroupKFold (groups = registered
       domain) on the training split, then refit on all of train
    4. metrics on validation and on the time-based test split
    5. best model by validation PR-AUC -> isotonic calibration on validation ->
       thresholds chosen on validation (FPR <= 1 % Malicious, <= 5 % Suspicious)
    6. artifacts/model.joblib + artifacts/results/model_comparison*.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import GroupKFold, RandomizedSearchCV
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from lexer.scanner import get_scanner
from ml.calibrate import IsotonicCalibrator, choose_thresholds
from ml.data_pipeline import DATASET, PROCESSED, STATS, load_dataset
from ml.features import FeatureExtractor, build_corpus
from ml.metrics import binary_metrics, curves, policy_confusion

ROOT = Path(__file__).resolve().parent.parent
ART = ROOT / "artifacts"
RESULTS = ART / "results"


def domain_only(url: str) -> str:
    """Keep only scheme://host (+port): removes the path/query shortcut entirely."""
    r = get_scanner().scan(url)
    scheme = next((t.value for t in r.tokens if t.type == "SCHEME"), "http")
    port = next((":" + t.value for t in r.tokens if t.type == "PORT"), "")
    return f"{scheme}://{r.host}{port}/" if r.host else url


def model_zoo(seed: int) -> dict:
    zoo = {
        "logreg": (make_pipeline(StandardScaler(), LogisticRegression(max_iter=3000)),
                   {"logisticregression__C": [0.01, 0.1, 1.0, 10.0]}),
        "random_forest": (RandomForestClassifier(n_jobs=-1, random_state=seed),
                          {"n_estimators": [200, 400], "max_depth": [None, 24, 40],
                           "min_samples_leaf": [1, 2, 5], "max_features": ["sqrt", 0.3]}),
    }
    try:
        from lightgbm import LGBMClassifier

        zoo["lightgbm"] = (LGBMClassifier(random_state=seed, verbose=-1, n_jobs=-1),
                           {"num_leaves": [31, 63, 127], "learning_rate": [0.03, 0.05, 0.1],
                            "n_estimators": [300, 600], "min_child_samples": [20, 50],
                            "subsample": [0.8, 1.0], "subsample_freq": [1], "colsample_bytree": [0.6, 0.8, 1.0]})
    except ImportError:
        print("lightgbm not installed: skipping")
    try:
        from xgboost import XGBClassifier

        zoo["xgboost"] = (XGBClassifier(random_state=seed, n_jobs=-1, eval_metric="logloss", tree_method="hist"),
                          {"max_depth": [4, 6, 8], "learning_rate": [0.03, 0.05, 0.1],
                           "n_estimators": [300, 600], "subsample": [0.8, 1.0], "colsample_bytree": [0.6, 0.8, 1.0]})
    except ImportError:
        print("xgboost not installed: skipping")
    return zoo


def featurize(df: pd.DataFrame, tag: str, seed: int) -> tuple[np.ndarray, FeatureExtractor]:
    PROCESSED.mkdir(parents=True, exist_ok=True)
    train_urls = df.loc[df.split == "train", "url"].tolist()
    corpus = build_corpus(train_urls)
    corpus_path = ART / f"corpus_symtab{tag}.json"
    ART.mkdir(exist_ok=True)
    corpus.save(corpus_path)
    fx = FeatureExtractor(corpus=corpus)
    key = hashlib.sha1(("\n".join(df["url"]) + "|" + ",".join(fx.names)).encode("utf-8")).hexdigest()[:12]
    cache = PROCESSED / f"features{tag}_{key}.npz"
    if cache.exists():
        X = np.load(cache)["X"]
        print(f"  loaded cached features {cache.name} {X.shape}")
    else:
        t0 = time.perf_counter()
        X = fx.transform(df["url"].tolist(), progress=True)
        np.savez_compressed(cache, X=X)
        print(f"  extracted {X.shape} features in {time.perf_counter() - t0:.1f}s")
    return X, fx


def tune(name, est, grid, X, y, groups, n_iter, seed, tune_rows):
    rng = np.random.default_rng(seed)
    idx = np.arange(len(y))
    if tune_rows and len(idx) > tune_rows:
        # subsample whole domains so the grouped CV stays leak-free
        ug = np.unique(groups)
        keep = set(rng.choice(ug, size=max(1, int(len(ug) * tune_rows / len(idx))), replace=False))
        idx = np.array([i for i in idx if groups[i] in keep])
    search = RandomizedSearchCV(est, grid, n_iter=n_iter, scoring="average_precision", cv=GroupKFold(n_splits=5),
                                random_state=seed, n_jobs=1, refit=False)
    search.fit(X[idx], y[idx], groups=groups[idx])
    best = search.best_index_
    cv = {"mean_pr_auc": round(float(search.cv_results_["mean_test_score"][best]), 4),
          "std_pr_auc": round(float(search.cv_results_["std_test_score"][best]), 4),
          "tuning_rows": int(len(idx)), "n_iter": n_iter}
    return search.best_params_, cv


def scores(model, X) -> np.ndarray:
    return model.predict_proba(X)[:, 1]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--domain-only", action="store_true")
    ap.add_argument("--models", default="logreg,random_forest,lightgbm,xgboost")
    ap.add_argument("--n-iter", type=int, default=6)
    ap.add_argument("--tune-rows", type=int, default=40000, help="rows used for the CV search (0 = all)")
    ap.add_argument("--sample", type=int, default=0, help="debug: use only N rows")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--dataset", type=Path, default=DATASET)
    a = ap.parse_args()

    tag = "_domain_only" if a.domain_only else ""
    df = load_dataset(a.dataset)
    if a.sample:
        df = df.sample(min(a.sample, len(df)), random_state=a.seed).reset_index(drop=True)
    if a.domain_only:
        df["url"] = df["url"].map(domain_only)
        df = df.drop_duplicates(subset=["url", "label"]).reset_index(drop=True)
    print(f"dataset: {len(df)} rows  {df.groupby(['split', 'label']).size().to_dict()}")

    X, fx = featurize(df, tag, a.seed)
    y = df["label"].to_numpy().astype(int)
    g = df["domain"].to_numpy()
    tr, va, te = (df.split == "train").to_numpy(), (df.split == "val").to_numpy(), (df.split == "test").to_numpy()

    zoo = model_zoo(a.seed)
    results: dict = {"domain_only": a.domain_only, "n_features": len(fx.names),
                     "rows": {"train": int(tr.sum()), "val": int(va.sum()), "test": int(te.sum())}, "models": {}}
    fitted = {}
    for name in [m for m in a.models.split(",") if m in zoo]:
        est, grid = zoo[name]
        t0 = time.perf_counter()
        params, cv = tune(name, est, grid, X[tr], y[tr], g[tr], a.n_iter, a.seed, a.tune_rows)
        model = est.set_params(**params)
        model.fit(X[tr], y[tr])
        fit_s = time.perf_counter() - t0
        pv, pt = scores(model, X[va]), scores(model, X[te])
        results["models"][name] = {"params": params, "cv_grouped_5fold": cv, "fit_seconds": round(fit_s, 1),
                                   "val": binary_metrics(y[va], pv), "test": binary_metrics(y[te], pt)}
        fitted[name] = (model, pv, pt)
        m = results["models"][name]
        print(f"  {name:<14} CV PR-AUC {cv['mean_pr_auc']:.4f}±{cv['std_pr_auc']:.4f} | "
              f"val PR-AUC {m['val']['pr_auc']} | test P {m['test']['precision']} R {m['test']['recall']} "
              f"F1 {m['test']['f1']} FPR {m['test']['fpr']} ROC {m['test']['roc_auc']} PR {m['test']['pr_auc']}")

    best = max(fitted, key=lambda n: results["models"][n]["val"]["pr_auc"])
    model, pv, pt = fitted[best]
    cal = IsotonicCalibrator().fit(pv, y[va])
    pv_c, pt_c = cal.transform(pv), cal.transform(pt)
    thr = choose_thresholds(pv_c, y[va])
    results["best"] = {
        "model": best,
        "thresholds": thr,
        "test_at_malicious_threshold": binary_metrics(y[te], pt_c, thr["malicious"]),
        "test_at_suspicious_threshold": binary_metrics(y[te], pt_c, thr["suspicious"]),
        "test_policy": policy_confusion(y[te], pt_c, thr),
        "curves_test": curves(y[te], pt_c),
    }
    if hasattr(model, "feature_importances_"):
        imp = np.asarray(model.feature_importances_, dtype=float)
        order = np.argsort(-imp)[:25]
        results["best"]["feature_importance_top25"] = [
            {"feature": fx.names[i], "group": fx.groups[i], "importance": round(float(imp[i] / imp.sum()), 5)}
            for i in order]
    if STATS.exists():
        results["dataset"] = json.loads(STATS.read_text(encoding="utf-8"))

    RESULTS.mkdir(parents=True, exist_ok=True)
    (RESULTS / f"model_comparison{tag}.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    bundle = {"model": model, "name": best, "feature_names": fx.names, "calibrator": cal, "thresholds": thr,
              "corpus_path": str(ART / f"corpus_symtab{tag}.json"), "domain_only": a.domain_only,
              "trained_at": time.strftime("%Y-%m-%d %H:%M:%S")}
    joblib.dump(bundle, ART / f"model{tag}.joblib")
    print(f"best = {best}; thresholds {thr}")
    print(f"saved {ART / f'model{tag}.joblib'} and results/model_comparison{tag}.json")


if __name__ == "__main__":
    main()
