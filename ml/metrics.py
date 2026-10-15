"""Evaluation metrics (precision, recall, F1, FPR, ROC-AUC, PR-AUC, confusion matrix).

Author: Ishitwo Khanra (24BCE2975)

Accuracy is deliberately not the headline number: with imbalanced classes and
an operational cost for false positives, FPR and PR-AUC say much more.
"""
from __future__ import annotations

import numpy as np
from sklearn.metrics import (average_precision_score, confusion_matrix, f1_score, precision_recall_curve,
                             precision_score, recall_score, roc_auc_score, roc_curve)


def binary_metrics(y: np.ndarray, p: np.ndarray, threshold: float = 0.5) -> dict:
    yhat = (p >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, yhat, labels=[0, 1]).ravel()
    both = len(np.unique(y)) == 2
    return {
        "threshold": round(float(threshold), 6),
        "precision": round(float(precision_score(y, yhat, zero_division=0)), 4),
        "recall": round(float(recall_score(y, yhat, zero_division=0)), 4),
        "f1": round(float(f1_score(y, yhat, zero_division=0)), 4),
        "fpr": round(float(fp / (fp + tn)) if fp + tn else 0.0, 4),
        "roc_auc": round(float(roc_auc_score(y, p)), 4) if both else None,
        "pr_auc": round(float(average_precision_score(y, p)), 4) if both else None,
        "confusion": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "n": int(len(y)), "positives": int(y.sum()),
    }


def curves(y: np.ndarray, p: np.ndarray, points: int = 200) -> dict:
    fpr, tpr, _ = roc_curve(y, p)
    prec, rec, _ = precision_recall_curve(y, p)

    def thin(a, b):
        idx = np.unique(np.linspace(0, len(a) - 1, min(points, len(a))).astype(int))
        return [[round(float(a[i]), 5), round(float(b[i]), 5)] for i in idx]

    return {"roc": thin(fpr, tpr), "pr": thin(rec, prec)}


def policy_confusion(y: np.ndarray, p: np.ndarray, thresholds: dict) -> dict:
    """Counts of Safe / Suspicious / Malicious verdicts per true class."""
    out = {}
    for lab, name in ((0, "benign"), (1, "malicious")):
        q = p[y == lab]
        out[name] = {
            "Safe": int(np.sum(q < thresholds["suspicious"])),
            "Suspicious": int(np.sum((q >= thresholds["suspicious"]) & (q < thresholds["malicious"]))),
            "Malicious": int(np.sum(q >= thresholds["malicious"])),
        }
    return out
