"""Probability calibration and policy thresholds.

Author: Ishitwo Khanra (24BCE2975)

Review 1 (section 3.2.10) promised that the Safe / Suspicious / Malicious
thresholds "will be calibrated using validation data rather than assumed".

1. Isotonic regression maps raw model scores to calibrated probabilities
   (monotone, non-parametric), fitted on the validation split only.
2. Thresholds are chosen on the calibrated validation scores by an operating
   constraint, not by a fixed 0.3 / 0.7:
       Malicious   lowest threshold with FPR <= 1 %
       Suspicious  lowest threshold with FPR <= 5 %
"""
from __future__ import annotations

import numpy as np
from sklearn.isotonic import IsotonicRegression

DEFAULT_THRESHOLDS = {"suspicious": 0.3, "malicious": 0.7, "source": "Review 1 defaults (uncalibrated)"}


class IsotonicCalibrator:
    def __init__(self) -> None:
        self.iso = IsotonicRegression(out_of_bounds="clip", y_min=0.0, y_max=1.0)

    def fit(self, scores: np.ndarray, y: np.ndarray) -> "IsotonicCalibrator":
        self.iso.fit(scores, y)
        return self

    def transform(self, scores: np.ndarray) -> np.ndarray:
        return self.iso.predict(np.asarray(scores, dtype=float))


def threshold_for_fpr(p: np.ndarray, y: np.ndarray, max_fpr: float) -> float:
    """Smallest threshold t such that FPR(p >= t) <= max_fpr on (p, y)."""
    neg = np.sort(p[y == 0])
    if len(neg) == 0:
        return 0.5
    cands = np.unique(np.concatenate([p, [1.0 + 1e-9]]))
    for t in cands:  # ascending: first t meeting the constraint is the smallest
        if np.mean(neg >= t) <= max_fpr:
            return float(min(t, 1.0))
    return 1.0


def choose_thresholds(p_cal: np.ndarray, y: np.ndarray, max_fpr_mal: float = 0.01,
                      max_fpr_susp: float = 0.05) -> dict:
    t_mal = threshold_for_fpr(p_cal, y, max_fpr_mal)
    t_susp = min(threshold_for_fpr(p_cal, y, max_fpr_susp), t_mal)
    return {"suspicious": t_susp, "malicious": t_mal,
            "source": f"validation split, FPR<={max_fpr_susp:.0%} / FPR<={max_fpr_mal:.0%}"}


def verdict(p: float, thresholds: dict) -> str:
    if p >= thresholds["malicious"]:
        return "Malicious"
    if p >= thresholds["suspicious"]:
        return "Suspicious"
    return "Safe"
