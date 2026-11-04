"""Bootstrap confidence interval estimation for model evaluation metrics."""

from dataclasses import dataclass
from typing import Any

import numpy as np
from sklearn.metrics import (
    average_precision_score,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)


@dataclass
class ConfidenceInterval:
    estimate: float
    ci_lower: float
    ci_upper: float
    confidence_level: float = 0.95

    def to_dict(self) -> dict[str, float]:
        return {
            "estimate": self.estimate,
            "ci_lower": self.ci_lower,
            "ci_upper": self.ci_upper,
            "confidence_level": self.confidence_level,
        }


def compute_bootstrap_confidence_intervals(
    y_true: np.ndarray,
    y_probs: np.ndarray,
    threshold: float = 0.5,
    n_bootstrap: int = 500,
    seed: int = 42,
) -> dict[str, Any]:
    """Calculate 95% bootstrap confidence intervals with empirical percentiles (2.5%, 97.5%).

    Discloses sample size and class distribution.
    """
    y_true = np.array(y_true, dtype=int)
    y_probs = np.array(y_probs, dtype=float)
    y_pred = (y_probs >= threshold).astype(int)

    n_samples = len(y_true)
    rng = np.random.RandomState(seed)

    f1_boot = []
    prec_boot = []
    rec_boot = []
    roc_auc_boot = []
    pr_auc_boot = []

    for _ in range(n_bootstrap):
        boot_idx = rng.choice(n_samples, size=n_samples, replace=True)
        y_b_true = y_true[boot_idx]
        y_b_prob = y_probs[boot_idx]
        y_b_pred = y_pred[boot_idx]

        # Require both classes in bootstrap sample
        if len(np.unique(y_b_true)) < 2:
            continue

        f1_boot.append(f1_score(y_b_true, y_b_pred, zero_division=0))
        prec_boot.append(precision_score(y_b_true, y_b_pred, zero_division=0))
        rec_boot.append(recall_score(y_b_true, y_b_pred, zero_division=0))

        try:
            roc_auc_boot.append(roc_auc_score(y_b_true, y_b_prob))
        except Exception:
            pass

        try:
            pr_auc_boot.append(average_precision_score(y_b_true, y_b_prob))
        except Exception:
            pass

    def get_ci(point_est: float, boot_vals: list[float]) -> dict[str, float]:
        if not boot_vals:
            return {"estimate": point_est, "ci_lower": point_est, "ci_upper": point_est}
        lower = float(round(np.percentile(boot_vals, 2.5), 4))
        upper = float(round(np.percentile(boot_vals, 97.5), 4))
        return {
            "estimate": float(round(point_est, 4)),
            "ci_lower": lower,
            "ci_upper": upper,
            "confidence_level": 0.95,
        }

    point_f1 = f1_score(y_true, y_pred, zero_division=0)
    point_prec = precision_score(y_true, y_pred, zero_division=0)
    point_rec = recall_score(y_true, y_pred, zero_division=0)

    try:
        point_roc = roc_auc_score(y_true, y_probs)
    except Exception:
        point_roc = 0.5

    try:
        point_pr = average_precision_score(y_true, y_probs)
    except Exception:
        point_pr = float(np.mean(y_true))

    return {
        "sample_size_disclosure": {
            "total_samples": n_samples,
            "malicious_samples": int(np.sum(y_true == 1)),
            "benign_samples": int(np.sum(y_true == 0)),
            "successful_bootstrap_iterations": len(f1_boot),
        },
        "confidence_intervals": {
            "f1": get_ci(point_f1, f1_boot),
            "precision": get_ci(point_prec, prec_boot),
            "recall": get_ci(point_rec, rec_boot),
            "roc_auc": get_ci(point_roc, roc_auc_boot),
            "pr_auc": get_ci(point_pr, pr_auc_boot),
        },
    }
