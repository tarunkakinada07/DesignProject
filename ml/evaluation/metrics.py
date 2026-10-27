"""Comprehensive model evaluation metrics with raw counts and prevalence adjustment."""

import time
from dataclasses import dataclass
from typing import Any

import numpy as np
from sklearn.metrics import (
    average_precision_score,
    brier_score_loss,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)


@dataclass
class EvaluationMetrics:
    total_samples: int
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    precision: float
    recall: float
    f1: float
    false_positive_rate: float
    false_negative_rate: float
    roc_auc: float
    pr_auc: float
    recall_at_1pct_fpr: float
    recall_at_5pct_fpr: float
    brier_score: float
    avg_inference_latency_ms: float
    precision_at_prevalence_1pct: float
    precision_at_prevalence_0_1pct: float
    prevalence_warning: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_samples": self.total_samples,
            "raw_counts": {
                "tp": self.true_positives,
                "fp": self.false_positives,
                "tn": self.true_negatives,
                "fn": self.false_negatives,
                "confusion_matrix": [
                    [self.true_negatives, self.false_positives],
                    [self.false_negatives, self.true_positives],
                ],
            },
            "rates": {
                "precision": self.precision,
                "recall": self.recall,
                "f1": self.f1,
                "false_positive_rate": self.false_positive_rate,
                "false_negative_rate": self.false_negative_rate,
                "roc_auc": self.roc_auc,
                "pr_auc": self.pr_auc,
                "recall_at_1pct_fpr": self.recall_at_1pct_fpr,
                "recall_at_5pct_fpr": self.recall_at_5pct_fpr,
                "brier_calibration_score": self.brier_score,
                "avg_inference_latency_ms": self.avg_inference_latency_ms,
            },
            "realistic_prevalence_adjustment": {
                "precision_at_1pct_prevalence": self.precision_at_prevalence_1pct,
                "precision_at_0_1pct_prevalence": self.precision_at_prevalence_0_1pct,
                "prevalence_warning": self.prevalence_warning,
            },
        }


def compute_precision_at_prevalence(
    recall: float,
    fpr: float,
    prevalence: float,
) -> float:
    """Compute expected precision at a specific real-world base rate prevalence using Bayes' theorem.

    P(Malicious | Positive) = (Recall * prevalence) / (Recall * prevalence + FPR * (1 - prevalence))
    """
    numerator = recall * prevalence
    denominator = numerator + (fpr * (1.0 - prevalence))
    if denominator <= 0.0:
        return 0.0
    return float(round(numerator / denominator, 4))


def compute_recall_at_fpr_target(
    y_true: np.ndarray,
    y_probs: np.ndarray,
    target_fpr: float,
) -> float:
    """Find maximum achievable recall when False Positive Rate is bounded by target_fpr."""
    fprs, tprs, _ = roc_curve(y_true, y_probs)
    # Find all operating points where FPR <= target_fpr
    valid_tprs = [tpr for fpr, tpr in zip(fprs, tprs, strict=False) if fpr <= target_fpr]
    if not valid_tprs:
        return 0.0
    return float(round(max(valid_tprs), 4))


def evaluate_predictions(
    y_true: np.ndarray,
    y_probs: np.ndarray,
    threshold: float = 0.5,
    benchmark_model: Any | None = None,
    x_test_benchmark: np.ndarray | None = None,
) -> EvaluationMetrics:
    """Compute comprehensive evaluation metrics on held-out test predictions."""
    y_true = np.array(y_true, dtype=int)
    y_probs = np.array(y_probs, dtype=float)
    y_pred = (y_probs >= threshold).astype(int)

    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = int(cm[0, 0]), int(cm[0, 1]), int(cm[1, 0]), int(cm[1, 1])

    prec = float(round(precision_score(y_true, y_pred, zero_division=0), 4))
    rec = float(round(recall_score(y_true, y_pred, zero_division=0), 4))
    f1 = float(round(f1_score(y_true, y_pred, zero_division=0), 4))

    fpr = float(round(fp / (fp + tn), 4)) if (fp + tn) > 0 else 0.0
    fnr = float(round(fn / (fn + tp), 4)) if (fn + tp) > 0 else 0.0

    try:
        roc_auc = float(round(roc_auc_score(y_true, y_probs), 4))
    except Exception:
        roc_auc = 0.5

    try:
        pr_auc = float(round(average_precision_score(y_true, y_probs), 4))
    except Exception:
        pr_auc = float(round(np.mean(y_true), 4))

    rec_1pct = compute_recall_at_fpr_target(y_true, y_probs, 0.01)
    rec_5pct = compute_recall_at_fpr_target(y_true, y_probs, 0.05)

    try:
        brier = float(round(brier_score_loss(y_true, y_probs), 4))
    except Exception:
        brier = 0.25

    # Benchmark inference latency
    latency_ms = 0.0
    if benchmark_model is not None and x_test_benchmark is not None and len(x_test_benchmark) > 0:
        start_t = time.perf_counter()
        _ = benchmark_model.predict_proba(x_test_benchmark) if hasattr(benchmark_model, "predict_proba") else benchmark_model.predict(x_test_benchmark)
        elapsed = time.perf_counter() - start_t
        latency_ms = float(round((elapsed / len(x_test_benchmark)) * 1000.0, 4))

    # Real-world prevalence calculations
    prec_1pct = compute_precision_at_prevalence(rec, fpr, 0.01)
    prec_0_1pct = compute_precision_at_prevalence(rec, fpr, 0.001)

    prev_warning = (
        "PREVALENCE WARNING: In real-world browser extension stores, malicious extensions "
        "represent a small fraction (e.g., 0.1% to 1.0%). Test set precision evaluated on a "
        "balanced or enriched dataset severely overstates in-the-wild precision due to base rate fallacy. "
        f"At 1.0% prevalence, expected precision is {prec_1pct * 100:.1f}%; "
        f"at 0.1% prevalence, expected precision is {prec_0_1pct * 100:.2f}%."
    )

    return EvaluationMetrics(
        total_samples=len(y_true),
        true_positives=tp,
        false_positives=fp,
        true_negatives=tn,
        false_negatives=fn,
        precision=prec,
        recall=rec,
        f1=f1,
        false_positive_rate=fpr,
        false_negative_rate=fnr,
        roc_auc=roc_auc,
        pr_auc=pr_auc,
        recall_at_1pct_fpr=rec_1pct,
        recall_at_5pct_fpr=rec_5pct,
        brier_score=brier,
        avg_inference_latency_ms=latency_ms,
        precision_at_prevalence_1pct=prec_1pct,
        precision_at_prevalence_0_1pct=prec_0_1pct,
        prevalence_warning=prev_warning,
    )
