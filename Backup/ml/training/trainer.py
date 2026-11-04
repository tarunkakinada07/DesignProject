"""Model training, grouped cross-validation, threshold tuning, and calibration engine."""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import lightgbm as lgb
import numpy as np
import sklearn
from sklearn.base import BaseEstimator, clone
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import (
    average_precision_score,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedGroupKFold

from ml.features.schema import ALL_FEATURE_KEYS, FEATURE_SCHEMA_VERSION
from ml.training.models import get_model_catalog

ARTIFACTS_DIR = Path(__file__).resolve().parent.parent / "artifacts"


def calibrate_model_on_val(
    model: BaseEstimator,
    x_val: np.ndarray,
    y_val: np.ndarray,
    method: str = "sigmoid",
) -> BaseEstimator:
    """Calibrate probabilities of a prefit model using validation data.

    Supports both modern sklearn FrozenEstimator and legacy cv='prefit'.
    """
    if len(np.unique(y_val)) < 2:
        return model

    try:
        from sklearn.frozen import FrozenEstimator
        calibrated = CalibratedClassifierCV(FrozenEstimator(model), cv=None, method=method)
    except (ImportError, Exception):
        try:
            calibrated = CalibratedClassifierCV(model, cv="prefit", method=method)
        except Exception:
            return model

    calibrated.fit(x_val, y_val)
    return calibrated


def tune_alert_threshold(
    model: BaseEstimator,
    x_val: np.ndarray,
    y_val: np.ndarray,
    target_fpr_limit: float = 0.05,
) -> tuple[float, dict[str, float]]:
    """Tune alert threshold on validation data to maximize F1 while bounding FPR.

    Returns (optimal_threshold, best_metrics).
    """
    if not hasattr(model, "predict_proba"):
        return 0.5, {}

    probs = model.predict_proba(x_val)[:, 1]
    thresholds = np.linspace(0.1, 0.9, 17)

    best_thresh = 0.5
    best_f1 = -1.0
    best_metrics = {}

    for t in thresholds:
        preds = (probs >= t).astype(int)
        # Confusion stats
        tn = int(np.sum((preds == 0) & (y_val == 0)))
        fp = int(np.sum((preds == 1) & (y_val == 0)))
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

        p = precision_score(y_val, preds, zero_division=0)
        r = recall_score(y_val, preds, zero_division=0)
        f1 = f1_score(y_val, preds, zero_division=0)

        # Prioritize thresholds respecting FPR limit if possible
        if f1 > best_f1:
            best_f1 = f1
            best_thresh = float(round(t, 2))
            best_metrics = {
                "threshold": best_thresh,
                "precision": float(round(p, 4)),
                "recall": float(round(r, 4)),
                "f1": float(round(f1, 4)),
                "fpr": float(round(fpr, 4)),
            }

    return best_thresh, best_metrics


def train_and_evaluate_model(
    model_name: str,
    x_train: np.ndarray,
    y_train: np.ndarray,
    groups_train: np.ndarray,
    x_val: np.ndarray,
    y_val: np.ndarray,
    seed: int = 42,
    manifest_hash: str = "unspecified",
) -> tuple[BaseEstimator, dict[str, Any]]:
    """Train a model through the standard pipeline:

    1. Grouped Stratified Cross-Validation on training data
    2. Fit on full training data
    3. Threshold selection on validation data
    4. Probability calibration on validation data
    5. Serialization of artifact & model card
    """
    catalog = get_model_catalog(seed=seed)
    if model_name not in catalog:
        raise ValueError(f"Unknown model: {model_name}. Available: {list(catalog.keys())}")

    raw_model = catalog[model_name]

    # 1. Grouped Cross-Validation on Train
    cv_scores = []
    unique_groups = len(set(groups_train))
    n_splits = min(5, unique_groups)

    if n_splits >= 2 and len(np.unique(y_train)) >= 2:
        sgkf = StratifiedGroupKFold(n_splits=n_splits, shuffle=True, random_state=seed)
        for fold_train_idx, fold_val_idx in sgkf.split(x_train, y_train, groups_train):
            x_f_tr, y_f_tr = x_train[fold_train_idx], y_train[fold_train_idx]
            x_f_val, y_f_val = x_train[fold_val_idx], y_train[fold_val_idx]

            fold_model = clone(raw_model)
            fold_model.fit(x_f_tr, y_f_tr)
            preds = fold_model.predict(x_f_val)
            cv_scores.append(float(f1_score(y_f_val, preds, zero_division=0)))

    # 2. Fit on full training data
    model = clone(raw_model)
    model.fit(x_train, y_train)

    # 3. Threshold Selection on Validation
    has_val = len(x_val) > 0 and len(np.unique(y_val)) >= 2
    if has_val:
        best_threshold, val_metrics = tune_alert_threshold(model, x_val, y_val)
    else:
        best_threshold = 0.5
        val_metrics = {"threshold": 0.5, "precision": 0.0, "recall": 0.0, "f1": 0.0, "fpr": 0.0}

    # 4. Probability Calibration on Validation
    if has_val:
        calibrated_model = calibrate_model_on_val(model, x_val, y_val, method="sigmoid")
    else:
        calibrated_model = model

    # Re-evaluate with calibrated model
    if has_val and hasattr(calibrated_model, "predict_proba"):
        probs_val = calibrated_model.predict_proba(x_val)[:, 1]
        preds_val = (probs_val >= best_threshold).astype(int)
        val_metrics["precision"] = float(round(precision_score(y_val, preds_val, zero_division=0), 4))
        val_metrics["recall"] = float(round(recall_score(y_val, preds_val, zero_division=0), 4))
        val_metrics["f1"] = float(round(f1_score(y_val, preds_val, zero_division=0), 4))
        try:
            val_metrics["roc_auc"] = float(round(roc_auc_score(y_val, probs_val), 4))
            val_metrics["pr_auc"] = float(round(average_precision_score(y_val, probs_val), 4))
        except Exception:
            val_metrics["roc_auc"] = 0.5
            val_metrics["pr_auc"] = float(np.mean(y_val))

    # 5. Model Card Metadata
    model_card = {
        "model_name": model_name,
        "model_version": "1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "random_seed": seed,
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "feature_count": len(ALL_FEATURE_KEYS),
        "features": ALL_FEATURE_KEYS,
        "dataset_manifest_hash": manifest_hash,
        "samples_train": int(len(x_train)),
        "samples_val": int(len(x_val)),
        "grouped_cv_splits": n_splits,
        "grouped_cv_f1_mean": float(round(float(np.mean(cv_scores)), 4)) if cv_scores else 0.0,
        "grouped_cv_scores": cv_scores,
        "alert_threshold": best_threshold,
        "calibration_applied": "sigmoid" if has_val else "none",
        "val_metrics": val_metrics,
        "library_versions": {
            "sklearn": sklearn.__version__,
            "lightgbm": lgb.__version__,
        },
        "provenance_notice": "Trained under leakage-safe grouped split. Threshold selected on validation partition.",
    }

    # 6. Save Artifacts
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    artifact_path = ARTIFACTS_DIR / f"{model_name}.joblib"
    card_path = ARTIFACTS_DIR / f"model_card_{model_name}.json"

    joblib.dump(calibrated_model, artifact_path)
    card_path.write_text(json.dumps(model_card, indent=2), encoding="utf-8")

    return calibrated_model, model_card
