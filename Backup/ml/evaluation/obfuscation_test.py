"""Obfuscation robustness test suite.

Simulates standard JavaScript obfuscator transformations (hex identifier mangling,
string-array extraction, base64 payload encoding, entropy elevation) on a held-out
evaluation set and measures shifts in False Positive Rate (FPR) and Malicious Recall.
"""

from typing import Any

import numpy as np
from sklearn.base import BaseEstimator
from sklearn.metrics import f1_score, precision_score, recall_score

from ml.evaluation.source_obfuscation_suite import run_source_level_obfuscation_suite
from ml.features.schema import ALL_FEATURE_KEYS


def apply_synthetic_obfuscation_transform(
    x: np.ndarray,
    feature_names: list[str] | None = None,
) -> np.ndarray:
    """Simulate the effect of JavaScript obfuscation tools (e.g. Obfuscator.io) on static features."""
    x_obf = x.copy()
    names = feature_names or ALL_FEATURE_KEYS
    name_to_idx = {name: i for i, name in enumerate(names)}

    # 1. Hex identifiers increase significantly
    if "hex_identifier_count" in name_to_idx:
        x_obf[:, name_to_idx["hex_identifier_count"]] += 15.0

    # 2. String array rotation loops introduced
    if "string_array_rotation_pattern" in name_to_idx:
        x_obf[:, name_to_idx["string_array_rotation_pattern"]] = 1.0

    # 3. Base64 and hex blobs generated
    if "long_base64_blob_count" in name_to_idx:
        x_obf[:, name_to_idx["long_base64_blob_count"]] += 4.0

    # 4. Escape sequence density increases
    if "escape_sequence_ratio" in name_to_idx:
        x_obf[:, name_to_idx["escape_sequence_ratio"]] = np.maximum(
            x_obf[:, name_to_idx["escape_sequence_ratio"]], 0.05
        )

    # 5. Obfuscation composite risk score jumps
    if "obfuscation_risk_score" in name_to_idx:
        x_obf[:, name_to_idx["obfuscation_risk_score"]] = 0.85

    # 6. Source entropy elevates
    if "shannon_entropy_source" in name_to_idx:
        x_obf[:, name_to_idx["shannon_entropy_source"]] += 0.8

    return x_obf


def evaluate_obfuscation_robustness(
    model: BaseEstimator,
    x_test: np.ndarray,
    y_test: np.ndarray,
    threshold: float = 0.5,
) -> dict[str, Any]:
    """Compare detection performance on clean test set vs obfuscated test set."""
    y_test = np.array(y_test, dtype=int)

    # Clean evaluation
    clean_probs = model.predict_proba(x_test)[:, 1] if hasattr(model, "predict_proba") else model.predict(x_test)
    clean_preds = (clean_probs >= threshold).astype(int)

    clean_rec = float(round(recall_score(y_test, clean_preds, zero_division=0), 4))
    clean_prec = float(round(precision_score(y_test, clean_preds, zero_division=0), 4))
    clean_f1 = float(round(f1_score(y_test, clean_preds, zero_division=0), 4))

    tn_c = int(np.sum((clean_preds == 0) & (y_test == 0)))
    fp_c = int(np.sum((clean_preds == 1) & (y_test == 0)))
    clean_fpr = float(round(fp_c / (fp_c + tn_c), 4)) if (fp_c + tn_c) > 0 else 0.0

    # Obfuscated evaluation
    x_obf = apply_synthetic_obfuscation_transform(x_test)
    obf_probs = model.predict_proba(x_obf)[:, 1] if hasattr(model, "predict_proba") else model.predict(x_obf)
    obf_preds = (obf_probs >= threshold).astype(int)

    obf_rec = float(round(recall_score(y_test, obf_preds, zero_division=0), 4))
    obf_prec = float(round(precision_score(y_test, obf_preds, zero_division=0), 4))
    obf_f1 = float(round(f1_score(y_test, obf_preds, zero_division=0), 4))

    tn_o = int(np.sum((obf_preds == 0) & (y_test == 0)))
    fp_o = int(np.sum((obf_preds == 1) & (y_test == 0)))
    obf_fpr = float(round(fp_o / (fp_o + tn_o), 4)) if (fp_o + tn_o) > 0 else 0.0

    delta_rec = float(round(obf_rec - clean_rec, 4))
    delta_fpr = float(round(obf_fpr - clean_fpr, 4))

    source_suite_results = run_source_level_obfuscation_suite()

    return {
        "clean_baseline": {
            "recall": clean_rec,
            "precision": clean_prec,
            "f1": clean_f1,
            "fpr": clean_fpr,
        },
        "under_obfuscation": {
            "recall": obf_rec,
            "precision": obf_prec,
            "f1": obf_f1,
            "fpr": obf_fpr,
        },
        "robustness_deltas": {
            "delta_recall": delta_rec,
            "delta_fpr": delta_fpr,
            "interpretation": (
                f"Recall shifted by {delta_rec * 100:+.1f}%, while False Positive Rate changed by {delta_fpr * 100:+.1f}% "
                "under simulated standard JS obfuscation."
            ),
        },
        "source_level_suite": source_suite_results,
    }
