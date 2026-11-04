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
    """Apply a mild feature-level perturbation without forcing every sample to look malicious.

    This is a sensitivity simulation, not a substitute for transforming actual JS files.
    In particular, the composite obfuscation score is not overwritten: it should be
    computed from source evidence by the feature extractor, not injected as a label-like cue.
    """
    x_obf = np.asarray(x, dtype=float).copy()
    names = feature_names or ALL_FEATURE_KEYS
    name_to_idx = {name: i for i, name in enumerate(names)}

    # Apply small, bounded shifts only to low-level features. Do not set strong indicators
    # (such as string rotation) to 1 for every benign and malicious sample.
    if "hex_identifier_count" in name_to_idx:
        idx = name_to_idx["hex_identifier_count"]
        x_obf[:, idx] += np.minimum(2.0, np.maximum(0.0, x_obf[:, idx] * 0.10))

    if "long_base64_blob_count" in name_to_idx:
        idx = name_to_idx["long_base64_blob_count"]
        x_obf[:, idx] += np.minimum(1.0, np.maximum(0.0, x_obf[:, idx] * 0.10))

    if "escape_sequence_ratio" in name_to_idx:
        idx = name_to_idx["escape_sequence_ratio"]
        # A small increase, capped at a plausible low ratio; avoid making every sample
        # cross a high-risk threshold solely because of the simulation.
        x_obf[:, idx] = np.minimum(0.02, x_obf[:, idx] + 0.002)

    if "shannon_entropy_source" in name_to_idx:
        idx = name_to_idx["shannon_entropy_source"]
        # Small shift rather than the previous large +0.8 jump.
        x_obf[:, idx] += 0.05

    # Deliberately do not force string_array_rotation_pattern = 1 and do not set
    # obfuscation_risk_score = 0.85 for every row. Those operations artificially
    # mark every benign sample as obfuscated and can make FPR hit 100% by construction.
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
