"""Feature group ablation experiment suite.

Ablation sequence (evaluated under identical protocol, folds, and seeds):
1. Manifest only (Group A)
2. Manifest + JavaScript static (Group A + Group B)
3. Manifest + JS static + Obfuscation (Group A + Group B + Group C)
4. Full Tier 1: Manifest + JS + Obfuscation + Behavior combinations (Groups A + B + C + D)
"""

from typing import Any

import numpy as np
from sklearn.base import clone
from sklearn.metrics import average_precision_score, f1_score, precision_score, recall_score

from ml.features.schema import (
    ALL_FEATURE_KEYS,
    GROUP_A_FEATURES,
    GROUP_B_FEATURES,
    GROUP_C_FEATURES,
)
from ml.training.models import get_model_catalog

ABLATION_TIERS = [
    ("1_manifest_only", GROUP_A_FEATURES),
    ("2_manifest_and_js_static", GROUP_A_FEATURES + GROUP_B_FEATURES),
    ("3_manifest_js_obfuscation", GROUP_A_FEATURES + GROUP_B_FEATURES + GROUP_C_FEATURES),
    ("4_full_tier1_all", ALL_FEATURE_KEYS),
]


def run_ablation_study(
    x_train: np.ndarray,
    y_train: np.ndarray,
    x_test: np.ndarray,
    y_test: np.ndarray,
    model_name: str = "random_forest",
    seed: int = 42,
) -> list[dict[str, Any]]:
    """Execute feature group ablation study.

    Returns list of evaluation result dicts per feature group tier.
    """
    catalog = get_model_catalog(seed=seed)
    base_model = catalog.get(model_name, catalog["random_forest"])

    feature_name_to_idx = {name: i for i, name in enumerate(ALL_FEATURE_KEYS)}
    ablation_results = []
    prev_f1 = 0.0

    for tier_name, feature_subset in ABLATION_TIERS:
        # Extract columns for this feature subset
        col_indices = [feature_name_to_idx[feat] for feat in feature_subset if feat in feature_name_to_idx]
        x_tr_sub = x_train[:, col_indices]
        x_te_sub = x_test[:, col_indices]

        # Train under identical protocol
        model = clone(base_model)
        model.fit(x_tr_sub, y_train)

        probs = model.predict_proba(x_te_sub)[:, 1] if hasattr(model, "predict_proba") else model.predict(x_te_sub)
        preds = (probs >= 0.5).astype(int)

        prec = float(round(precision_score(y_test, preds, zero_division=0), 4))
        rec = float(round(recall_score(y_test, preds, zero_division=0), 4))
        f1 = float(round(f1_score(y_test, preds, zero_division=0), 4))

        tn = int(np.sum((preds == 0) & (y_test == 0)))
        fp = int(np.sum((preds == 1) & (y_test == 0)))
        fpr = float(round(fp / (fp + tn), 4)) if (fp + tn) > 0 else 0.0

        try:
            pr_auc = float(round(average_precision_score(y_test, probs), 4))
        except Exception:
            pr_auc = float(round(np.mean(y_test), 4))

        delta_f1 = float(round(f1 - prev_f1, 4))
        prev_f1 = f1

        ablation_results.append({
            "tier": tier_name,
            "feature_count": len(col_indices),
            "precision": prec,
            "recall": rec,
            "f1": f1,
            "fpr": fpr,
            "pr_auc": pr_auc,
            "delta_f1_gain": delta_f1,
        })

    return ablation_results
