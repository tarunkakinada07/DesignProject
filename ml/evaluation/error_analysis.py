"""Structured error analysis for False Positives (FP) and False Negatives (FN).

Categorizes failure modes to guide transparent model limitations reporting:
- False Positives: Over-privileged developer extensions, ad blockers using webRequest, high minification.
- False Negatives: Low-privilege stealthy stealers, evasion of static keyword patterns.
"""

from typing import Any

import numpy as np

from ml.features.schema import ALL_FEATURE_KEYS


def categorize_false_positive(
    feature_row: np.ndarray,
    feature_names: list[str],
) -> str:
    """Categorize probable reason for a False Positive classification."""
    name_to_idx = {name: i for i, name in enumerate(feature_names)}

    idx_broad = name_to_idx.get("has_broad_host_access")
    idx_webreq = name_to_idx.get("call_chrome_webrequest")
    idx_perms = name_to_idx.get("perm_count_high_risk")
    idx_minified = name_to_idx.get("is_minified_heuristic")
    idx_entropy = name_to_idx.get("shannon_entropy_source")

    if idx_webreq is not None and feature_row[idx_webreq] > 0 and idx_broad is not None and feature_row[idx_broad] > 0:
        return "Ad-blocker / network tool utility pattern (legitimate webRequest + broad host)"
    elif idx_perms is not None and feature_row[idx_perms] >= 3:
        return "Over-privileged developer/productivity tool requesting broad capabilities"
    elif idx_minified is not None and feature_row[idx_minified] > 0:
        return "Aggressive production bundle minification with long lines"
    elif idx_entropy is not None and feature_row[idx_entropy] > 5.0:
        return "High entropy embedded assets or localization bundles"
    return "Heuristic threshold boundary trigger without explicit malicious intent"


def categorize_false_negative(
    feature_row: np.ndarray,
    feature_names: list[str],
) -> str:
    """Categorize probable reason for a False Negative classification."""
    name_to_idx = {name: i for i, name in enumerate(feature_names)}

    idx_high_perms = name_to_idx.get("perm_count_high_risk")
    idx_eval = name_to_idx.get("call_eval")
    idx_obf = name_to_idx.get("obfuscation_risk_score")

    if idx_high_perms is not None and feature_row[idx_high_perms] == 0:
        return "Stealthy low-privilege architecture (requests zero high-risk manifest permissions)"
    elif idx_eval is not None and feature_row[idx_eval] == 0 and idx_obf is not None and feature_row[idx_obf] < 0.2:
        return "Clean, unobfuscated code style with delayed logic activation"
    return "Static feature evasion or unseen external domain indicators"


def perform_structured_error_analysis(
    y_true: np.ndarray,
    y_probs: np.ndarray,
    x_matrix: np.ndarray,
    sample_ids: list[str],
    threshold: float = 0.5,
    feature_names: list[str] | None = None,
) -> dict[str, Any]:
    """Perform detailed breakdown of all False Positives and False Negatives."""
    names = feature_names or ALL_FEATURE_KEYS
    y_true = np.array(y_true, dtype=int)
    y_probs = np.array(y_probs, dtype=float)
    y_pred = (y_probs >= threshold).astype(int)

    fp_cases = []
    fn_cases = []

    for i in range(len(y_true)):
        actual = y_true[i]
        predicted = y_pred[i]
        prob = float(round(y_probs[i], 4))
        sid = sample_ids[i] if i < len(sample_ids) else f"sample_{i}"
        row = x_matrix[i]

        if actual == 0 and predicted == 1:
            category = categorize_false_positive(row, names)
            fp_cases.append({
                "sample_id": sid,
                "predicted_probability": prob,
                "failure_category": category,
            })
        elif actual == 1 and predicted == 0:
            category = categorize_false_negative(row, names)
            fn_cases.append({
                "sample_id": sid,
                "predicted_probability": prob,
                "failure_category": category,
            })

    # Summary of error category frequencies
    fp_categories = {}
    for c in fp_cases:
        cat = c["failure_category"]
        fp_categories[cat] = fp_categories.get(cat, 0) + 1

    fn_categories = {}
    for c in fn_cases:
        cat = c["failure_category"]
        fn_categories[cat] = fn_categories.get(cat, 0) + 1

    return {
        "summary": {
            "total_evaluated": len(y_true),
            "false_positive_count": len(fp_cases),
            "false_negative_count": len(fn_cases),
        },
        "false_positive_breakdown": {
            "category_distribution": fp_categories,
            "sample_cases": fp_cases[:10],
        },
        "false_negative_breakdown": {
            "category_distribution": fn_categories,
            "sample_cases": fn_cases[:10],
        },
        "external_benchmark_disclaimer": (
            "NOTICE: These metrics represent internal held-out validation under grouped splitting. "
            "They must never be claimed as a world-best accuracy claim on unseen real-world distributions."
        ),
    }
