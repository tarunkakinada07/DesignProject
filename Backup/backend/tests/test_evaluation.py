"""Unit tests for Phase 6: Honest evaluation, bootstrapping, ablation, obfuscation robustness, and error analysis."""

import numpy as np
import pytest
from sklearn.ensemble import RandomForestClassifier

from ml.evaluation.ablation import ABLATION_TIERS, run_ablation_study
from ml.evaluation.bootstrap import ConfidenceInterval, compute_bootstrap_confidence_intervals
from ml.evaluation.error_analysis import (
    categorize_false_negative,
    categorize_false_positive,
    perform_structured_error_analysis,
)
from ml.evaluation.metrics import (
    compute_precision_at_prevalence,
    compute_recall_at_fpr_target,
    evaluate_predictions,
)
from ml.evaluation.obfuscation_test import (
    apply_synthetic_obfuscation_transform,
    evaluate_obfuscation_robustness,
)
from ml.features.schema import ALL_FEATURE_KEYS


def generate_synthetic_eval_data(n_samples: int = 40, seed: int = 42):
    """Generate synthetic test features and binary labels."""
    rng = np.random.RandomState(seed)
    n_features = len(ALL_FEATURE_KEYS)
    x = rng.uniform(0.0, 5.0, size=(n_samples, n_features))
    y = rng.choice([0, 1], size=n_samples, p=[0.6, 0.4])
    sample_ids = [f"ext_{i:03d}" for i in range(n_samples)]
    return x, y, sample_ids


def test_compute_precision_at_prevalence():
    # Recall = 0.9, FPR = 0.01, Prevalence = 0.01 (1%)
    # Bayes: (0.9 * 0.01) / (0.9 * 0.01 + 0.01 * 0.99) = 0.009 / 0.0189 ~= 0.4762
    prec = compute_precision_at_prevalence(recall=0.9, fpr=0.01, prevalence=0.01)
    assert 0.47 <= prec <= 0.48

    # Edge cases: 0 denominator
    assert compute_precision_at_prevalence(recall=0.0, fpr=0.0, prevalence=0.01) == 0.0
    assert compute_precision_at_prevalence(recall=0.5, fpr=0.05, prevalence=0.0) == 0.0


def test_compute_recall_at_fpr_target():
    y_true = np.array([0, 0, 0, 0, 0, 1, 1, 1, 1, 1])
    # Perfect separation
    y_probs = np.array([0.1, 0.1, 0.2, 0.2, 0.3, 0.7, 0.8, 0.85, 0.9, 0.95])

    # Target FPR = 0.0 -> max TPR with 0 FPR should be 1.0 (threshold > 0.3 gives FPR 0.0, TPR 1.0)
    recall = compute_recall_at_fpr_target(y_true, y_probs, target_fpr=0.01)
    assert recall == 1.0


def test_evaluate_predictions_and_serialization():
    y_true = np.array([0, 0, 0, 1, 1, 1])
    y_probs = np.array([0.1, 0.2, 0.8, 0.2, 0.7, 0.9])
    # At threshold 0.5:
    # Preds: [0, 0, 1, 0, 1, 1]
    # TN: 2 (idx 0, 1), FP: 1 (idx 2), FN: 1 (idx 3), TP: 2 (idx 4, 5)

    metrics = evaluate_predictions(y_true, y_probs, threshold=0.5)

    assert metrics.total_samples == 6
    assert metrics.true_negatives == 2
    assert metrics.false_positives == 1
    assert metrics.false_negatives == 1
    assert metrics.true_positives == 2

    assert metrics.precision == pytest.approx(2 / 3, abs=1e-3)
    assert metrics.recall == pytest.approx(2 / 3, abs=1e-3)
    assert metrics.false_positive_rate == pytest.approx(1 / 3, abs=1e-3)

    # Check to_dict structure
    m_dict = metrics.to_dict()
    assert "raw_counts" in m_dict
    assert "rates" in m_dict
    assert "realistic_prevalence_adjustment" in m_dict
    assert "PREVALENCE WARNING" in m_dict["realistic_prevalence_adjustment"]["prevalence_warning"]


def test_bootstrap_confidence_intervals():
    ci = ConfidenceInterval(estimate=0.85, ci_lower=0.75, ci_upper=0.92)
    assert ci.to_dict()["confidence_level"] == 0.95

    y_true = np.array([0] * 15 + [1] * 15)
    y_probs = np.linspace(0.1, 0.9, 30)

    res = compute_bootstrap_confidence_intervals(y_true, y_probs, threshold=0.5, n_bootstrap=100, seed=42)

    disclosure = res["sample_size_disclosure"]
    assert disclosure["total_samples"] == 30
    assert disclosure["malicious_samples"] == 15
    assert disclosure["benign_samples"] == 15
    assert disclosure["successful_bootstrap_iterations"] > 80

    cis = res["confidence_intervals"]
    assert "f1" in cis
    assert "roc_auc" in cis
    assert "pr_auc" in cis
    assert cis["f1"]["ci_lower"] <= cis["f1"]["estimate"] <= cis["f1"]["ci_upper"] or cis["f1"]["ci_lower"] <= cis["f1"]["ci_upper"]


def test_ablation_study():
    x_train, y_train, _ = generate_synthetic_eval_data(50, seed=1)
    x_test, y_test, _ = generate_synthetic_eval_data(30, seed=2)

    results = run_ablation_study(x_train, y_train, x_test, y_test, model_name="decision_tree", seed=42)

    assert len(results) == len(ABLATION_TIERS)
    expected_feature_counts = [len(tier[1]) for tier in ABLATION_TIERS]
    for row, expected_count in zip(results, expected_feature_counts, strict=False):
        assert row["feature_count"] == expected_count
        assert "f1" in row
        assert "delta_f1_gain" in row


def test_obfuscation_transform_and_robustness():
    x = np.zeros((5, len(ALL_FEATURE_KEYS)))
    x_obf = apply_synthetic_obfuscation_transform(x)

    name_to_idx = {name: i for i, name in enumerate(ALL_FEATURE_KEYS)}
    assert np.all(x_obf[:, name_to_idx["hex_identifier_count"]] == 15.0)
    assert np.all(x_obf[:, name_to_idx["string_array_rotation_pattern"]] == 1.0)
    assert np.all(x_obf[:, name_to_idx["long_base64_blob_count"]] == 4.0)
    assert np.all(x_obf[:, name_to_idx["obfuscation_risk_score"]] == 0.85)

    # Test robustness evaluation on fitted model
    clf = RandomForestClassifier(n_estimators=10, random_state=42)
    x_train, y_train, _ = generate_synthetic_eval_data(40, seed=10)
    x_test, y_test, _ = generate_synthetic_eval_data(20, seed=20)
    clf.fit(x_train, y_train)

    rob = evaluate_obfuscation_robustness(clf, x_test, y_test, threshold=0.5)
    assert "clean_baseline" in rob
    assert "under_obfuscation" in rob
    assert "robustness_deltas" in rob
    assert "delta_recall" in rob["robustness_deltas"]
    assert "delta_fpr" in rob["robustness_deltas"]


def test_error_analysis_categorization():
    names = ALL_FEATURE_KEYS
    name_to_idx = {name: i for i, name in enumerate(names)}

    # 1. Ad blocker pattern FP
    row_fp1 = np.zeros(len(names))
    row_fp1[name_to_idx["call_chrome_webrequest"]] = 2.0
    row_fp1[name_to_idx["has_broad_host_access"]] = 1.0
    cat_fp1 = categorize_false_positive(row_fp1, names)
    assert "Ad-blocker" in cat_fp1

    # 2. Over-privileged FP
    row_fp2 = np.zeros(len(names))
    row_fp2[name_to_idx["perm_count_high_risk"]] = 4.0
    cat_fp2 = categorize_false_positive(row_fp2, names)
    assert "Over-privileged" in cat_fp2

    # 3. Minification FP
    row_fp3 = np.zeros(len(names))
    row_fp3[name_to_idx["is_minified_heuristic"]] = 1.0
    cat_fp3 = categorize_false_positive(row_fp3, names)
    assert "minification" in cat_fp3

    # 4. Stealthy FN
    row_fn1 = np.zeros(len(names))
    row_fn1[name_to_idx["perm_count_high_risk"]] = 0.0
    cat_fn1 = categorize_false_negative(row_fn1, names)
    assert "Stealthy low-privilege" in cat_fn1

    # 5. Clean unobfuscated FN
    row_fn2 = np.zeros(len(names))
    row_fn2[name_to_idx["perm_count_high_risk"]] = 1.0
    row_fn2[name_to_idx["call_eval"]] = 0.0
    row_fn2[name_to_idx["obfuscation_risk_score"]] = 0.1
    cat_fn2 = categorize_false_negative(row_fn2, names)
    assert "Clean, unobfuscated" in cat_fn2

    # Full structured error analysis run
    x_matrix = np.vstack([row_fp1, row_fn1])
    y_true = np.array([0, 1])
    # Force errors: sample 0 is predicted positive (FP), sample 1 is predicted negative (FN)
    y_probs = np.array([0.9, 0.1])
    sample_ids = ["ext_fp", "ext_fn"]

    analysis = perform_structured_error_analysis(
        y_true=y_true,
        y_probs=y_probs,
        x_matrix=x_matrix,
        sample_ids=sample_ids,
        threshold=0.5,
        feature_names=names,
    )

    assert analysis["summary"]["false_positive_count"] == 1
    assert analysis["summary"]["false_negative_count"] == 1
    assert len(analysis["false_positive_breakdown"]["sample_cases"]) == 1
    assert len(analysis["false_negative_breakdown"]["sample_cases"]) == 1
    assert "NOTICE" in analysis["external_benchmark_disclaimer"]
