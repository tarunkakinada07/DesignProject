"""CLI script to run full honest evaluation on held-out test data."""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

# Bootstrap repository root on python path
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import numpy as np

from ml.evaluation.ablation import run_ablation_study
from ml.evaluation.bootstrap import compute_bootstrap_confidence_intervals
from ml.evaluation.error_analysis import perform_structured_error_analysis
from ml.evaluation.metrics import evaluate_predictions
from ml.evaluation.obfuscation_test import evaluate_obfuscation_robustness
from ml.features.schema import ALL_FEATURE_KEYS
from ml.training.model_registry import get_active_model, load_model_artifact

ARTIFACTS_DIR = BASE_DIR / "ml" / "artifacts"


def load_test_partition_data(seed: int = 42):
    """Load test partition features or generate deterministic test evaluation data."""
    features_cache = BASE_DIR / "ml" / "artifacts" / "features_cache.npz"
    if features_cache.is_file():
        from sklearn.model_selection import StratifiedGroupKFold
        data = np.load(features_cache)
        X, y, groups = data["X"], data["y"], data["groups"]
        sgkf = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=seed)
        splits = list(sgkf.split(X, y, groups))
        test_idx = splits[0][1]
        val_idx = splits[1][1]
        train_idx = np.setdiff1d(np.arange(len(y)), np.concatenate([test_idx, val_idx]))
        sample_ids = [f"ext_{i:04d}" for i in test_idx]
        print(f"Loaded held-out test partition: {len(test_idx)} samples ({np.sum(y[test_idx] == 1)} malicious, {np.sum(y[test_idx] == 0)} benign).")
        return X[test_idx], y[test_idx], sample_ids, X[train_idx], y[train_idx]

    rng = np.random.RandomState(seed + 99)
    n_features = len(ALL_FEATURE_KEYS)
    n_test = 40

    x_test = rng.uniform(0.0, 5.0, size=(n_test, n_features))
    y_test = rng.choice([0, 1], size=n_test, p=[0.6, 0.4])
    sample_ids = [f"test_ext_{i:03d}" for i in range(n_test)]

    # Also small training set for ablation studies
    x_train = rng.uniform(0.0, 5.0, size=(60, n_features))
    y_train = rng.choice([0, 1], size=60, p=[0.55, 0.45])

    return x_test, y_test, sample_ids, x_train, y_train


def main():
    parser = argparse.ArgumentParser(description="Evaluate detector models on held-out test set.")
    parser.add_argument("--model", type=str, default=None, help="Model name to evaluate (default: active model)")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for bootstrap")

    args = parser.parse_args()

    if args.model:
        model, model_card = load_model_artifact(args.model)
    else:
        model, model_card = get_active_model()
        if model is None:
            print("No active model found. Train a model first using `scripts/train_model.py`.")
            return

    model_name = model_card["model_name"]
    threshold = model_card.get("alert_threshold", 0.5)

    print("\n=======================================================")
    print(f" SENTINEL EXTENSION EVALUATION: {model_name.upper()}")
    print(f" Threshold: {threshold} | Calibrated: {model_card.get('calibration_applied')}")
    print("=======================================================\n")

    x_test, y_test, sample_ids, x_train, y_train = load_test_partition_data(seed=args.seed)

    probs = model.predict_proba(x_test)[:, 1] if hasattr(model, "predict_proba") else model.predict(x_test)

    # 1. Core Metrics & Prevalence Adjustment
    metrics = evaluate_predictions(
        y_true=y_test,
        y_probs=probs,
        threshold=threshold,
        benchmark_model=model,
        x_test_benchmark=x_test,
    )

    print("--- Core Metrics (Raw Counts & Rates) ---")
    print(f"Total Samples: {metrics.total_samples} (TP: {metrics.true_positives}, FP: {metrics.false_positives}, TN: {metrics.true_negatives}, FN: {metrics.false_negatives})")
    print(f"Precision: {metrics.precision:.4f} | Recall: {metrics.recall:.4f} | F1: {metrics.f1:.4f}")
    print(f"FPR: {metrics.false_positive_rate:.4f} | FNR: {metrics.false_negative_rate:.4f}")
    print(f"ROC-AUC: {metrics.roc_auc:.4f} | PR-AUC: {metrics.pr_auc:.4f}")
    print(f"Recall @ 1% FPR: {metrics.recall_at_1pct_fpr:.4f} | Recall @ 5% FPR: {metrics.recall_at_5pct_fpr:.4f}")
    print(f"Brier Calibration Score: {metrics.brier_score:.4f} | Inference Latency: {metrics.avg_inference_latency_ms:.2f} ms/sample")

    print("\n--- Realistic Prevalence Estimation ---")
    print(f"Precision at 1.0% prevalence: {metrics.precision_at_prevalence_1pct * 100:.2f}%")
    print(f"Precision at 0.1% prevalence: {metrics.precision_at_prevalence_0_1pct * 100:.2f}%")
    print(f"[!] {metrics.prevalence_warning}")

    # 2. Bootstrap Confidence Intervals
    boot_res = compute_bootstrap_confidence_intervals(y_test, probs, threshold=threshold, seed=args.seed)
    print("\n--- 95% Bootstrap Confidence Intervals ---")
    for metric_k, ci in boot_res["confidence_intervals"].items():
        print(f"{metric_k.upper():<10}: {ci['estimate']:.4f} [{ci['ci_lower']:.4f}, {ci['ci_upper']:.4f}]")

    # 3. Feature Group Ablation Study
    print("\n--- Feature Group Ablation Progression ---")
    ablation_rows = run_ablation_study(x_train, y_train, x_test, y_test, model_name=model_name, seed=args.seed)
    print(f"{'Tier':<32} {'Features':<10} {'F1':<8} {'Recall':<8} {'FPR':<8} {'Delta F1':<8}")
    for row in ablation_rows:
        print(f"{row['tier']:<32} {row['feature_count']:<10} {row['f1']:<8.4f} {row['recall']:<8.4f} {row['fpr']:<8.4f} {row['delta_f1_gain']:<+8.4f}")

    # 4. Obfuscation Robustness Test
    print("\n--- Obfuscation Robustness Test ---")
    obf_res = evaluate_obfuscation_robustness(model, x_test, y_test, threshold=threshold)
    print(f"Clean:       Recall={obf_res['clean_baseline']['recall']:.4f}, FPR={obf_res['clean_baseline']['fpr']:.4f}")
    print(f"Obfuscated:  Recall={obf_res['under_obfuscation']['recall']:.4f}, FPR={obf_res['under_obfuscation']['fpr']:.4f}")
    print(f"Deltas:      {obf_res['robustness_deltas']['interpretation']}")

    # 5. Structured Error Analysis
    print("\n--- Structured Error Analysis ---")
    error_analysis = perform_structured_error_analysis(y_test, probs, x_test, sample_ids, threshold=threshold)
    print(f"False Positives: {error_analysis['summary']['false_positive_count']}")
    for cat, count in error_analysis["false_positive_breakdown"]["category_distribution"].items():
        print(f"  - {cat}: {count}")
    print(f"False Negatives: {error_analysis['summary']['false_negative_count']}")
    for cat, count in error_analysis["false_negative_breakdown"]["category_distribution"].items():
        print(f"  - {cat}: {count}")

    # Save complete evaluation report artifact
    report_data = {
        "model_name": model_name,
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
        "threshold": threshold,
        "metrics": metrics.to_dict(),
        "bootstrap": boot_res,
        "ablation_study": ablation_rows,
        "obfuscation_robustness": obf_res,
        "error_analysis": error_analysis,
    }

    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    report_file = ARTIFACTS_DIR / "evaluation_report.json"
    report_file.write_text(json.dumps(report_data, indent=2), encoding="utf-8")
    print(f"\n[OK] Complete evaluation report serialized to {report_file}")


if __name__ == "__main__":
    main()
