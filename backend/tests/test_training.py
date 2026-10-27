"""Unit and integration tests for Phase 5: Model training, calibration, and secure registry."""

from pathlib import Path

import numpy as np
import pytest

from ml.features.schema import ALL_FEATURE_KEYS, FEATURE_SCHEMA_VERSION
from ml.training.baselines import HeuristicRuleBaseline, MajorityClassBaseline
from ml.training.model_registry import (
    UntrustedModelPathError,
    get_active_model,
    load_model_artifact,
    set_active_model,
)
from ml.training.models import get_model_catalog
from ml.training.trainer import (
    calibrate_model_on_val,
    train_and_evaluate_model,
    tune_alert_threshold,
)


def generate_synthetic_feature_data(n_samples: int = 60, seed: int = 42):
    """Generate synthetic feature matrix matching ALL_FEATURE_KEYS."""
    rng = np.random.RandomState(seed)
    n_features = len(ALL_FEATURE_KEYS)
    x = rng.uniform(0.0, 5.0, size=(n_samples, n_features))
    y = rng.choice([0, 1], size=n_samples, p=[0.6, 0.4])
    # 10 clusters
    groups = np.array([f"cluster_{i % 10}" for i in range(n_samples)])
    return x, y, groups


def test_majority_baseline():
    x, y, _ = generate_synthetic_feature_data(30)
    base = MajorityClassBaseline()
    base.fit(x, y)
    preds = base.predict(x)
    probs = base.predict_proba(x)

    assert len(preds) == len(y)
    assert probs.shape == (len(y), 2)
    # All predictions should be the most common class
    most_common = 1 if np.sum(y == 1) > np.sum(y == 0) else 0
    assert np.all(preds == most_common)


def test_heuristic_rule_baseline():
    n_features = len(ALL_FEATURE_KEYS)
    x = np.zeros((3, n_features))
    np.array([0, 1, 1])

    name_to_idx = {name: i for i, name in enumerate(ALL_FEATURE_KEYS)}

    # Sample 0: clean
    # Sample 1: flag_cookies_broadhost_network set
    x[1, name_to_idx["flag_cookies_broadhost_network"]] = 1.0
    # Sample 2: obfuscation_risk_score >= 0.50
    x[2, name_to_idx["obfuscation_risk_score"]] = 0.80

    rule = HeuristicRuleBaseline(feature_names=ALL_FEATURE_KEYS)
    preds = rule.predict(x)
    probs = rule.predict_proba(x)

    assert preds[0] == 0
    assert preds[1] == 1
    assert preds[2] == 1
    assert probs[1, 1] >= 0.85


def test_model_catalog_keys():
    catalog = get_model_catalog(seed=42)
    expected_models = {
        "majority_baseline",
        "heuristic_rule",
        "logistic_regression",
        "decision_tree",
        "random_forest",
        "svm",
        "lightgbm",
    }
    assert expected_models.issubset(catalog.keys())


def test_threshold_tuning_and_calibration():
    from sklearn.linear_model import LogisticRegression

    x_tr, y_tr, _ = generate_synthetic_feature_data(40, seed=1)
    x_val, y_val, _ = generate_synthetic_feature_data(20, seed=2)

    clf = LogisticRegression().fit(x_tr, y_tr)

    # Threshold tuning
    thresh, metrics = tune_alert_threshold(clf, x_val, y_val)
    assert 0.1 <= thresh <= 0.9
    assert "f1" in metrics

    # Probability calibration
    calibrated = calibrate_model_on_val(clf, x_val, y_val)
    probs = calibrated.predict_proba(x_val)
    assert probs.shape == (len(x_val), 2)
    assert np.all((probs >= 0.0) & (probs <= 1.0))


def test_full_model_training_progression(tmp_path: Path, monkeypatch):
    import ml.training.model_registry as mr
    import ml.training.trainer as tr

    test_art_dir = tmp_path / "artifacts"
    test_art_dir.mkdir()
    monkeypatch.setattr(tr, "ARTIFACTS_DIR", test_art_dir)
    monkeypatch.setattr(mr, "TRUSTED_ARTIFACTS_DIR", test_art_dir)
    monkeypatch.setattr(mr, "ACTIVE_MODEL_POINTER", test_art_dir / "active_model.json")

    x_tr, y_tr, grp_tr = generate_synthetic_feature_data(50, seed=10)
    x_val, y_val, grp_val = generate_synthetic_feature_data(20, seed=20)

    # Test training Logistic Regression, Random Forest, and LightGBM
    for model_name in ["logistic_regression", "random_forest", "lightgbm"]:
        model, card = train_and_evaluate_model(
            model_name=model_name,
            x_train=x_tr,
            y_train=y_tr,
            groups_train=grp_tr,
            x_val=x_val,
            y_val=y_val,
            seed=42,
            manifest_hash="test_manifest_hash_123",
        )

        assert model is not None
        assert card["model_name"] == model_name
        assert card["feature_schema_version"] == FEATURE_SCHEMA_VERSION
        assert card["dataset_manifest_hash"] == "test_manifest_hash_123"
        assert (test_art_dir / f"{model_name}.joblib").is_file()
        assert (test_art_dir / f"model_card_{model_name}.json").is_file()


def test_model_registry_security(tmp_path: Path, monkeypatch):
    import ml.training.model_registry as mr
    import ml.training.trainer as tr

    test_art_dir = tmp_path / "artifacts"
    test_art_dir.mkdir()
    monkeypatch.setattr(tr, "ARTIFACTS_DIR", test_art_dir)
    monkeypatch.setattr(mr, "TRUSTED_ARTIFACTS_DIR", test_art_dir)
    monkeypatch.setattr(mr, "ACTIVE_MODEL_POINTER", test_art_dir / "active_model.json")

    # 1. Reject Path Traversal
    with pytest.raises(UntrustedModelPathError):
        load_model_artifact("../../evil")

    # 2. Setup state when no model is active
    active_m, active_c = get_active_model()
    assert active_m is None
    assert active_c is None

    # Train and register active model
    x_tr, y_tr, grp_tr = generate_synthetic_feature_data(30)
    x_val, y_val, _ = generate_synthetic_feature_data(15)

    train_and_evaluate_model(
        "random_forest", x_tr, y_tr, grp_tr, x_val, y_val, seed=42
    )

    card = set_active_model("random_forest")
    assert card["model_name"] == "random_forest"

    # Now active model can be retrieved safely
    loaded_m, loaded_c = get_active_model()
    assert loaded_m is not None
    assert loaded_c["model_name"] == "random_forest"
