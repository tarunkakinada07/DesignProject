"""Pipeline factory enforcing strict fit-on-train-only data leakage prevention."""

import numpy as np
from sklearn.base import BaseEstimator
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler


def build_training_pipeline(
    classifier: BaseEstimator,
    with_scaling: bool = True,
    with_imputer: bool = True,
) -> Pipeline:
    """Build an sklearn Pipeline encapsulating all data transformers and the estimator.

    Guarantees that all transformers (imputer, scaler) are fitted exclusively
    inside the training fold via `pipeline.fit(X_train, y_train)` and never see test data.
    """
    steps = []
    if with_imputer:
        steps.append(("imputer", SimpleImputer(strategy="median", fill_value=0.0)))
    if with_scaling:
        steps.append(("scaler", StandardScaler()))
    steps.append(("classifier", classifier))

    return Pipeline(steps)


def assert_no_test_leakage(
    pipeline: Pipeline,
    x_train: np.ndarray,
    x_test: np.ndarray,
    y_train: np.ndarray,
) -> bool:
    """Verify that test set samples exert zero influence over fitted transformer parameters.

    Tests that:
    1. Transformer parameters (e.g., scaler.mean_, scaler.scale_) match exact training statistics.
    2. Modifying or injecting extreme outliers into x_test does NOT alter transformer parameters.
    """
    # Fit pipeline strictly on training data
    pipeline.fit(x_train, y_train)

    scaler = pipeline.named_steps.get("scaler")
    if scaler is not None:
        # Check that mean_ matches x_train mean, not x_test or combined
        expected_mean = np.mean(x_train, axis=0)
        np.testing.assert_allclose(
            scaler.mean_,
            expected_mean,
            rtol=1e-5,
            err_msg="Scaler mean was not fitted exclusively on training data!",
        )

        # Mutate test data with extreme outliers
        x_test_corrupted = x_test.copy() + 1e7
        # Running transform on corrupted test data must NOT change scaler parameters
        _ = pipeline.predict_proba(x_test_corrupted) if hasattr(pipeline, "predict_proba") else pipeline.predict(x_test_corrupted)

        np.testing.assert_allclose(
            scaler.mean_,
            expected_mean,
            rtol=1e-5,
            err_msg="Scaler parameters mutated during test set evaluation (leakage detected)!",
        )

    imputer = pipeline.named_steps.get("imputer")
    if imputer is not None:
        # Check that imputer statistics match training data
        expected_median = np.nanmedian(x_train, axis=0)
        np.testing.assert_allclose(
            imputer.statistics_,
            expected_median,
            rtol=1e-5,
            err_msg="Imputer statistics were not fitted exclusively on training data!",
        )

    return True
