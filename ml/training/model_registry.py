"""Secure model registry and artifact loader.

Security constraint: Do not load artifacts from untrusted paths.
Enforces:
- Path confinement strictly within `ml/artifacts` directory (blocks path traversal).
- Feature schema version and feature count verification before loading.
"""

import json
from pathlib import Path
from typing import Any

import joblib
from sklearn.base import BaseEstimator

from backend.app.core.exceptions import SentinelError
from ml.features.schema import ALL_FEATURE_KEYS, FEATURE_SCHEMA_VERSION

TRUSTED_ARTIFACTS_DIR = (Path(__file__).resolve().parent.parent / "artifacts").resolve()
ACTIVE_MODEL_POINTER = TRUSTED_ARTIFACTS_DIR / "active_model.json"


class UntrustedModelPathError(SentinelError):
    """Raised when an artifact load request targets an unconfined or untrusted filesystem path."""

    pass


class ModelSchemaMismatchError(SentinelError):
    """Raised when a saved model card feature schema does not align with active schema."""

    pass


def load_model_artifact(model_name: str) -> tuple[BaseEstimator, dict[str, Any]]:
    """Safely load a registered model artifact and its companion model card.

    Security checks:
    - Path must strictly resolve inside TRUSTED_ARTIFACTS_DIR.
    - Model card must exist and have matching FEATURE_SCHEMA_VERSION.
    """
    if "/" in model_name or "\\" in model_name or ".." in model_name:
        raise UntrustedModelPathError(
            f"Attempted to load model from untrusted path: {model_name}",
            safe_message="Model path rejected: untrusted location.",
        )

    clean_name = Path(model_name).name
    artifact_path = (TRUSTED_ARTIFACTS_DIR / f"{clean_name}.joblib").resolve()
    card_path = (TRUSTED_ARTIFACTS_DIR / f"model_card_{clean_name}.json").resolve()

    # Path traversal confinement assertion
    try:
        artifact_path.relative_to(TRUSTED_ARTIFACTS_DIR)
        card_path.relative_to(TRUSTED_ARTIFACTS_DIR)
    except ValueError as e:
        raise UntrustedModelPathError(
            f"Attempted to load model from untrusted path: {model_name}",
            safe_message="Model path rejected: untrusted location.",
        ) from e

    if not artifact_path.is_file():
        raise FileNotFoundError(f"Model artifact not found: {clean_name}.joblib")
    if not card_path.is_file():
        raise FileNotFoundError(f"Model card not found for: {clean_name}")

    # Inspect model card before deserializing binary
    card_data = json.loads(card_path.read_text(encoding="utf-8"))
    saved_schema = card_data.get("feature_schema_version")
    if saved_schema != FEATURE_SCHEMA_VERSION:
        raise ModelSchemaMismatchError(
            f"Schema version mismatch: saved={saved_schema}, active={FEATURE_SCHEMA_VERSION}",
            safe_message="Model artifact feature schema does not match current pipeline.",
        )

    saved_count = card_data.get("feature_count")
    if saved_count != len(ALL_FEATURE_KEYS):
        raise ModelSchemaMismatchError(
            f"Feature count mismatch: saved={saved_count}, active={len(ALL_FEATURE_KEYS)}",
            safe_message="Model feature count mismatch.",
        )

    model = joblib.load(artifact_path)
    return model, card_data


def set_active_model(model_name: str) -> dict[str, Any]:
    """Designate a registered model as the active scanner detector."""
    # Verify model can be loaded cleanly
    _, card = load_model_artifact(model_name)
    ACTIVE_MODEL_POINTER.write_text(
        json.dumps({"active_model": model_name, "updated_at": card.get("timestamp")}),
        encoding="utf-8",
    )
    return card


def get_active_model() -> tuple[BaseEstimator | None, dict[str, Any] | None]:
    """Retrieve currently active model. Returns (None, None) if in setup state."""
    if not ACTIVE_MODEL_POINTER.is_file():
        return None, None
    try:
        pointer_data = json.loads(ACTIVE_MODEL_POINTER.read_text(encoding="utf-8"))
        name = pointer_data.get("active_model")
        if not name:
            return None, None
        return load_model_artifact(name)
    except Exception:
        return None, None
