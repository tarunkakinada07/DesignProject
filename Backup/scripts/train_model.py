"""CLI script to train detector models under leakage-safe grouped evaluation."""

import argparse
import sys
from pathlib import Path

# Bootstrap repository root on python path
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import numpy as np

from backend.app.database.connection import get_db_connection, init_db
from ml.datasets.splits import create_protocol_a_split
from ml.features.pipeline import extract_features_from_directory
from ml.features.schema import ALL_FEATURE_KEYS
from ml.training.model_registry import set_active_model
from ml.training.models import get_model_catalog
from ml.training.trainer import train_and_evaluate_model


def load_dataset_features_and_splits(seed: int = 42):
    """Load parsed packages from SQLite or generate demo training partition."""
    init_db()

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT * FROM samples
            WHERE parse_status = 'parsed' AND label IN ('malicious', 'benign')
            """
        )
        samples = [dict(r) for r in cursor.fetchall()]

    if len(samples) >= 6:
        # Extract features from disk
        x_list = []
        y_list = []
        groups_list = []
        valid_samples = []

        for s in samples:
            pkg_p = s.get("package_path")
            if pkg_p and Path(pkg_p).is_dir():
                _, vec, _, _ = extract_features_from_directory(Path(pkg_p))
                x_list.append(vec)
                y_list.append(1 if s["label"] == "malicious" else 0)
                groups_list.append(s.get("near_dup_cluster_id") or s["extension_id"])
                valid_samples.append(s)

        if len(x_list) >= 6:
            partition = create_protocol_a_split(valid_samples, seed=seed)
            id_to_idx = {s["internal_id"]: i for i, s in enumerate(valid_samples)}

            tr_idx = [id_to_idx[sid] for sid in partition.train_ids]
            val_idx = [id_to_idx[sid] for sid in partition.val_ids]

            X = np.array(x_list)
            y = np.array(y_list)
            groups = np.array(groups_list)

            return (
                X[tr_idx],
                y[tr_idx],
                groups[tr_idx],
                X[val_idx],
                y[val_idx],
                partition.manifest_hash,
            )

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
        print(f"Loaded {len(X)} samples from feature cache ({len(train_idx)} train, {len(val_idx)} val, {len(test_idx)} test across {len(np.unique(groups))} clusters).")
        return X[train_idx], y[train_idx], groups[train_idx], X[val_idx], y[val_idx], "manifest_hash_1300"

    # If database does not yet contain enough parsed raw packages on disk,
    # generate a clearly documented demonstration partition for training verification
    print(
        "Notice: Parsed package count in SQLite is below threshold (need >=6). "
        "Using seeded demonstration features to verify model training progression."
    )
    rng = np.random.RandomState(seed)
    n_features = len(ALL_FEATURE_KEYS)

    n_tr = 50
    x_tr = rng.uniform(0.0, 5.0, size=(n_tr, n_features))
    y_tr = rng.choice([0, 1], size=n_tr, p=[0.55, 0.45])
    grp_tr = np.array([f"cluster_{i % 10}" for i in range(n_tr)])

    n_val = 20
    x_val = rng.uniform(0.0, 5.0, size=(n_val, n_features))
    y_val = rng.choice([0, 1], size=n_val, p=[0.55, 0.45])

    return x_tr, y_tr, grp_tr, x_val, y_val, "demo_manifest_hash_42"


def main():
    parser = argparse.ArgumentParser(description="Train extension risk detector models.")
    parser.add_argument(
        "--model",
        choices=list(get_model_catalog().keys()) + ["all"],
        default="random_forest",
        help="Model architecture to train",
    )
    parser.add_argument("--seed", type=int, default=42, help="Fixed random seed")
    parser.add_argument(
        "--register-active",
        action="store_true",
        help="Register the trained model as active for scans",
    )

    args = parser.parse_args()

    x_tr, y_tr, grp_tr, x_val, y_val, m_hash = load_dataset_features_and_splits(seed=args.seed)

    models_to_train = (
        list(get_model_catalog().keys()) if args.model == "all" else [args.model]
    )

    best_model_name = None
    best_f1 = -1.0

    print(f"\nTraining pipeline initialized. Seed: {args.seed}. Training samples: {len(x_tr)}, Val: {len(x_val)}")

    for m_name in models_to_train:
        print(f"\n--- Training: {m_name} ---")
        _, card = train_and_evaluate_model(
            model_name=m_name,
            x_train=x_tr,
            y_train=y_tr,
            groups_train=grp_tr,
            x_val=x_val,
            y_val=y_val,
            seed=args.seed,
            manifest_hash=m_hash,
        )

        val_f1 = card["val_metrics"].get("f1", 0.0)
        cv_f1 = card.get("grouped_cv_f1_mean", 0.0)
        thresh = card.get("alert_threshold", 0.5)

        print(f"Grouped CV F1 Mean: {cv_f1:.4f}")
        print(f"Validation F1: {val_f1:.4f} (selected threshold: {thresh})")
        print(f"Validation Metrics: {card['val_metrics']}")

        if val_f1 > best_f1:
            best_f1 = val_f1
            best_model_name = m_name

    if args.register_active or args.model != "all":
        target_to_register = args.model if args.model != "all" else best_model_name
        if target_to_register:
            set_active_model(target_to_register)
            print(f"\n[OK] Model '{target_to_register}' is now registered as the active detector.")


if __name__ == "__main__":
    main()
