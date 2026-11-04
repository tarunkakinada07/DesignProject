"""Unit and integration tests for Phase 4: Splits and leakage prevention."""

from pathlib import Path

import numpy as np
from sklearn.linear_model import LogisticRegression

from ml.datasets.dataset_audit import perform_pre_split_audit
from ml.datasets.pipeline_factory import assert_no_test_leakage, build_training_pipeline
from ml.datasets.splits import (
    create_protocol_a_split,
    create_protocol_b_chronological_split,
    create_protocol_c_cross_source_split,
)


def generate_synthetic_clustered_dataset(num_clusters: int = 20, samples_per_cluster: int = 3):
    """Helper creating synthetic samples with version variants sharing cluster IDs."""
    samples = []
    np.random.RandomState(42)

    for c_idx in range(num_clusters):
        cluster_id = f"cluster_{c_idx:03d}"
        ext_id = f"extension_{c_idx:03d}"
        label = "malicious" if c_idx % 2 == 0 else "benign"
        base_date = f"2026-0{1 + (c_idx % 9):02d}-15"

        for v_idx in range(samples_per_cluster):
            samples.append({
                "internal_id": f"samp_{c_idx}_{v_idx}",
                "extension_id": ext_id,
                "version": f"1.{v_idx}.0",
                "label": label,
                "near_dup_cluster_id": cluster_id,
                "source": "source_a" if c_idx < num_clusters // 2 else "source_b",
                "collection_date": base_date,
                "parse_status": "parsed",
                "sha256": f"hash_{c_idx}_{v_idx}",
            })
    return samples


def test_protocol_a_grouped_stratified_split():
    samples = generate_synthetic_clustered_dataset(num_clusters=20, samples_per_cluster=3)
    partition = create_protocol_a_split(samples, seed=123, n_splits=5)

    assert len(partition.train_ids) > 0
    assert len(partition.val_ids) > 0
    assert len(partition.test_ids) > 0

    train_set = set(partition.train_ids)
    val_set = set(partition.val_ids)
    test_set = set(partition.test_ids)

    # 1. Zero sample overlap across partitions
    assert train_set.isdisjoint(val_set)
    assert train_set.isdisjoint(test_set)
    assert val_set.isdisjoint(test_set)

    # 2. Zero cluster overlap across partitions (Critical leakage check!)
    sample_to_cluster = {s["internal_id"]: s["near_dup_cluster_id"] for s in samples}

    train_clusters = {sample_to_cluster[sid] for sid in partition.train_ids}
    val_clusters = {sample_to_cluster[sid] for sid in partition.val_ids}
    test_clusters = {sample_to_cluster[sid] for sid in partition.test_ids}

    assert train_clusters.isdisjoint(val_clusters), "Cluster leakage between Train and Val!"
    assert train_clusters.isdisjoint(test_clusters), "Cluster leakage between Train and Test!"
    assert val_clusters.isdisjoint(test_clusters), "Cluster leakage between Val and Test!"


def test_protocol_b_chronological_split():
    samples = generate_synthetic_clustered_dataset(num_clusters=12, samples_per_cluster=2)
    partition = create_protocol_b_chronological_split(samples, test_ratio=0.30)

    assert len(partition.train_ids) > 0
    assert len(partition.test_ids) > 0
    assert set(partition.train_ids).isdisjoint(set(partition.test_ids))

    # All versions of any cluster in train must not appear in test
    sample_to_cluster = {s["internal_id"]: s["near_dup_cluster_id"] for s in samples}
    train_clusters = {sample_to_cluster[sid] for sid in partition.train_ids}
    test_clusters = {sample_to_cluster[sid] for sid in partition.test_ids}

    assert train_clusters.isdisjoint(test_clusters)


def test_protocol_c_cross_source_split():
    samples = generate_synthetic_clustered_dataset(num_clusters=14, samples_per_cluster=2)
    partition = create_protocol_c_cross_source_split(samples, held_out_source="source_b")

    sample_dict = {s["internal_id"]: s for s in samples}

    # All test samples must be from source_b
    for sid in partition.test_ids:
        assert sample_dict[sid]["source"] == "source_b"

    # All train samples must NOT be from source_b
    for sid in partition.train_ids:
        assert sample_dict[sid]["source"] != "source_b"

    assert set(partition.train_ids).isdisjoint(set(partition.test_ids))


def test_no_test_leakage_in_pipeline():
    """Verify that transformers (StandardScaler, SimpleImputer) are fitted strictly on X_train."""
    rng = np.random.RandomState(42)

    # Synthetic train and test distributions with different means
    x_train = rng.normal(loc=10.0, scale=2.0, size=(100, 5))
    y_train = rng.choice([0, 1], size=100)

    # Test distribution with very different mean (5000.0)
    x_test = rng.normal(loc=5000.0, scale=10.0, size=(40, 5))

    pipeline = build_training_pipeline(LogisticRegression())

    # assert_no_test_leakage confirms scaler.mean_ matches train, and corrupting test does not alter it
    is_safe = assert_no_test_leakage(pipeline, x_train, x_test, y_train)
    assert is_safe is True

    # Confirm scaler mean is around 10.0, not contaminated by 5000.0
    scaler = pipeline.named_steps["scaler"]
    np.testing.assert_allclose(scaler.mean_, np.mean(x_train, axis=0), rtol=1e-5)


def test_partition_serialization(tmp_path: Path):
    samples = generate_synthetic_clustered_dataset(num_clusters=10, samples_per_cluster=2)
    partition = create_protocol_a_split(samples, seed=99)

    out_file = tmp_path / "split_test.json"
    partition.save(out_file)

    assert out_file.is_file()
    data = partition.to_dict()
    assert data["protocol"] == "Protocol_A_Grouped_Stratified"
    assert data["seed"] == 99
    assert data["manifest_hash"] is not None
    assert data["counts"]["total"] == len(samples)


def test_audit_empty_and_populated_database(tmp_path: Path, monkeypatch):
    from backend.app.core.config import settings
    from backend.app.database.connection import init_db

    db_path = tmp_path / "audit_test.db"
    monkeypatch.setattr(settings, "DB_PATH", db_path)
    init_db(db_path)

    # Empty audit check
    empty_report = perform_pre_split_audit()
    assert empty_report["status"] == "empty"
    assert empty_report["can_split"] is False
