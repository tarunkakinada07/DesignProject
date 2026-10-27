"""Splitting protocols and leakage-safe partition management.

Protocols:
- Protocol A (Required): Grouped, stratified train/validation/test split by near_dup_cluster_id.
  All versions of an extension and near-duplicates are guaranteed to stay in the same partition.
- Protocol B (Tier 2): Chronological split (train on older, test on newer).
- Protocol C (Tier 2): Cross-source split (train on source A, test on source B).
"""

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
from sklearn.model_selection import StratifiedGroupKFold

from backend.app.database.connection import get_db_connection


@dataclass
class DatasetPartition:
    train_ids: list[str]
    val_ids: list[str]
    test_ids: list[str]
    cluster_mapping: dict[str, str]  # sample_id -> cluster_id
    protocol: str
    seed: int
    created_at: str
    manifest_hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "protocol": self.protocol,
            "seed": self.seed,
            "created_at": self.created_at,
            "manifest_hash": self.manifest_hash,
            "counts": {
                "train": len(self.train_ids),
                "val": len(self.val_ids),
                "test": len(self.test_ids),
                "total": len(self.train_ids) + len(self.val_ids) + len(self.test_ids),
            },
            "train_ids": self.train_ids,
            "val_ids": self.val_ids,
            "test_ids": self.test_ids,
        }

    def save(self, filepath: Path):
        filepath.parent.mkdir(parents=True, exist_ok=True)
        filepath.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")


def compute_sample_manifest_hash(samples: list[dict[str, Any]]) -> str:
    """Compute deterministic SHA-256 hash over sorted sample IDs and labels."""
    sorted_data = sorted(
        f"{s['internal_id']}:{s['label']}:{s.get('sha256', '')}" for s in samples
    )
    return hashlib.sha256("\n".join(sorted_data).encode("utf-8")).hexdigest()


def create_protocol_a_split(
    samples: list[dict[str, Any]] | None = None,
    seed: int = 42,
    n_splits: int = 5,
) -> DatasetPartition:
    """Protocol A: Grouped, stratified train/val/test split.

    Uses near_dup_cluster_id (fallback to extension_id) so that no cluster is split
    across partitions.
    Partition proportions with n_splits=5:
    - Train: ~60% (folds 2, 3, 4)
    - Validation: ~20% (fold 1)
    - Test: ~20% (fold 0)
    """
    if samples is None:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT * FROM samples
                WHERE parse_status = 'parsed' AND label IN ('malicious', 'benign')
                ORDER BY internal_id ASC
                """
            )
            samples = [dict(r) for r in cursor.fetchall()]

    if len(samples) < 4:
        raise ValueError(
            f"Insufficient samples for Protocol A split: {len(samples)} found. Need at least 4."
        )

    # Filter to binary classification samples
    valid_samples = [s for s in samples if s["label"] in ("malicious", "benign")]
    manifest_hash = compute_sample_manifest_hash(valid_samples)

    sample_ids = [s["internal_id"] for s in valid_samples]
    labels = np.array([1 if s["label"] == "malicious" else 0 for s in valid_samples])
    groups = np.array([s.get("near_dup_cluster_id") or s["extension_id"] for s in valid_samples])

    # Check that groups have at least n_splits distinct groups
    unique_groups = len(set(groups))
    effective_splits = min(n_splits, unique_groups)
    if effective_splits < 2:
        raise ValueError(
            f"Not enough distinct clusters ({unique_groups}) for grouped splitting."
        )

    sgkf = StratifiedGroupKFold(n_splits=effective_splits, shuffle=True, random_state=seed)

    folds = list(sgkf.split(sample_ids, labels, groups))

    if effective_splits >= 3:
        test_idx = folds[0][1]
        val_idx = folds[1][1]
        train_idx = np.concatenate([folds[i][1] for i in range(2, effective_splits)])
    else:
        # Fallback for minimal data (2 splits: train / test, val empty)
        test_idx = folds[0][1]
        val_idx = np.array([], dtype=int)
        train_idx = folds[1][1]

    train_ids = [sample_ids[i] for i in train_idx]
    val_ids = [sample_ids[i] for i in val_idx]
    test_ids = [sample_ids[i] for i in test_idx]

    # Verify zero cluster leakage between partitions
    train_clusters = {groups[i] for i in train_idx}
    val_clusters = {groups[i] for i in val_idx}
    test_clusters = {groups[i] for i in test_idx}

    assert train_clusters.isdisjoint(test_clusters), "Leakage detected: train and test share clusters!"
    assert train_clusters.isdisjoint(val_clusters), "Leakage detected: train and val share clusters!"
    assert val_clusters.isdisjoint(test_clusters), "Leakage detected: val and test share clusters!"

    cluster_mapping = {
        s["internal_id"]: s.get("near_dup_cluster_id") or s["extension_id"]
        for s in valid_samples
    }

    return DatasetPartition(
        train_ids=train_ids,
        val_ids=val_ids,
        test_ids=test_ids,
        cluster_mapping=cluster_mapping,
        protocol="Protocol_A_Grouped_Stratified",
        seed=seed,
        created_at=datetime.now(timezone.utc).isoformat(),
        manifest_hash=manifest_hash,
    )


def create_protocol_b_chronological_split(
    samples: list[dict[str, Any]],
    test_ratio: float = 0.25,
) -> DatasetPartition:
    """Protocol B (Tier 2): Chronological split (older in train, newer in test)."""
    valid_samples = [s for s in samples if s.get("collection_date") and s["label"] in ("malicious", "benign")]
    sorted_samples = sorted(valid_samples, key=lambda s: s["collection_date"])

    manifest_hash = compute_sample_manifest_hash(sorted_samples)
    groups = {s["internal_id"]: s.get("near_dup_cluster_id") or s["extension_id"] for s in sorted_samples}

    split_point = int(len(sorted_samples) * (1.0 - test_ratio))
    train_candidates = sorted_samples[:split_point]
    test_candidates = sorted_samples[split_point:]

    train_clusters = {groups[s["internal_id"]] for s in train_candidates}
    test_ids = []
    for s in test_candidates:
        c = groups[s["internal_id"]]
        if c not in train_clusters:
            test_ids.append(s["internal_id"])
        else:
            # If cluster began in train, keep whole cluster in train to prevent leakage
            train_candidates.append(s)

    train_ids = [s["internal_id"] for s in train_candidates]

    return DatasetPartition(
        train_ids=train_ids,
        val_ids=[],
        test_ids=test_ids,
        cluster_mapping=groups,
        protocol="Protocol_B_Chronological",
        seed=0,
        created_at=datetime.now(timezone.utc).isoformat(),
        manifest_hash=manifest_hash,
    )


def create_protocol_c_cross_source_split(
    samples: list[dict[str, Any]],
    held_out_source: str,
) -> DatasetPartition:
    """Protocol C (Tier 2): Train on one or more sources, test on held-out source."""
    valid_samples = [s for s in samples if s["label"] in ("malicious", "benign")]
    manifest_hash = compute_sample_manifest_hash(valid_samples)

    groups = {s["internal_id"]: s.get("near_dup_cluster_id") or s["extension_id"] for s in valid_samples}

    test_ids = [s["internal_id"] for s in valid_samples if s["source"] == held_out_source]
    train_ids = [s["internal_id"] for s in valid_samples if s["source"] != held_out_source]

    # Purge any clusters from test that happen to appear in train
    train_clusters = {groups[sid] for sid in train_ids}
    clean_test_ids = [sid for sid in test_ids if groups[sid] not in train_clusters]

    return DatasetPartition(
        train_ids=train_ids,
        val_ids=[],
        test_ids=clean_test_ids,
        cluster_mapping=groups,
        protocol=f"Protocol_C_CrossSource_{held_out_source}",
        seed=0,
        created_at=datetime.now(timezone.utc).isoformat(),
        manifest_hash=manifest_hash,
    )
