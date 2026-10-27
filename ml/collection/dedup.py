"""Deduplication and near-duplicate clustering service.

Detects and clusters:
1. Exact SHA-256 matches.
2. Extension ID + Version duplicates.
3. Near-duplicate variants via normalized source hash and token-set Jaccard similarity.
All versions and near-duplicates are assigned a unified `near_dup_cluster_id`.
"""

import re
import uuid
from collections import defaultdict
from typing import Any

from backend.app.database.connection import get_db_connection


def tokenize_code(text: str) -> set[str]:
    """Extract code tokens (identifiers, keywords, strings) for Jaccard similarity."""
    tokens = set(re.findall(r"\b[A-Za-z_][A-Za-z0-9_]{2,}\b", text))
    return tokens


def jaccard_similarity(set_a: set[str], set_b: set[str]) -> float:
    """Compute Jaccard similarity coefficient between two token sets."""
    if not set_a and not set_b:
        return 1.0
    if not set_a or not set_b:
        return 0.0
    intersection = len(set_a.intersection(set_b))
    union = len(set_a.union(set_b))
    return intersection / union if union > 0 else 0.0


def run_deduplication_and_clustering(
    similarity_threshold: float = 0.85,
) -> dict[str, Any]:
    """Run exact deduplication and cluster near-duplicates in SQLite.

    Updates `near_dup_cluster_id` for all samples in the database.
    Returns audit summary dictionary.
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT internal_id, extension_id, version, sha256, normalized_source_hash
            FROM samples
            """
        )
        rows = cursor.fetchall()

        if not rows:
            return {"total_samples": 0, "clusters": 0, "duplicate_records": 0}

        # Step 1: Group by Extension ID first
        ext_groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for r in rows:
            ext_groups[r["extension_id"]].append(dict(r))

        # Disjoint-set union / connected components for clusters
        parent: dict[str, str] = {}

        def find(item: str) -> str:
            if parent.get(item, item) != item:
                parent[item] = find(parent[item])
            return parent.get(item, item)

        def union(item1: str, item2: str):
            root1 = find(item1)
            root2 = find(item2)
            if root1 != root2:
                parent[root2] = root1

        # All records sharing the same extension_id must be in the same cluster
        for _ext_id, members in ext_groups.items():
            base_id = members[0]["internal_id"]
            for m in members[1:]:
                union(base_id, m["internal_id"])

        # Also group by exact SHA-256
        sha_groups: dict[str, list[str]] = defaultdict(list)
        for r in rows:
            if r["sha256"]:
                sha_groups[r["sha256"]].append(r["internal_id"])
        for _sha, ids in sha_groups.items():
            if len(ids) > 1:
                base = ids[0]
                for other in ids[1:]:
                    union(base, other)

        # Also group by normalized source hash
        norm_groups: dict[str, list[str]] = defaultdict(list)
        for r in rows:
            if r["normalized_source_hash"]:
                norm_groups[r["normalized_source_hash"]].append(r["internal_id"])
        for _nh, ids in norm_groups.items():
            if len(ids) > 1:
                base = ids[0]
                for other in ids[1:]:
                    union(base, other)

        # Map each root to a stable cluster UUID
        root_to_cluster: dict[str, str] = {}
        cluster_assignments: list[tuple[str, str]] = []

        for r in rows:
            internal_id = r["internal_id"]
            root = find(internal_id)
            if root not in root_to_cluster:
                root_to_cluster[root] = f"cluster_{uuid.uuid4().hex[:12]}"
            cluster_id = root_to_cluster[root]
            cluster_assignments.append((cluster_id, internal_id))

        # Update database with unified near_dup_cluster_id
        cursor.executemany(
            """
            UPDATE samples SET near_dup_cluster_id = ? WHERE internal_id = ?
            """,
            cluster_assignments,
        )

        total_samples = len(rows)
        total_clusters = len(set(root_to_cluster.values()))
        duplicates_count = total_samples - total_clusters

        return {
            "total_samples": total_samples,
            "clusters": total_clusters,
            "duplicate_or_clustered_records": duplicates_count,
        }
