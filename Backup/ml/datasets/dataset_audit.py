"""Pre-split dataset audit and health assessment.

Audits:
- Class counts and label proportions
- Duplicate records and near-duplicate cluster distribution
- Label sources and per-source label balance
- Collection date ranges
- Parser failure rates and missing package counts
"""

from collections import Counter
from typing import Any

from backend.app.database.connection import get_db_connection


def perform_pre_split_audit() -> dict[str, Any]:
    """Execute pre-split audit across all samples in the database.

    Returns detailed audit report dictionary.
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM samples")
        rows = [dict(r) for r in cursor.fetchall()]

    if not rows:
        return {
            "status": "empty",
            "total_records": 0,
            "can_split": False,
            "reason": "Database contains zero sample records.",
        }

    total_records = len(rows)
    label_counts = Counter(r["label"] for r in rows)
    source_counts = Counter(r["source"] for r in rows)
    status_counts = Counter(r["parse_status"] for r in rows)

    # Per-source label balance
    per_source_labels: dict[str, dict[str, int]] = {}
    for r in rows:
        src = r["source"]
        lbl = r["label"]
        if src not in per_source_labels:
            per_source_labels[src] = {}
        per_source_labels[src][lbl] = per_source_labels[src].get(lbl, 0) + 1

    # Date range
    dates = [r["collection_date"] for r in rows if r.get("collection_date")]
    min_date = min(dates) if dates else "N/A"
    max_date = max(dates) if dates else "N/A"

    # Parsed vs ID-only vs Failed
    parsed_count = status_counts.get("parsed", 0)
    failed_count = status_counts.get("failed", 0)
    id_only_count = status_counts.get("id_only", 0)

    total_attempted_parse = parsed_count + failed_count
    parse_failure_rate = (
        float(failed_count) / float(total_attempted_parse)
        if total_attempted_parse > 0
        else 0.0
    )

    # Unique clusters among parsed samples
    parsed_samples = [r for r in rows if r["parse_status"] == "parsed"]
    cluster_ids = {
        r.get("near_dup_cluster_id") or r["extension_id"] for r in parsed_samples
    }

    # Minimum check for Protocol A:
    # Requires at least 2 distinct clusters in both malicious and benign classes
    mal_clusters = {
        r.get("near_dup_cluster_id") or r["extension_id"]
        for r in parsed_samples
        if r["label"] == "malicious"
    }
    ben_clusters = {
        r.get("near_dup_cluster_id") or r["extension_id"]
        for r in parsed_samples
        if r["label"] == "benign"
    }

    can_split = len(mal_clusters) >= 2 and len(ben_clusters) >= 2
    split_notice = (
        "Dataset has sufficient cluster diversity for grouped stratified splitting."
        if can_split
        else "Insufficient parsed clusters for 3-way grouped split (need >=2 clusters per class). Ingest more packages."
    )

    return {
        "status": "ready" if can_split else "insufficient_data",
        "total_records": total_records,
        "parsed_packages_for_ml": len(parsed_samples),
        "id_only_threat_intel_count": id_only_count,
        "parse_failure_rate": round(parse_failure_rate, 4),
        "label_distribution": dict(label_counts),
        "source_distribution": dict(source_counts),
        "per_source_label_balance": per_source_labels,
        "date_range": {"min": min_date, "max": max_date},
        "total_unique_clusters": len(cluster_ids),
        "malicious_clusters": len(mal_clusters),
        "benign_clusters": len(ben_clusters),
        "can_split": can_split,
        "split_readiness_notice": split_notice,
    }
