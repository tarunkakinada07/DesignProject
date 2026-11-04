"""Dataset audit, label conflict detection, and quality reporting."""

from collections import Counter
from pathlib import Path
from typing import Any

from backend.app.database.connection import get_db_connection


def detect_label_conflicts() -> list[dict[str, Any]]:
    """Scan database for conflicting labels on the same extension_id or sha256.

    Returns a list of conflict report dictionaries.
    """
    conflicts: list[dict[str, Any]] = []

    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Check by extension_id
        cursor.execute(
            """
            SELECT extension_id, COUNT(DISTINCT label) as label_count, GROUP_CONCAT(DISTINCT label) as labels,
                   GROUP_CONCAT(DISTINCT source) as sources
            FROM samples
            GROUP BY extension_id
            HAVING COUNT(DISTINCT label) > 1
            """
        )
        for row in cursor.fetchall():
            conflicts.append({
                "conflict_type": "extension_id_label_mismatch",
                "identifier": row["extension_id"],
                "distinct_labels": row["labels"].split(","),
                "sources": row["sources"].split(","),
            })

        # Check by sha256
        cursor.execute(
            """
            SELECT sha256, COUNT(DISTINCT label) as label_count, GROUP_CONCAT(DISTINCT label) as labels,
                   GROUP_CONCAT(DISTINCT source) as sources
            FROM samples
            WHERE sha256 IS NOT NULL AND sha256 != ''
            GROUP BY sha256
            HAVING COUNT(DISTINCT label) > 1
            """
        )
        for row in cursor.fetchall():
            conflicts.append({
                "conflict_type": "sha256_label_mismatch",
                "identifier": row["sha256"],
                "distinct_labels": row["labels"].split(","),
                "sources": row["sources"].split(","),
            })

    return conflicts


def generate_missing_file_report() -> dict[str, Any]:
    """Audit local raw packages vs threat-intel metadata records."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT internal_id, extension_id, label, parse_status, package_path, source
            FROM samples
            """
        )
        rows = cursor.fetchall()

    id_only_count = 0
    package_present_count = 0
    missing_file_count = 0
    missing_samples: list[dict[str, str]] = []

    for r in rows:
        status = r["parse_status"]
        pkg_path = r["package_path"]

        if status == "id_only":
            id_only_count += 1
        elif pkg_path and Path(pkg_path).is_file():
            package_present_count += 1
        else:
            missing_file_count += 1
            missing_samples.append({
                "internal_id": r["internal_id"],
                "extension_id": r["extension_id"],
                "source": r["source"],
                "label": r["label"],
            })

    return {
        "total_records": len(rows),
        "threat_intel_id_only": id_only_count,
        "packages_present_on_disk": package_present_count,
        "missing_or_unparsed_files": missing_file_count,
        "sample_missing_details": missing_samples[:20],
    }


def dataset_quality_summary() -> dict[str, Any]:
    """Generate comprehensive dataset quality and provenance summary."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM samples")
        rows = cursor.fetchall()

    if not rows:
        return {
            "status": "empty",
            "total_records": 0,
            "message": "Dataset database is empty. Ingest samples to build dataset.",
        }

    labels = Counter(r["label"] for r in rows)
    sources = Counter(r["source"] for r in rows)
    parse_statuses = Counter(r["parse_status"] for r in rows)
    clusters = len(set(r["near_dup_cluster_id"] for r in rows if r["near_dup_cluster_id"]))

    dates = [r["collection_date"] for r in rows if r["collection_date"]]
    date_min = min(dates) if dates else "N/A"
    date_max = max(dates) if dates else "N/A"

    conflicts = detect_label_conflicts()
    missing_files = generate_missing_file_report()

    # Per project prompt: Honest assessment of real packages
    packages_available = missing_files["packages_present_on_disk"]
    real_malicious_packages = sum(
        1 for r in rows if r["label"] == "malicious" and r["package_path"] and Path(r["package_path"]).is_file()
    )

    assessment = (
        f"Verified {packages_available} raw packages on disk ({real_malicious_packages} malicious). "
        f"{missing_files['threat_intel_id_only']} records are ID-only threat-intel IOCs."
    )
    if real_malicious_packages < 30:
        uncertainty_warning = (
            "NOTICE: Real malicious packages are limited. Model evaluation uncertainty will be high. "
            "Never invent counts; transparently report sample size."
        )
    else:
        uncertainty_warning = "Sufficient package count for cross-validation."

    return {
        "total_samples": len(rows),
        "label_distribution": dict(labels),
        "source_distribution": dict(sources),
        "parse_status_distribution": dict(parse_statuses),
        "unique_clusters": clusters,
        "date_range": {"earliest": date_min, "latest": date_max},
        "label_conflicts_count": len(conflicts),
        "label_conflicts": conflicts,
        "packages_on_disk": packages_available,
        "real_malicious_packages_on_disk": real_malicious_packages,
        "threat_intel_id_only_count": missing_files["threat_intel_id_only"],
        "quality_assessment": assessment,
        "uncertainty_notice": uncertainty_warning,
    }
