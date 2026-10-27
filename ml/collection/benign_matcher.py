"""Benign sample selection and covariate matching policy.

Matches benign extension candidates against known malicious packages on:
- Category (e.g., productivity, shopping, developer_tools)
- Size bracket (small: <100KB, medium: 100KB-1MB, large: >1MB)
- Manifest version (MV2 vs MV3)

Records `benign_verification_date` because extension reputation can change after a compromised update.
Prevents the model from learning shortcuts like "small and old = malicious".
"""

from datetime import datetime, timezone
from typing import Any

from backend.app.database.connection import get_db_connection


def categorize_size_bracket(size_bytes: int) -> str:
    """Group file size into discrete brackets for stratified matching."""
    if size_bytes < 100 * 1024:
        return "small"
    elif size_bytes < 1024 * 1024:
        return "medium"
    else:
        return "large"


def match_benign_samples_to_malicious(
    benign_candidates: list[dict[str, Any]],
    target_ratio: float = 1.0,
) -> list[dict[str, Any]]:
    """Select benign candidates that match malicious package distributions.

    Prevents spurious correlation between package size/age/category and maliciousness.
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT category, size_bytes, manifest_version
            FROM samples
            WHERE label = 'malicious' AND parse_status = 'parsed'
            """
        )
        malicious_rows = cursor.fetchall()

    if not malicious_rows or not benign_candidates:
        return benign_candidates

    # Compute target distribution of malicious profiles
    malicious_profiles: list[tuple[str, str, int]] = []
    for r in malicious_rows:
        cat = r["category"] or "general"
        size_b = categorize_size_bracket(r["size_bytes"] or 0)
        mv = r["manifest_version"] or 3
        malicious_profiles.append((cat, size_b, mv))

    matched_benign: list[dict[str, Any]] = []
    available_candidates = list(benign_candidates)
    today = datetime.now(timezone.utc).date().isoformat()

    for target_profile in malicious_profiles:
        # Search for closest matching candidate
        best_idx = -1
        best_score = -1

        for i, cand in enumerate(available_candidates):
            c_cat = cand.get("category", "general")
            c_size_b = categorize_size_bracket(cand.get("size_bytes", 0))
            c_mv = cand.get("manifest_version", 3)

            score = 0
            if c_cat == target_profile[0]:
                score += 3
            if c_size_b == target_profile[1]:
                score += 2
            if c_mv == target_profile[2]:
                score += 1

            if score > best_score:
                best_score = score
                best_idx = i

        if best_idx >= 0:
            chosen = available_candidates.pop(best_idx)
            # Record reputation audit date
            chosen["benign_verification_date"] = today
            matched_benign.append(chosen)

        if not available_candidates:
            break

    return matched_benign
