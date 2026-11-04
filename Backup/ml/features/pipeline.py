"""Unified feature extraction pipeline.

Combines Group A (Manifest), Group B (JavaScript static), Group C (Obfuscation),
and Group D (Behavior combinations & mismatches) into a versioned, deterministic feature vector.
"""

from pathlib import Path
from typing import Any

from backend.app.schemas.manifest import NormalizedManifest
from backend.app.services.manifest_parser import parse_manifest_file
from ml.features.group_a_manifest import extract_group_a_manifest_features
from ml.features.group_b_js_static import extract_group_b_js_features
from ml.features.group_c_obfuscation import extract_group_c_obfuscation_features
from ml.features.group_d_behavior import extract_group_d_behavior_features
from ml.features.schema import (
    ALL_FEATURE_KEYS,
    FEATURE_SCHEMA_VERSION,
    GROUP_A_FEATURES,
    GROUP_B_FEATURES,
    GROUP_C_FEATURES,
    GROUP_D_FEATURES,
)


def extract_features_from_directory(
    extension_dir: Path,
    manifest: NormalizedManifest | None = None,
) -> tuple[dict[str, float], list[float], list[str], dict[str, Any]]:
    """Extract complete, deterministic feature set from an unpacked extension directory.

    Missing-Value Policy:
    All features are numeric (float). Any uncomputed or absent feature defaults to 0.0.

    Returns:
    - feature_dict: Mapping of feature_name -> float (ordered by ALL_FEATURE_KEYS)
    - feature_vector: Dense list of floats aligned with ALL_FEATURE_KEYS
    - evidence: List of human-readable security observations and risk indicators
    - metadata: Extraction metadata (schema version, file counts, sizes)
    """
    if manifest is None:
        manifest = parse_manifest_file(extension_dir)

    all_evidence: list[str] = []

    # Group A: Manifest features
    feat_a, ev_a = extract_group_a_manifest_features(manifest)
    all_evidence.extend(ev_a)

    # Group B: JS static features
    feat_b, ev_b, meta_b = extract_group_b_js_features(extension_dir)
    all_evidence.extend(ev_b)

    # Group C: Obfuscation indicators
    feat_c, ev_c = extract_group_c_obfuscation_features(extension_dir)
    all_evidence.extend(ev_c)

    # Group D: Behavior combination & mismatch features
    feat_d, ev_d = extract_group_d_behavior_features(manifest, extension_dir, feat_a, feat_b)
    all_evidence.extend(ev_d)

    # Merge all features
    raw_merged: dict[str, float] = {}
    raw_merged.update(feat_a)
    raw_merged.update(feat_b)
    raw_merged.update(feat_c)
    raw_merged.update(feat_d)

    # Guarantee exact deterministic alignment with ALL_FEATURE_KEYS
    final_dict: dict[str, float] = {}
    final_vector: list[float] = []

    for key in ALL_FEATURE_KEYS:
        val = raw_merged.get(key, 0.0)
        # Enforce missing-value policy (no NaNs or non-numerics)
        if val is None or not isinstance(val, (int, float)):
            val = 0.0
        final_dict[key] = float(val)
        final_vector.append(float(val))

    metadata = {
        "schema_version": FEATURE_SCHEMA_VERSION,
        "feature_count": len(ALL_FEATURE_KEYS),
        "group_counts": {
            "group_a": len(GROUP_A_FEATURES),
            "group_b": len(GROUP_B_FEATURES),
            "group_c": len(GROUP_C_FEATURES),
            "group_d": len(GROUP_D_FEATURES),
        },
        "js_files": meta_b.get("js_files", []),
        "external_urls_sample": meta_b.get("external_urls_sample", []),
    }

    return final_dict, final_vector, all_evidence, metadata
