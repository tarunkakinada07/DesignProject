"""Inference service connecting safe extraction, threat-intel lookups, feature extraction, model scoring, and local SHAP explanations."""

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np

from backend.app.database.connection import get_db_connection
from backend.app.schemas.manifest import NormalizedManifest
from backend.app.schemas.scan import (
    ExtractionSummary,
    RiskFactor,
    ScanResultResponse,
)
from ml.features.pipeline import extract_features_from_directory
from ml.features.schema import ALL_FEATURE_KEYS
from ml.training.baselines import HeuristicRuleBaseline
from ml.training.model_registry import get_active_model

FEATURE_DESCRIPTIONS: dict[str, str] = {
    "perm_count_total": "Total number of browser permissions requested.",
    "perm_count_high_risk": "Count of high-risk permissions (e.g., cookies, webRequest, proxy, debugger, management).",
    "perm_count_medium_risk": "Count of medium-risk permissions (e.g., storage, tabs, downloads).",
    "has_broad_host_access": "Broad host permissions granted (<all_urls> or *://*/*).",
    "has_sensitive_host_patterns": "Sensitive host access patterns targeting auth or payment domains.",
    "csp_has_unsafe_eval": "Content Security Policy explicitly permits unsafe-eval string execution.",
    "update_url_is_external": "Update URL points to external or untrusted server instead of Chrome Web Store.",
    "has_native_messaging": "Requests nativeMessaging permission allowing arbitrary local OS binary execution.",
    "call_chrome_webrequest": "Intercepts or modifies browser network requests via chrome.webRequest.",
    "call_chrome_cookies": "Accesses user session cookies via chrome.cookies.",
    "call_chrome_tabs": "Inspects active tab URLs and page metadata via chrome.tabs.",
    "call_eval": "Uses eval() or Function constructor to dynamically evaluate strings as code.",
    "call_dynamic_script_injection": "Dynamically injects external scripts into web page DOM contexts.",
    "external_url_count": "Hardcoded external HTTP/HTTPS domain references in JavaScript source.",
    "ip_literal_url_count": "Raw IP literal addresses embedded directly in script code.",
    "shannon_entropy_source": "Shannon entropy of JavaScript source code (high entropy indicates compression/packing).",
    "shannon_entropy_strings": "Shannon entropy of string literals in JavaScript code.",
    "hex_identifier_count": "Hex-encoded obfuscated variable identifiers (_0x...).",
    "string_array_rotation_pattern": "String array extraction and rotation loop obfuscation pattern.",
    "escape_sequence_ratio": "High density of hex/unicode escape sequences in script code.",
    "long_base64_blob_count": "Large embedded base64 encoded strings (potential encrypted payloads).",
    "long_hex_blob_count": "Large embedded hex strings (potential shellcode or binary payloads).",
    "atob_btoa_into_eval_or_func": "Pipes decoded base64 directly into code evaluation routines.",
    "is_minified_heuristic": "Standard production code minification heuristic.",
    "obfuscation_risk_score": "Composite metric distinguishing malicious obfuscation from minification.",
    "declared_unused_perm_count": "Over-privileged permissions requested in manifest but unused in code.",
    "flag_cookies_broadhost_network": "High-risk combination: cookies + broad host access + external networking.",
    "flag_webrequest_redirect_broadhost": "Dangerous combination: webRequestBlocking + broad host redirection capability.",
    "flag_tabshistory_network": "Surveillance combination: tabs/history access combined with external network calls.",
    "flag_remotescript_eval": "Remote payload execution: external URL fetching + eval execution.",
    "flag_allpages_domform_network": "Form-stealing combination: all-page content scripts + DOM inputs + exfiltration.",
}


def check_threat_intel_match(sha256: str, extension_id: str | None = None) -> dict[str, Any] | None:
    """Check if extension hash or ID matches known malicious threat intelligence records in SQLite."""
    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Check by SHA-256
        cursor.execute(
            "SELECT internal_id, extension_id, source, label, label_evidence, threat_family, collection_date "
            "FROM samples WHERE sha256 = ? AND label = 'malicious' LIMIT 1",
            (sha256,),
        )
        row = cursor.fetchone()
        if row:
            return {
                "match_type": "sha256_exact",
                "internal_id": row["internal_id"],
                "extension_id": row["extension_id"],
                "source": row["source"],
                "threat_family": row["threat_family"],
                "label_evidence": row["label_evidence"],
                "collection_date": row["collection_date"],
            }

        # Check by Extension ID if provided
        if extension_id and len(extension_id) >= 16:
            cursor.execute(
                "SELECT internal_id, extension_id, source, label, label_evidence, threat_family, collection_date "
                "FROM samples WHERE extension_id = ? AND label = 'malicious' LIMIT 1",
                (extension_id,),
            )
            row = cursor.fetchone()
            if row:
                return {
                    "match_type": "extension_id_exact",
                    "internal_id": row["internal_id"],
                    "extension_id": row["extension_id"],
                    "source": row["source"],
                    "threat_family": row["threat_family"],
                    "label_evidence": row["label_evidence"],
                    "collection_date": row["collection_date"],
                }

    return None


def extract_local_shap_factors(
    model: Any,
    feature_vector: list[float],
    feature_names: list[str],
) -> tuple[list[RiskFactor], list[RiskFactor]]:
    """Compute local feature contributions using SHAP TreeExplainer or deterministic importances."""
    x = np.array([feature_vector], dtype=float)
    x_imputed = x

    # Attempt to extract base tree estimator from CalibratedClassifierCV
    base_estimator = None
    if hasattr(model, "calibrated_classifiers_") and len(model.calibrated_classifiers_) > 0:
        first_cal = model.calibrated_classifiers_[0]
        base_estimator = getattr(first_cal, "estimator", first_cal)
    elif hasattr(model, "estimator"):
        base_estimator = model.estimator
    else:
        base_estimator = model

    # Unpack pipeline if present
    imputer = None
    classifier = base_estimator
    if hasattr(base_estimator, "named_steps"):
        imputer = base_estimator.named_steps.get("imputer")
        classifier = base_estimator.named_steps.get("classifier", base_estimator)
        if imputer is not None:
            try:
                x_imputed = imputer.transform(x)
            except Exception:
                x_imputed = x

    shap_values = None
    try:
        import shap
        explainer = shap.TreeExplainer(classifier)
        raw_vals = explainer.shap_values(x_imputed)
        if isinstance(raw_vals, list) and len(raw_vals) == 2:
            shap_values = raw_vals[1][0]
        elif isinstance(raw_vals, np.ndarray):
            if raw_vals.ndim == 3 and raw_vals.shape[2] == 2:
                shap_values = raw_vals[0, :, 1]
            elif raw_vals.ndim == 2:
                shap_values = raw_vals[0]
    except Exception:
        shap_values = None

    # Fallback to feature importance * normalized feature value
    if shap_values is None or len(shap_values) != len(feature_names):
        importances = getattr(classifier, "feature_importances_", None)
        if importances is not None and len(importances) == len(feature_names):
            shap_values = importances * np.minimum(x[0], 5.0)
        else:
            shap_values = np.zeros(len(feature_names))

    # Rank factors
    scored_factors = []
    for i, name in enumerate(feature_names):
        val = float(feature_vector[i])
        s_val = float(shap_values[i])
        desc = FEATURE_DESCRIPTIONS.get(name, f"Static detector indicator: {name}")
        scored_factors.append({
            "name": name,
            "val": val,
            "shap": s_val,
            "desc": desc,
        })

    # Sort positive contributors (increasing risk)
    pos = [f for f in scored_factors if f["shap"] > 0.001 or (f["val"] > 0 and f["name"].startswith("flag_"))]
    pos.sort(key=lambda item: item["shap"], reverse=True)
    top_pos: list[RiskFactor] = [
        RiskFactor(
            feature_name=f["name"],
            feature_value=f["val"],
            shap_value=float(round(f["shap"], 4)),
            direction="increases_risk",
            description=f["desc"],
        )
        for f in pos[:6]
    ]

    # Sort negative contributors (reducing risk / protective)
    neg = [f for f in scored_factors if f["shap"] < -0.001]
    neg.sort(key=lambda item: item["shap"])
    top_neg: list[RiskFactor] = [
        RiskFactor(
            feature_name=f["name"],
            feature_value=f["val"],
            shap_value=float(round(f["shap"], 4)),
            direction="reduces_risk",
            description=f["desc"],
        )
        for f in neg[:4]
    ]

    return top_pos, top_neg


def run_full_inference(
    temp_dir: Path,
    sha256: str,
    format_str: str,
    manifest: NormalizedManifest,
    summary: ExtractionSummary,
) -> ScanResultResponse:
    """Execute complete static analysis, threat intel check, ML inference, and DB persistence."""
    scan_id = str(uuid.uuid4())
    scanned_at = datetime.now(timezone.utc).isoformat()

    # 1. Feature Extraction
    feat_dict, feat_vector, evidence, _ = extract_features_from_directory(temp_dir, manifest)

    # 2. Threat Intel Match Check
    threat_intel = check_threat_intel_match(sha256=sha256, extension_id=manifest.name)
    matched_threat_intel = threat_intel is not None

    # 3. Model Scoring
    model, model_card = get_active_model()
    alert_threshold = 0.5
    calibrated_prob = 0.0

    if model is not None:
        alert_threshold = float(model_card.get("alert_threshold", 0.5))
        try:
            x_arr = np.array([feat_vector], dtype=float)
            if hasattr(model, "predict_proba"):
                calibrated_prob = float(model.predict_proba(x_arr)[0, 1])
            else:
                calibrated_prob = float(model.predict(x_arr)[0])
        except Exception:
            calibrated_prob = 0.5
        top_risk, protective = extract_local_shap_factors(model, feat_vector, ALL_FEATURE_KEYS)
    else:
        # Fallback to Heuristic Baseline
        base = HeuristicRuleBaseline()
        x_arr = np.array([feat_vector], dtype=float)
        calibrated_prob = float(base.predict_proba(x_arr)[0, 1])
        top_risk, protective = [], []

    # 4. Outcome Classification (Strictly Separated & Transparent)
    if matched_threat_intel:
        risk_verdict = "KNOWN_MALICIOUS_IOC"
        risk_verdict_label = "Known Threat Match (Threat Intel IOC)"
        risk_score = 1.0
    elif calibrated_prob >= 0.65 or (calibrated_prob >= alert_threshold and calibrated_prob >= 0.50):
        risk_verdict = "HIGH_RISK"
        risk_verdict_label = "High Model Risk (Malicious Indicators Detected)"
        risk_score = float(round(calibrated_prob, 4))
    elif calibrated_prob >= 0.20:
        risk_verdict = "SUSPICIOUS_UNCERTAIN"
        risk_verdict_label = "Suspicious / Uncertain Risk"
        risk_score = float(round(calibrated_prob, 4))
    else:
        risk_verdict = "LOW_RISK"
        risk_verdict_label = "Low Model Risk (Static Heuristics)"
        risk_score = float(round(calibrated_prob, 4))

    # 5. Mandatory Disclaimers
    prevalence_warning = (
        "PREVALENCE NOTICE: In real-world web stores, malicious extensions represent <1.0% of all extensions. "
        "Test precision on enriched datasets can overstate real-world accuracy due to base rate fallacy. "
        "High risk scores warrant manual inspection."
    )
    limitations_disclaimer = (
        "STATIC ANALYSIS LIMITATION: Zero code execution, dynamic instrumentation, or sandboxing was performed. "
        "A low model risk score does NOT guarantee that the extension is completely safe, as dynamic payload downloads "
        "or encrypted C2 channels cannot be observed through static analysis alone."
    )

    # 6. Build response
    scan_result = ScanResultResponse(
        scan_id=scan_id,
        sha256=sha256,
        format=format_str,
        manifest=manifest,
        extraction_summary=summary,
        risk_verdict=risk_verdict,
        risk_verdict_label=risk_verdict_label,
        risk_score=risk_score,
        alert_threshold=alert_threshold,
        matched_threat_intel=matched_threat_intel,
        threat_intel_details=threat_intel,
        top_risk_factors=top_risk,
        protective_factors=protective,
        evidence=evidence,
        prevalence_warning=prevalence_warning,
        limitations_disclaimer=limitations_disclaimer,
        scanned_at=scanned_at,
    )

    # 7. Persist to SQLite Scan History
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO scan_history (
                scan_id, sha256, extension_id, extension_name, version,
                timestamp, score, risk_category, matched_threat_intel, report_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                sha256,
                manifest.name,
                manifest.name,
                manifest.version,
                scanned_at,
                risk_score,
                risk_verdict,
                1 if matched_threat_intel else 0,
                json.dumps(scan_result.model_dump(), indent=2),
            ),
        )

    return scan_result
