"""Group A: Manifest Static Feature Extractor.

Extracts normalized manifest risk features from NormalizedManifest.
Deterministic, versioned, zero runtime execution.
"""

import re

from backend.app.schemas.manifest import NormalizedManifest

HIGH_RISK_PERMISSIONS = {
    "webrequest",
    "webrequestblocking",
    "cookies",
    "tabs",
    "history",
    "proxy",
    "debugger",
    "management",
    "privacy",
    "geolocation",
    "scripting",
    "downloads",
    "nativemessaging",
}

MEDIUM_RISK_PERMISSIONS = {
    "storage",
    "notifications",
    "alarms",
    "contextmenus",
    "idle",
    "unlimitedstorage",
    "clipboardread",
    "clipboardwrite",
    "declarativenetrequest",
    "declarativenetrequestwithhostaccess",
}

SENSITIVE_HOST_KEYWORD_REGEX = re.compile(
    r"(bank|paypal|chase|wellsfargo|citi|crypto|coinbase|binance|metamask|kraken|"
    r"login|signin|oauth|accounts\.google|mail\.google|outlook|live\.com|facebook|twitter|github)",
    re.IGNORECASE,
)


def extract_group_a_manifest_features(
    manifest: NormalizedManifest,
) -> tuple[dict[str, float], list[str]]:
    """Extract Group A manifest features and human-readable evidence.

    Returns (features_dict, evidence_notes).
    """
    evidence: list[str] = []
    features: dict[str, float] = {}

    mv = float(manifest.manifest_version)
    features["manifest_version_num"] = mv

    all_perms = [p.lower() for p in manifest.permissions + manifest.optional_permissions]
    features["perm_count_total"] = float(len(all_perms))

    high_risk_matches = [p for p in all_perms if p in HIGH_RISK_PERMISSIONS]
    med_risk_matches = [p for p in all_perms if p in MEDIUM_RISK_PERMISSIONS]

    features["perm_count_high_risk"] = float(len(high_risk_matches))
    features["perm_count_medium_risk"] = float(len(med_risk_matches))

    if high_risk_matches:
        evidence.append(f"High-risk permissions requested: {', '.join(high_risk_matches)}")

    # Broad host access check-
    broad_patterns = {"<all_urls>", "*://*/*", "https://*/*", "http://*/*"}
    has_broad = any(
        hp.strip().lower() in broad_patterns
        or hp.strip().startswith(("*://*", "https://*", "http://*"))
        for hp in manifest.host_permissions
    )
    features["has_broad_host_access"] = 1.0 if has_broad else 0.0
    if has_broad:
        evidence.append("Broad host access (<all_urls> or universal wildcard) requested")

    # Sensitive host pattern check
    has_sensitive_host = any(
        bool(SENSITIVE_HOST_KEYWORD_REGEX.search(hp)) for hp in manifest.host_permissions
    )
    # Also inspect content script matches
    for cs in manifest.content_scripts:
        if any(bool(SENSITIVE_HOST_KEYWORD_REGEX.search(m)) for m in cs.matches):
            has_sensitive_host = True
            break
    features["has_sensitive_host_patterns"] = 1.0 if has_sensitive_host else 0.0
    if has_sensitive_host:
        evidence.append("Sensitive domain match pattern detected (banking/crypto/auth)")

    # Content scripts analysis
    features["content_script_count"] = float(len(manifest.content_scripts))
    cs_all_urls = any(
        any(m in broad_patterns for m in cs.matches) for cs in manifest.content_scripts
    )
    cs_all_frames = any(cs.all_frames for cs in manifest.content_scripts)

    features["content_script_all_urls"] = 1.0 if cs_all_urls else 0.0
    features["content_script_all_frames"] = 1.0 if cs_all_frames else 0.0
    if cs_all_urls:
        evidence.append("Content script injected into all URLs")

    # Background execution
    features["has_background_service_worker"] = 1.0 if manifest.background_service_worker else 0.0
    features["has_background_scripts"] = 1.0 if manifest.background_scripts else 0.0
    features["has_externally_connectable"] = 1.0 if manifest.externally_connectable else 0.0
    features["web_accessible_resource_count"] = float(len(manifest.web_accessible_resources))

    # CSP checks
    features["csp_has_unsafe_eval"] = 1.0 if manifest.csp_has_unsafe_eval else 0.0
    features["csp_has_remote_sources"] = 1.0 if manifest.csp_has_remote_sources else 0.0
    if manifest.csp_has_unsafe_eval:
        evidence.append("CSP permits 'unsafe-eval' dynamic code execution")
    if manifest.csp_has_remote_sources:
        evidence.append("CSP allows external script sources")

    # Update URL checks
    update_is_ext = bool(manifest.update_url and not manifest.update_url_is_official_store)
    features["update_url_is_external"] = 1.0 if update_is_ext else 0.0
    if update_is_ext:
        evidence.append(f"External update_url pointing outside Chrome Web Store: {manifest.update_url}")

    features["has_native_messaging"] = 1.0 if manifest.native_messaging_declared else 0.0
    if manifest.native_messaging_declared:
        evidence.append("Native messaging permission declared (can communicate with host binaries)")

    return features, evidence
