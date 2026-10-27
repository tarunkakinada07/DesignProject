"""Group D: Behavior-Combination and Mismatch Feature Extractor.

Calculates:
- Declared-versus-used permission over-privilege
- Dangerous combinations as explicit boolean flags:
  * cookies + broad host + network send
  * webRequest/declarativeNetRequest + redirect rules + broad host
  * tabs/history + network send
  * remote script fetch followed by eval or dynamic injection
  * content script on all pages + DOM form access + network send
- Remote code loading indicators (fetching remote JS and executing/injecting)
"""

import re
from pathlib import Path

from backend.app.schemas.manifest import NormalizedManifest

# Mapping of standard permissions to JS usage patterns
PERMISSION_USAGE_REGEX = {
    "cookies": re.compile(r"\b(?:chrome|browser)\.cookies\b"),
    "tabs": re.compile(r"\b(?:chrome|browser)\.tabs\b"),
    "history": re.compile(r"\b(?:chrome|browser)\.history\b"),
    "storage": re.compile(r"\b(?:chrome|browser)\.storage\b"),
    "webrequest": re.compile(r"\b(?:chrome|browser)\.webRequest\b"),
    "webrequestblocking": re.compile(r"\b(?:chrome|browser)\.webRequest\b"),
    "declarativenetrequest": re.compile(r"\b(?:chrome|browser)\.declarativeNetRequest\b"),
    "management": re.compile(r"\b(?:chrome|browser)\.management\b"),
    "proxy": re.compile(r"\b(?:chrome|browser)\.proxy\b"),
    "downloads": re.compile(r"\b(?:chrome|browser)\.downloads\b"),
    "scripting": re.compile(r"\b(?:chrome|browser)\.scripting\b"),
    "bookmarks": re.compile(r"\b(?:chrome|browser)\.bookmarks\b"),
    "geolocation": re.compile(r"\bnavigator\.geolocation\b"),
}

REDIRECT_REGEX = re.compile(r"(?:redirectUrl|redirect|blocking|onBeforeRequest)", re.IGNORECASE)
FORM_INPUT_REGEX = re.compile(
    r"(?:type\s*===\s*['\"`]password['\"`]|input\[type=['\"`]password['\"`]|"
    r"document\.(?:forms|getElementById|querySelector).*(?:password|cardNumber|cvv|token|auth))",
    re.IGNORECASE,
)
REMOTE_SCRIPT_FETCH_EVAL_REGEX = re.compile(
    r"fetch\s*\([^)]*\.js['\"`\?][^)]*\)\s*\.then\(.*?(?:eval|Function|document\.createElement)",
    re.DOTALL | re.IGNORECASE,
)
REMOTE_CODE_LOADING_REGEX = re.compile(
    r"(?:fetch|XMLHttpRequest|getScript|ajax)\s*\([^)]*https?://[^)]*\)\s*\.then\(.*?(?:eval|new\s+Function|appendChild)|"
    r"import\s*\(\s*['\"`]https?://|"
    r"document\.createElement\s*\(\s*['\"`]script['\"`]\s*\)\s*;\s*[\w$]+\.src\s*=\s*['\"`]https?://",
    re.DOTALL | re.IGNORECASE,
)


def extract_group_d_behavior_features(
    manifest: NormalizedManifest,
    extension_dir: Path,
    group_a_features: dict[str, float],
    group_b_features: dict[str, float],
) -> tuple[dict[str, float], list[str]]:
    """Extract Group D behavior-combination and mismatch features.

    Returns (features_dict, evidence_notes).
    """
    evidence: list[str] = []
    features: dict[str, float] = {}

    # Read all JS source files concatenated
    all_js_text = []
    js_files = [
        p for p in extension_dir.rglob("*")
        if p.is_file() and p.suffix.lower() in {".js", ".mjs", ".cjs"}
    ]
    for p in js_files:
        try:
            all_js_text.append(p.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            continue
    concat_code = "\n".join(all_js_text)

    # 1. Declared-versus-used (over-privilege)
    declared_perms = [p.lower() for p in manifest.permissions]
    unused_count = 0
    unused_list = []
    for perm in declared_perms:
        if perm in PERMISSION_USAGE_REGEX:
            pat = PERMISSION_USAGE_REGEX[perm]
            if not pat.search(concat_code):
                unused_count += 1
                unused_list.append(perm)

    features["declared_unused_perm_count"] = float(unused_count)
    if unused_list:
        evidence.append(f"Over-privileged: permissions declared but never referenced: {', '.join(unused_list)}")

    has_broad_host = group_a_features.get("has_broad_host_access", 0.0) > 0
    has_network_send = (
        group_b_features.get("call_fetch", 0.0) > 0
        or group_b_features.get("call_xmlhttprequest", 0.0) > 0
        or group_b_features.get("call_websocket", 0.0) > 0
        or group_b_features.get("call_sendbeacon", 0.0) > 0
    )

    # 2. Flag: Cookies + Broad Host + Network Send
    has_cookies = (
        "cookies" in declared_perms
        or group_b_features.get("call_chrome_cookies", 0.0) > 0
    )
    flag_cookies = float(bool(has_cookies and has_broad_host and has_network_send))
    features["flag_cookies_broadhost_network"] = flag_cookies
    if flag_cookies > 0:
        evidence.append("CRITICAL COMBINATION: Cookies access + Broad Host pattern + Network send capability")

    # 3. Flag: webRequest/declarativeNetRequest + Redirect Rules + Broad Host
    has_net_intercept = (
        "webrequest" in declared_perms
        or "declarativenetrequest" in declared_perms
        or group_b_features.get("call_chrome_webrequest", 0.0) > 0
        or group_b_features.get("call_chrome_declarativenetrequest", 0.0) > 0
    )
    has_redirect = bool(REDIRECT_REGEX.search(concat_code))
    flag_redirect = float(bool(has_net_intercept and has_redirect and has_broad_host))
    features["flag_webrequest_redirect_broadhost"] = flag_redirect
    if flag_redirect > 0:
        evidence.append("CRITICAL COMBINATION: Traffic interception + URL redirection rules + Broad host scope")

    # 4. Flag: Tabs / History + Network Send
    has_tabs_history = (
        group_b_features.get("call_chrome_tabs", 0.0) > 0
        or group_b_features.get("call_chrome_history", 0.0) > 0
        or "tabs" in declared_perms
        or "history" in declared_perms
    )
    flag_tabshistory = float(bool(has_tabs_history and has_network_send))
    features["flag_tabshistory_network"] = flag_tabshistory
    if flag_tabshistory > 0:
        evidence.append("Suspicious combination: Browsing history/active tab access paired with network egress")

    # 5. Flag: Remote script fetch followed by eval or dynamic injection
    has_remotescript_eval = bool(REMOTE_SCRIPT_FETCH_EVAL_REGEX.search(concat_code))
    # Also if fetch/xhr > 0 and eval/function > 0
    has_fetch_and_eval = (
        has_network_send
        and (
            group_b_features.get("call_eval", 0.0) > 0
            or group_b_features.get("call_function_constructor", 0.0) > 0
        )
    )
    flag_remote_eval = float(bool(has_remotescript_eval or has_fetch_and_eval))
    features["flag_remotescript_eval"] = flag_remote_eval
    if flag_remote_eval > 0:
        evidence.append("HIGH RISK COMBINATION: Network fetching co-occurring with dynamic code execution (eval/Function)")

    # 6. Flag: Content script on all pages + DOM form access + Network Send
    has_content_script_all = group_a_features.get("content_script_all_urls", 0.0) > 0
    has_form_access = bool(FORM_INPUT_REGEX.search(concat_code))
    flag_domform = float(bool(has_content_script_all and has_form_access and has_network_send))
    features["flag_allpages_domform_network"] = flag_domform
    if flag_domform > 0:
        evidence.append("CRITICAL COMBINATION: Content script on all pages + Sensitive form/credential access + Network egress")

    # 7. Remote code loading indicators
    remote_code_matches = len(REMOTE_CODE_LOADING_REGEX.findall(concat_code))
    features["remote_code_loading_count"] = float(remote_code_matches)
    if remote_code_matches > 0:
        evidence.append(f"Remote code loading pattern detected: {remote_code_matches} occurrences")

    return features, evidence
