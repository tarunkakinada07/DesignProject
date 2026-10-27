"""Group B: JavaScript Static Feature Extractor.

Extracts static structural and API usage features across JavaScript files:
- Line counts, size, line length statistics
- Sensitive chrome.* and browser.* API calls
- Network calls (fetch, XMLHttpRequest, WebSocket, sendBeacon)
- Dynamic code execution (eval, new Function, setTimeout with strings, dynamic script tags)
- External URLs, IP literals, and Shannon entropy
"""

import math
import re
from pathlib import Path
from typing import Any

API_PATTERNS = {
    "call_chrome_webrequest": re.compile(r"\b(?:chrome|browser)\.webRequest\b"),
    "call_chrome_cookies": re.compile(r"\b(?:chrome|browser)\.cookies\b"),
    "call_chrome_tabs": re.compile(r"\b(?:chrome|browser)\.tabs\b"),
    "call_chrome_history": re.compile(r"\b(?:chrome|browser)\.history\b"),
    "call_chrome_storage": re.compile(r"\b(?:chrome|browser)\.storage\b"),
    "call_chrome_scripting": re.compile(
        r"\b(?:(?:chrome|browser)\.scripting|(?:chrome|browser)\.tabs\.executeScript)\b"
    ),
    "call_chrome_declarativenetrequest": re.compile(r"\b(?:chrome|browser)\.declarativeNetRequest\b"),
    "call_chrome_management": re.compile(r"\b(?:chrome|browser)\.management\b"),
    "call_chrome_proxy": re.compile(r"\b(?:chrome|browser)\.proxy\b"),
    "call_chrome_downloads": re.compile(r"\b(?:chrome|browser)\.downloads\b"),
    "call_fetch": re.compile(r"\bfetch\s*\("),
    "call_xmlhttprequest": re.compile(r"\b(?:new\s+)?XMLHttpRequest\b"),
    "call_websocket": re.compile(r"\b(?:new\s+)?WebSocket\b"),
    "call_sendbeacon": re.compile(r"\b(?:navigator\.)?sendBeacon\s*\("),
    "call_eval": re.compile(r"\b(?:window\.)?eval\s*\("),
    "call_function_constructor": re.compile(r"\bnew\s+Function\s*\("),
    "call_settimeout_string": re.compile(
        r"\b(?:setTimeout|setInterval)\s*\(\s*['\"`][^'\"`]+['\"`]"
    ),
    "call_dynamic_script_injection": re.compile(
        r"document\.createElement\s*\(\s*['\"`]script['\"`]\s*\)|"
        r"\.src\s*=\s*['\"`][^'\"`]+\.js['\"`]|"
        r"\.appendChild\s*\(\s*[\w$]+\s*\)"
    ),
}

URL_REGEX = re.compile(r"https?://(?:[a-zA-Z0-9\-\.]+|\[[a-fA-F0-9:]+\])(?::\d+)?(?:/[^\s'\"<>]*)?")
IP_LITERAL_REGEX = re.compile(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?(?:/[^\s'\"<>]*)?")
STRING_LITERAL_REGEX = re.compile(r"(['\"`])(?:\\.|(?!\1)[^\\])*\1")


def compute_shannon_entropy(data: str) -> float:
    """Compute base-2 Shannon entropy H = -sum(p_i * log2(p_i)) over character frequencies."""
    if not data:
        return 0.0
    length = len(data)
    freq: dict[str, int] = {}
    for ch in data:
        freq[ch] = freq.get(ch, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def extract_group_b_js_features(
    extension_dir: Path,
) -> tuple[dict[str, float], list[str], dict[str, Any]]:
    """Extract Group B static features across all JavaScript files in the extension.

    Returns (features_dict, evidence_notes, metadata_dict).
    """
    evidence: list[str] = []
    features: dict[str, float] = {k: 0.0 for k in API_PATTERNS}

    js_files = [
        p for p in extension_dir.rglob("*")
        if p.is_file() and p.suffix.lower() in {".js", ".mjs", ".cjs"}
    ]

    features["js_file_count"] = float(len(js_files))

    if not js_files:
        features["total_js_bytes"] = 0.0
        features["total_js_lines"] = 0.0
        features["avg_line_length"] = 0.0
        features["max_line_length"] = 0.0
        features["external_url_count"] = 0.0
        features["ip_literal_url_count"] = 0.0
        features["shannon_entropy_source"] = 0.0
        features["shannon_entropy_strings"] = 0.0
        return features, evidence, {"js_files": []}

    total_bytes = 0
    total_lines = 0
    max_line_len = 0
    all_source_concat = []
    all_strings = []
    external_urls_seen = set()
    ip_literals_seen = set()

    for js_p in js_files:
        try:
            content = js_p.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        size = len(content.encode("utf-8"))
        total_bytes += size
        lines = content.splitlines()
        total_lines += len(lines)
        for line in lines:
            if len(line) > max_line_len:
                max_line_len = len(line)

        all_source_concat.append(content)

        # Count API patterns
        for key, pat in API_PATTERNS.items():
            matches = len(pat.findall(content))
            features[key] += float(matches)

        # Extract URLs
        for m in URL_REGEX.findall(content):
            external_urls_seen.add(m)
        for m in IP_LITERAL_REGEX.findall(content):
            ip_literals_seen.add(m)

        # Extract string literals
        for str_match in STRING_LITERAL_REGEX.findall(content):
            all_strings.append(str_match)

    features["total_js_bytes"] = float(total_bytes)
    features["total_js_lines"] = float(total_lines)
    features["max_line_length"] = float(max_line_len)
    features["avg_line_length"] = (
        float(total_bytes) / float(total_lines) if total_lines > 0 else 0.0
    )

    features["external_url_count"] = float(len(external_urls_seen))
    features["ip_literal_url_count"] = float(len(ip_literals_seen))

    # Compute entropy
    full_source = "".join(all_source_concat)
    features["shannon_entropy_source"] = compute_shannon_entropy(full_source[:50000])
    combined_strings = "".join(all_strings)
    features["shannon_entropy_strings"] = compute_shannon_entropy(combined_strings[:50000])

    # Record evidence
    if features["call_eval"] > 0:
        evidence.append(f"Dynamic eval() invocation count: {int(features['call_eval'])}")
    if features["call_function_constructor"] > 0:
        evidence.append(
            f"Dynamic Function() constructor count: {int(features['call_function_constructor'])}"
        )
    if features["call_chrome_cookies"] > 0:
        evidence.append(f"Direct chrome.cookies API calls: {int(features['call_chrome_cookies'])}")
    if features["call_chrome_webrequest"] > 0:
        evidence.append(
            f"Direct chrome.webRequest interception calls: {int(features['call_chrome_webrequest'])}"
        )
    if features["call_chrome_scripting"] > 0:
        evidence.append(
            f"Dynamic code injection via chrome.scripting: {int(features['call_chrome_scripting'])}"
        )
    if features["ip_literal_url_count"] > 0:
        evidence.append(f"Hardcoded IP literal URLs found: {int(features['ip_literal_url_count'])}")

    metadata = {
        "js_files": [str(p.name) for p in js_files],
        "external_urls_sample": list(external_urls_seen)[:5],
        "ip_literals": list(ip_literals_seen),
    }

    return features, evidence, metadata
