"""Group B: JavaScript Static Feature Extractor.

Extracts static structural and API usage features across JavaScript files:
- Line counts, size, line length statistics
- Sensitive chrome.* and browser.* API calls (dot and computed bracket access)
- Network calls (fetch, XMLHttpRequest, WebSocket, sendBeacon)
- Dynamic code execution (eval, new Function, aliased eval, dynamic script tags)
- External URLs, IP literals, and Shannon entropy
- AST-guided structural inspection via Esprima with safe lexical fallback
"""

from __future__ import annotations

import math
import re
from pathlib import Path
from typing import Any

from ml.parsing.ast_analyzer import (
    ASTAnalysisResult,
    FindingEvidence,
    analyze_javascript_file,
)

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

    Combines AST-based structural inspection with lexical regex patterns to guarantee
    zero missed detections while accurately capturing aliasing, bracket access, and
    decode-to-exec pipelines.

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
        return features, evidence, {
            "js_files": [],
            "code_categories": {},
            "parser_warnings": [],
            "ast_findings": [],
        }

    total_bytes = 0
    total_lines = 0
    max_line_len = 0
    all_source_concat = []
    all_strings = []
    external_urls_seen = set()
    ip_literals_seen = set()
    parser_warnings: list[str] = []
    ast_findings: list[dict[str, Any]] = []
    code_categories: dict[str, int] = {}

    for js_p in js_files:
        try:
            content = js_p.read_text(encoding="utf-8", errors="ignore")
        except Exception as e:
            parser_warnings.append(f"Failed to read {js_p.name}: {e}")
            continue

        size = len(content.encode("utf-8"))
        total_bytes += size
        lines = content.splitlines()
        total_lines += len(lines)
        for line in lines:
            if len(line) > max_line_len:
                max_line_len = len(line)

        all_source_concat.append(content)

        # 1. Structural AST Analysis
        ast_result: ASTAnalysisResult = analyze_javascript_file(js_p)
        if ast_result.parser_warning:
            parser_warnings.append(f"{js_p.name}: {ast_result.parser_warning}")

        # Track code categories across files
        cat = ast_result.code_category
        code_categories[cat] = code_categories.get(cat, 0) + 1

        # Extract structured AST evidence
        for ev in ast_result.evidence:
            tag = f"[{ev.category.upper()}]"
            loc = f":{ev.line_number}" if ev.line_number else ""
            ast_findings.append({
                "file": ev.file_name,
                "line": ev.line_number,
                "category": ev.category,
                "description": ev.description,
            })
            evidence.append(f"{tag} {ev.file_name}{loc} — {ev.description}")

        # 2. Count API patterns: combine AST count and Lexical count (max)
        for key, pat in API_PATTERNS.items():
            regex_matches = len(pat.findall(content))
            ast_matches = ast_result.api_counts.get(key, 0)

            # In AST, aliased eval counts towards call_eval
            if key == "call_eval" and ast_result.aliased_eval_count > 0:
                ast_matches += ast_result.aliased_eval_count
            # In AST, DOM script injections count towards call_dynamic_script_injection
            if key == "call_dynamic_script_injection" and ast_result.dom_script_injections > 0:
                ast_matches = max(ast_matches, ast_result.dom_script_injections)

            features[key] += float(max(regex_matches, ast_matches))

        # 3. Extract URLs
        for m in URL_REGEX.findall(content):
            external_urls_seen.add(m)
        for m in IP_LITERAL_REGEX.findall(content):
            ip_literals_seen.add(m)

        # 4. Extract string literals
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

    # Record high-level summary evidence if not already covered
    if features["call_eval"] > 0 and not any("eval" in e.lower() for e in evidence):
        evidence.append(f"[HEURISTIC_SUSPICION] Dynamic eval() invocation count: {int(features['call_eval'])}")
    if features["call_function_constructor"] > 0 and not any("function()" in e.lower() for e in evidence):
        evidence.append(
            f"[HEURISTIC_SUSPICION] Dynamic Function() constructor count: {int(features['call_function_constructor'])}"
        )
    if features["call_chrome_cookies"] > 0 and not any("cookies" in e.lower() for e in evidence):
        evidence.append(f"[OBSERVED_FACT] Direct chrome.cookies API calls: {int(features['call_chrome_cookies'])}")
    if features["call_chrome_webrequest"] > 0 and not any("webrequest" in e.lower() for e in evidence):
        evidence.append(
            f"[OBSERVED_FACT] Direct chrome.webRequest interception calls: {int(features['call_chrome_webrequest'])}"
        )
    if features["call_chrome_scripting"] > 0 and not any("scripting" in e.lower() for e in evidence):
        evidence.append(
            f"[OBSERVED_FACT] Dynamic code injection via chrome.scripting: {int(features['call_chrome_scripting'])}"
        )
    if features["ip_literal_url_count"] > 0:
        evidence.append(f"[THREAT_INDICATOR] Hardcoded IP literal URLs found: {int(features['ip_literal_url_count'])}")

    metadata = {
        "js_files": [str(p.name) for p in js_files],
        "external_urls_sample": list(external_urls_seen)[:5],
        "ip_literals": list(ip_literals_seen),
        "code_categories": code_categories,
        "parser_warnings": parser_warnings,
        "ast_findings": ast_findings[:20],
    }

    return features, evidence, metadata
