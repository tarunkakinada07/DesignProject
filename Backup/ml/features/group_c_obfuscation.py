"""Group C: Obfuscation Indicators Feature Extractor.

Detects obfuscation techniques:
- Hex-style identifiers (_0x1a2b)
- String-array-plus-rotation patterns (Obfuscator.io)
- High escape-sequence ratios (\\x.., \\u..)
- Long base64 and hex literal blobs (excluding benign static data URIs)
- atob/btoa feeding eval or Function
- String.fromCharCode concatenation

CRITICAL REQUIREMENT (Section 2.2):
Separates 'minified' from 'obfuscated'. Minification alone (long lines, single-letter
variables, Webpack/Terser/Rollup bundles, SVG data URIs) must NEVER trigger high
obfuscation scores or cause false positives.
"""

from __future__ import annotations

import re
from pathlib import Path

from ml.parsing.ast_analyzer import (
    ASTAnalysisResult,
    analyze_javascript_file,
)

HEX_IDENTIFIER_REGEX = re.compile(r"\b_0x[a-fA-F0-9]{3,8}\b")
STRING_ARRAY_ROTATION_REGEX = re.compile(
    r"(?:var|let|const)\s+([a-zA-Z0-9_$]+)\s*=\s*\[\s*(?:['\"`][^'\"`]*['\"`]\s*,\s*){4,}.*?\]\s*;\s*"
    r"\(\s*function\s*\(\s*([a-zA-Z0-9_$]+)\s*,\s*([a-zA-Z0-9_$]+)\s*\)\s*\{.*?(?:push\s*\(\s*\2\.shift|\.shift\s*\(\s*\))",
    re.DOTALL,
)
ESCAPE_SEQUENCE_REGEX = re.compile(r"\\(?:x[a-fA-F0-9]{2}|u[a-fA-F0-9]{4})")
LONG_BASE64_REGEX = re.compile(r"['\"`]([A-Za-z0-9+/=]{60,})['\"`]")
DATA_URI_BASE64_REGEX = re.compile(
    r"['\"`]data:(?:image|font|application)/(?:svg\+xml|png|jpeg|webp|woff2?|json);base64,[A-Za-z0-9+/=]{40,}['\"`]",
    re.IGNORECASE,
)
LONG_HEX_REGEX = re.compile(r"['\"`]([0-9a-fA-F]{40,})['\"`]")
ATOB_FEEDING_EVAL_REGEX = re.compile(
    r"(?:eval|Function)\s*\(\s*(?:window\.)?atob\s*\(|"
    r"(?:window\.)?atob\s*\([^)]*\)\s*\)\s*;\s*(?:eval|Function)"
)
FROM_CHAR_CODE_REGEX = re.compile(r"String\.fromCharCode\s*\(\s*(?:\d+\s*,\s*){3,}\d+\s*\)")

# Bundler / Minifier markers indicating legitimate build output
BUNDLER_MARKERS_REGEX = re.compile(
    r"\b(?:__webpack_require__|webpackChunk|__esModule|parcelRequire|define\.amd|Symbol\.iterator|regeneratorRuntime|vite)\b"
)


def extract_group_c_obfuscation_features(
    extension_dir: Path,
) -> tuple[dict[str, float], list[str]]:
    """Extract Group C obfuscation indicators and evidence.

    Combines AST-verified transformations with multi-signal heuristics to separate
    benign minified bundles from hostile commercial obfuscators.

    Returns (features_dict, evidence_notes).
    """
    evidence: list[str] = []
    features: dict[str, float] = {}

    js_files = [
        p for p in extension_dir.rglob("*")
        if p.is_file() and p.suffix.lower() in {".js", ".mjs", ".cjs"}
    ]

    if not js_files:
        return {
            "hex_identifier_count": 0.0,
            "string_array_rotation_pattern": 0.0,
            "escape_sequence_ratio": 0.0,
            "long_base64_blob_count": 0.0,
            "long_hex_blob_count": 0.0,
            "atob_btoa_into_eval_or_func": 0.0,
            "char_code_concatenation_count": 0.0,
            "is_minified_heuristic": 0.0,
            "obfuscation_risk_score": 0.0,
        }, evidence

    total_chars = 0
    total_escapes = 0
    hex_ids = 0
    string_rotations = 0
    base64_blobs = 0
    hex_blobs = 0
    atob_evals = 0
    char_codes = 0
    bundler_marker_hits = 0

    max_line_len = 0
    line_count = 0

    for js_p in js_files:
        try:
            content = js_p.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        total_chars += len(content)
        lines = content.splitlines()
        line_count += len(lines)
        for line in lines:
            if len(line) > max_line_len:
                max_line_len = len(line)

        # 1. Structural AST check
        ast_result: ASTAnalysisResult = analyze_javascript_file(js_p)
        if ast_result.atob_exec_count > 0:
            atob_evals += ast_result.atob_exec_count
        if ast_result.string_array_rotations > 0:
            string_rotations += ast_result.string_array_rotations
        if ast_result.hex_identifiers > 0:
            hex_ids += ast_result.hex_identifiers

        # 2. Count patterns with regex
        regex_hex_ids = len(HEX_IDENTIFIER_REGEX.findall(content))
        hex_ids = max(hex_ids, regex_hex_ids)

        regex_string_rotations = len(STRING_ARRAY_ROTATION_REGEX.findall(content))
        string_rotations = max(string_rotations, regex_string_rotations)

        total_escapes += len(ESCAPE_SEQUENCE_REGEX.findall(content))

        # Filter out benign base64 data URIs (images, fonts, svgs)
        data_uris = len(DATA_URI_BASE64_REGEX.findall(content))
        raw_b64 = len(LONG_BASE64_REGEX.findall(content))
        suspicious_b64 = max(0, raw_b64 - data_uris)
        base64_blobs += suspicious_b64

        hex_blobs += len(LONG_HEX_REGEX.findall(content))

        regex_atob_evals = len(ATOB_FEEDING_EVAL_REGEX.findall(content))
        atob_evals = max(atob_evals, regex_atob_evals)

        char_codes += len(FROM_CHAR_CODE_REGEX.findall(content))

        if BUNDLER_MARKERS_REGEX.search(content):
            bundler_marker_hits += 1

    escape_ratio = (
        float(total_escapes) / float(total_chars) if total_chars > 0 else 0.0
    )

    # Multi-signal Minification Identification
    # Characterized by long lines / minified structure, bundler markers, or high density of short lines,
    # but LACK of hostile string rotation loops and decode-to-exec pipelines.
    has_hostile_obfuscation = (string_rotations > 0 or atob_evals > 0 or hex_ids >= 10)
    is_minified_structure = (
        max_line_len > 1000
        or (line_count > 0 and total_chars / line_count > 250)
        or bundler_marker_hits > 0
    )

    is_minified = is_minified_structure and not has_hostile_obfuscation and escape_ratio < 0.02

    features["hex_identifier_count"] = float(hex_ids)
    features["string_array_rotation_pattern"] = float(string_rotations)
    features["escape_sequence_ratio"] = float(round(escape_ratio, 6))
    features["long_base64_blob_count"] = float(base64_blobs)
    features["long_hex_blob_count"] = float(hex_blobs)
    features["atob_btoa_into_eval_or_func"] = float(atob_evals)
    features["char_code_concatenation_count"] = float(char_codes)
    features["is_minified_heuristic"] = 1.0 if is_minified else 0.0

    # Composite obfuscation score (0.0 to 1.0)
    score = 0.0
    if hex_ids > 0:
        score += min(0.35, hex_ids * 0.05)
    if string_rotations > 0:
        score += 0.35
    if atob_evals > 0:
        score += 0.30
    if char_codes > 0:
        score += min(0.20, char_codes * 0.05)
    if escape_ratio > 0.02:
        score += min(0.20, escape_ratio * 5)
    if base64_blobs > 0:
        score += min(0.15, base64_blobs * 0.03)

    # Multi-signal adjustment:
    # If code is standard minified/bundled code without obfuscation artifacts, score remains 0.0
    if is_minified and hex_ids == 0 and string_rotations == 0 and atob_evals == 0:
        score = 0.0

    features["obfuscation_risk_score"] = float(round(min(1.0, score), 4))

    # Evidence notes
    if hex_ids > 0:
        evidence.append(f"[HEURISTIC_SUSPICION] Mangled hex identifiers detected: {hex_ids} instances (e.g. _0x...)")
    if string_rotations > 0:
        evidence.append("[THREAT_INDICATOR] Obfuscator.io string-array and shift/rotation pattern detected")
    if atob_evals > 0:
        evidence.append("[THREAT_INDICATOR] Base64 decoding directly into dynamic code execution (atob -> eval/Function)")
    if char_codes > 0:
        evidence.append(f"[OBSERVED_FACT] String.fromCharCode concatenation count: {char_codes}")
    if is_minified:
        evidence.append("[OBSERVED_FACT] Code exhibits typical production minification (not classified as malicious obfuscation)")

    return features, evidence
