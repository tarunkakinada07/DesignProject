"""Group C: Obfuscation Indicators Feature Extractor.

Detects obfuscation techniques:
- Hex-style identifiers (_0x1a2b)
- String-array-plus-rotation patterns
- High escape-sequence ratios (\\x.., \\u..)
- Long base64 and hex literal blobs
- atob/btoa feeding eval or Function
- String.fromCharCode concatenation

CRITICAL REQUIREMENT:
Separates 'minified' from 'obfuscated'. Minification alone (long lines, single-letter variables)
must NEVER trigger high obfuscation scores.
"""

import re
from pathlib import Path

HEX_IDENTIFIER_REGEX = re.compile(r"\b_0x[a-fA-F0-9]{3,8}\b")
STRING_ARRAY_ROTATION_REGEX = re.compile(
    r"(?:var|let|const)\s+([a-zA-Z0-9_$]+)\s*=\s*\[\s*(?:['\"`][^'\"`]*['\"`]\s*,\s*){4,}.*?\]\s*;\s*"
    r"\(\s*function\s*\(\s*([a-zA-Z0-9_$]+)\s*,\s*([a-zA-Z0-9_$]+)\s*\)\s*\{.*?(?:push\s*\(\s*\2\.shift|\.shift\s*\(\s*\))",
    re.DOTALL,
)
ESCAPE_SEQUENCE_REGEX = re.compile(r"\\(?:x[a-fA-F0-9]{2}|u[a-fA-F0-9]{4})")
LONG_BASE64_REGEX = re.compile(r"['\"`]([A-Za-z0-9+/=]{60,})['\"`]")
LONG_HEX_REGEX = re.compile(r"['\"`]([0-9a-fA-F]{40,})['\"`]")
ATOB_FEEDING_EVAL_REGEX = re.compile(
    r"(?:eval|Function)\s*\(\s*(?:window\.)?atob\s*\(|"
    r"(?:window\.)?atob\s*\([^)]*\)\s*\)\s*;\s*(?:eval|Function)"
)
FROM_CHAR_CODE_REGEX = re.compile(r"String\.fromCharCode\s*\(\s*(?:\d+\s*,\s*){3,}\d+\s*\)")


def extract_group_c_obfuscation_features(
    extension_dir: Path,
) -> tuple[dict[str, float], list[str]]:
    """Extract Group C obfuscation indicators and evidence.

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

        # Count patterns
        hex_ids += len(HEX_IDENTIFIER_REGEX.findall(content))
        string_rotations += len(STRING_ARRAY_ROTATION_REGEX.findall(content))
        total_escapes += len(ESCAPE_SEQUENCE_REGEX.findall(content))
        base64_blobs += len(LONG_BASE64_REGEX.findall(content))
        hex_blobs += len(LONG_HEX_REGEX.findall(content))
        atob_evals += len(ATOB_FEEDING_EVAL_REGEX.findall(content))
        char_codes += len(FROM_CHAR_CODE_REGEX.findall(content))

    escape_ratio = (
        float(total_escapes) / float(total_chars) if total_chars > 0 else 0.0
    )

    # Heuristic for minification:
    # Characterized by long lines / few newlines, but LACK of hex identifiers & rotation loops
    is_minified = (
        (max_line_len > 1000 or (line_count > 0 and total_chars / line_count > 250))
        and hex_ids == 0
        and string_rotations == 0
        and atob_evals == 0
        and escape_ratio < 0.01
    )

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

    # If code is standard minified code without obfuscation artifacts, score remains 0.0
    if is_minified and hex_ids == 0 and string_rotations == 0 and atob_evals == 0:
        score = 0.0

    features["obfuscation_risk_score"] = float(round(min(1.0, score), 4))

    # Evidence notes
    if hex_ids > 0:
        evidence.append(f"Mangled hex identifiers detected: {hex_ids} instances (e.g. _0x...)")
    if string_rotations > 0:
        evidence.append("Obfuscator.io string-array and shift/rotation pattern detected")
    if atob_evals > 0:
        evidence.append("Base64 decoding directly into dynamic code execution (atob -> eval/Function)")
    if char_codes > 0:
        evidence.append(f"String.fromCharCode concatenation count: {char_codes}")
    if is_minified:
        evidence.append("Code exhibits typical production minification (not classified as malicious obfuscation)")

    return features, evidence
