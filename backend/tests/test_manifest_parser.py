"""Comprehensive tests for strict manifest parsing (MV2 & MV3).

Covers:
- MV2 and MV3 normalization
- Host permission separation
- Background script vs service worker extraction
- CSP unsafe-eval and remote sources inspection
- Corrupt JSON and missing manifest error handling
- Unsupported manifest versions
- Official vs external update URL checking
"""

from pathlib import Path

import pytest

from backend.app.core.exceptions import (
    CorruptManifestError,
    InvalidManifestError,
    ManifestNotFoundError,
)
from backend.app.services.manifest_parser import (
    parse_manifest_data,
    parse_manifest_file,
)


def test_valid_mv2_manifest():
    mv2_raw = {
        "manifest_version": 2,
        "name": "Ad Blocker Pro",
        "version": "1.4.2",
        "description": "Blocks annoying advertisements",
        "permissions": [
            "webRequest",
            "webRequestBlocking",
            "storage",
            "http://*/*",
            "https://*/*",
        ],
        "background": {
            "scripts": ["js/background.js", "js/rules.js"],
            "persistent": True,
        },
        "content_scripts": [
            {
                "matches": ["*://*.youtube.com/*"],
                "js": ["content.js"],
                "run_at": "document_start",
            }
        ],
        "content_security_policy": "script-src 'self' 'unsafe-eval'; object-src 'self'",
        "update_url": "https://clients2.google.com/service/update2/crx",
    }

    manifest = parse_manifest_data(mv2_raw)
    assert manifest.manifest_version == 2
    assert manifest.name == "Ad Blocker Pro"
    assert manifest.version == "1.4.2"

    # Verify separation of host permissions from API permissions
    assert "webRequest" in manifest.permissions
    assert "webRequestBlocking" in manifest.permissions
    assert "storage" in manifest.permissions
    assert "http://*/*" in manifest.host_permissions
    assert "https://*/*" in manifest.host_permissions

    # Background
    assert manifest.background_type == "scripts"
    assert manifest.background_scripts == ["js/background.js", "js/rules.js"]
    assert manifest.background_persistent is True

    # Content scripts
    assert len(manifest.content_scripts) == 1
    assert manifest.content_scripts[0].matches == ["*://*.youtube.com/*"]
    assert manifest.content_scripts[0].run_at == "document_start"

    # CSP and Update URL
    assert manifest.csp_has_unsafe_eval is True
    assert manifest.update_url_is_official_store is True


def test_valid_mv3_manifest():
    mv3_raw = {
        "manifest_version": 3,
        "name": "Secure Crypto Helper",
        "version": "3.0.0",
        "permissions": ["declarativeNetRequest", "cookies", "nativeMessaging"],
        "host_permissions": ["<all_urls>"],
        "background": {
            "service_worker": "worker.js",
        },
        "content_security_policy": {
            "extension_pages": "script-src 'self'; object-src 'self'",
            "sandbox": "sandbox allow-scripts; script-src https://cdn.example.com",
        },
        "update_url": "https://external-domain.com/updates.xml",
    }

    manifest = parse_manifest_data(mv3_raw)
    assert manifest.manifest_version == 3
    assert manifest.background_type == "service_worker"
    assert manifest.background_service_worker == "worker.js"
    assert manifest.host_permissions == ["<all_urls>"]
    assert manifest.native_messaging_declared is True
    assert manifest.csp_has_unsafe_eval is False
    assert manifest.csp_has_remote_sources is True
    assert manifest.update_url_is_official_store is False


def test_missing_manifest(tmp_path: Path):
    with pytest.raises(ManifestNotFoundError):
        parse_manifest_file(tmp_path)


def test_corrupt_manifest_json(tmp_path: Path):
    bad_file = tmp_path / "manifest.json"
    bad_file.write_text("{ unquoted_key: 'broken json' ", encoding="utf-8")

    with pytest.raises(CorruptManifestError):
        parse_manifest_file(tmp_path)


def test_invalid_manifest_version():
    with pytest.raises(InvalidManifestError):
        parse_manifest_data({"manifest_version": 1, "name": "Ancient Ext"})

    with pytest.raises(InvalidManifestError):
        parse_manifest_data({"manifest_version": 4, "name": "Future Ext"})


def test_csp_unsafe_eval_detection():
    # Detects inside string
    m1 = parse_manifest_data({
        "manifest_version": 2,
        "name": "T1",
        "content_security_policy": "script-src 'self' 'unsafe-eval'",
    })
    assert m1.csp_has_unsafe_eval is True

    # Safe CSP
    m2 = parse_manifest_data({
        "manifest_version": 3,
        "name": "T2",
        "content_security_policy": {"extension_pages": "script-src 'self'"},
    })
    assert m2.csp_has_unsafe_eval is False
