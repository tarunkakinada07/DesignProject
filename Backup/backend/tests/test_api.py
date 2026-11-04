"""Integration tests for FastAPI endpoints, full inference scanning, history, and dashboard."""

import io
import struct
import zipfile

from fastapi.testclient import TestClient

from backend.app.database.connection import get_db_connection
from backend.app.main import app
from backend.app.services.safe_extractor import CRX_MAGIC

client = TestClient(app)


def build_test_zip(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buf.getvalue()


def test_health_endpoint():
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "version" in data
    assert "python_version" in data
    assert isinstance(data["model_loaded"], bool)


def test_security_headers_middleware():
    response = client.get("/api/health")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "default-src" in response.headers["Content-Security-Policy"]


def test_upload_valid_extension_full_inference():
    zip_bytes = build_test_zip({
        "manifest.json": '{"manifest_version": 3, "name": "API Full Test Ext", "version": "1.0.0", "permissions": ["storage"]}',
        "background.js": "console.log('started');",
    })

    response = client.post(
        "/api/scan/upload",
        files={"file": ("test_ext.zip", zip_bytes, "application/zip")},
    )

    assert response.status_code == 200
    data = response.json()
    assert "scan_id" in data
    assert data["format"] == "zip"
    assert data["manifest"]["name"] == "API Full Test Ext"
    assert data["manifest"]["manifest_version"] == 3
    assert data["extraction_summary"]["file_count"] == 2
    assert "risk_verdict" in data
    assert "risk_score" in data
    assert "prevalence_warning" in data
    assert "limitations_disclaimer" in data


def test_upload_threat_intel_ioc_match():
    # Insert a known malicious sample into the test database
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT OR REPLACE INTO samples (
                internal_id, extension_id, source, collection_date, label,
                label_evidence, threat_family, parse_status, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "ioc_test_sample",
                "known_malicious_ext_id",
                "chrome-mal-ids",
                "2026-10-18",
                "malicious",
                "Confirmed credential stealer C2",
                "StealerFamilyA",
                "id_only",
                "2026-10-18T00:00:00",
            ),
        )

    zip_bytes = build_test_zip({
        "manifest.json": '{"manifest_version": 3, "name": "known_malicious_ext_id", "version": "1.0.0"}',
        "background.js": "console.log('malware active');",
    })

    response = client.post(
        "/api/scan/upload",
        files={"file": ("ioc_match.zip", zip_bytes, "application/zip")},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["risk_verdict"] == "KNOWN_MALICIOUS_IOC"
    assert data["matched_threat_intel"] is True
    assert data["risk_score"] == 1.0
    assert data["threat_intel_details"]["threat_family"] == "StealerFamilyA"


def test_upload_zip_slip_rejected():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../traversal.js", "evil")
        zf.writestr("manifest.json", '{"manifest_version": 3, "name": "Evil", "version": "1.0"}')

    evil_zip = buf.getvalue()

    response = client.post(
        "/api/scan/upload",
        files={"file": ("evil.zip", evil_zip, "application/zip")},
    )

    assert response.status_code == 400
    detail = response.json()["detail"]
    assert "Path traversal detected" in detail
    assert "C:\\" not in detail
    assert "sentinel_safe_" not in detail


def test_upload_corrupt_crx_rejected():
    corrupt_crx = CRX_MAGIC + struct.pack("<I", 3) + struct.pack("<I", 0xFFFFFFFF)

    response = client.post(
        "/api/scan/upload",
        files={"file": ("corrupt.crx", corrupt_crx, "application/x-chrome-extension")},
    )

    assert response.status_code == 400
    assert "Malformed CRX3 package" in response.json()["detail"]


def test_upload_corrupt_manifest_rejected():
    zip_bytes = build_test_zip({
        "manifest.json": "{ broken syntax json",
    })

    response = client.post(
        "/api/scan/upload",
        files={"file": ("bad_manifest.zip", zip_bytes, "application/zip")},
    )

    assert response.status_code == 400
    assert "manifest.json is invalid JSON" in response.json()["detail"]


def test_overview_endpoint():
    response = client.get("/api/overview")
    assert response.status_code == 200
    data = response.json()
    assert "total_samples" in data
    assert "malicious_samples" in data
    assert "benign_samples" in data
    assert "total_scans" in data


def test_scan_history_and_deletion():
    # Execute a scan first
    zip_bytes = build_test_zip({
        "manifest.json": '{"manifest_version": 3, "name": "History Test Ext", "version": "2.1.0"}',
        "content.js": "console.log('history test');",
    })

    scan_res = client.post(
        "/api/scan/upload",
        files={"file": ("history_test.zip", zip_bytes, "application/zip")},
    )
    assert scan_res.status_code == 200
    scan_id = scan_res.json()["scan_id"]

    # Verify present in /api/history
    hist_res = client.get("/api/history")
    assert hist_res.status_code == 200
    records = hist_res.json()
    assert any(r["scan_id"] == scan_id for r in records)

    # Search filter
    search_res = client.get("/api/history?search=History%20Test%20Ext")
    assert search_res.status_code == 200
    assert any(r["scan_id"] == scan_id for r in search_res.json())

    # Get specific detail
    detail_res = client.get(f"/api/history/{scan_id}")
    assert detail_res.status_code == 200
    assert detail_res.json()["scan_id"] == scan_id

    # Delete record
    del_res = client.delete(f"/api/history/{scan_id}")
    assert del_res.status_code == 200

    # Ensure 404 after deletion
    after_del = client.get(f"/api/history/{scan_id}")
    assert after_del.status_code == 404


def test_evaluation_endpoint():
    response = client.get("/api/evaluation")
    assert response.status_code == 200
    data = response.json()
    assert "metrics" in data
    assert "bootstrap" in data
    assert "ablation_study" in data
    assert "obfuscation_robustness" in data
    assert "error_analysis" in data


def test_frontend_index_serving():
    response = client.get("/")
    assert response.status_code == 200
    assert "Sentinel Extension" in response.text
    assert "Overview" in response.text
    assert "Extension Scanner" in response.text


def test_download_pdf_report_endpoint():
    response = client.get("/api/docs/download-pdf")
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pdf"
    assert len(response.content) > 1000
    assert response.content.startswith(b"%PDF")
