"""Dataset importers with strict provenance tracking.

Imports from:
1. chrome-mal-ids: Privacy Commons Institute malicious extension IOC metadata.
2. malicious_extension_sentry: Threat intelligence ID feeds.
3. MalCryptoExt: Cryptocurrency malicious extension dataset records.
4. Manually supplied archives / packages: Local CRX/ZIP files.
"""

import csv
import hashlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen

from backend.app.database.connection import get_db_connection
from backend.app.database.models import SampleRecord
from backend.app.services.manifest_parser import parse_manifest_file
from backend.app.services.safe_extractor import safe_extract_extension

TPCI_URL = "https://raw.githubusercontent.com/The-Privacy-Commons-Institute/chrome-mal-ids/master/data/current-list-meta.csv"
SENTRY_URL = "https://raw.githubusercontent.com/toborrm9/malicious_extension_sentry/main/extensions.json"


def insert_sample_record(conn, sample: SampleRecord) -> bool:
    """Insert or update sample record in SQLite database.

    Returns True if inserted/updated, False if skipped.
    """
    cursor = conn.cursor()
    # Check if this exact record (extension_id, version, source) already exists
    cursor.execute(
        """
        SELECT internal_id, label, parse_status FROM samples
        WHERE extension_id = ? AND version = ? AND source = ?
        """,
        (sample.extension_id, sample.version, sample.source),
    )
    existing = cursor.fetchone()

    if existing:
        # Update existing record if new information is provided
        cursor.execute(
            """
            UPDATE samples SET
                sha256 = COALESCE(?, sha256),
                manifest_version = COALESCE(?, manifest_version),
                parse_status = CASE WHEN ? != 'unparsed' THEN ? ELSE parse_status END,
                package_path = COALESCE(?, package_path),
                size_bytes = CASE WHEN ? > 0 THEN ? ELSE size_bytes END,
                normalized_source_hash = COALESCE(?, normalized_source_hash)
            WHERE internal_id = ?
            """,
            (
                sample.sha256,
                sample.manifest_version,
                sample.parse_status,
                sample.parse_status,
                sample.package_path,
                sample.size_bytes,
                sample.size_bytes,
                sample.normalized_source_hash,
                existing["internal_id"],
            ),
        )
        return False

    cursor.execute(
        """
        INSERT INTO samples (
            internal_id, extension_id, version, manifest_version, sha256,
            source, source_record_id, collection_date, first_seen, last_seen,
            label, label_evidence, label_confidence, threat_family, parse_status,
            review_status, package_path, normalized_source_hash, near_dup_cluster_id,
            category, size_bytes, benign_verification_date, created_at
        ) VALUES (
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
        )
        """,
        (
            sample.internal_id,
            sample.extension_id,
            sample.version,
            sample.manifest_version,
            sample.sha256,
            sample.source,
            sample.source_record_id,
            sample.collection_date,
            sample.first_seen,
            sample.last_seen,
            sample.label,
            sample.label_evidence,
            sample.label_confidence,
            sample.threat_family,
            sample.parse_status,
            sample.review_status,
            sample.package_path,
            sample.normalized_source_hash,
            sample.near_dup_cluster_id or sample.extension_id,
            sample.category,
            sample.size_bytes,
            sample.benign_verification_date,
            sample.created_at,
        ),
    )
    return True


def import_chrome_mal_ids(csv_content: str | Path | None = None) -> tuple[int, int]:
    """Import chrome-mal-ids malicious extension metadata.

    If csv_content is None, attempts to download the latest feed, falling back gracefully.
    Returns (inserted_count, total_processed).
    """
    raw_text = ""
    if isinstance(csv_content, Path) and csv_content.is_file():
        raw_text = csv_content.read_text(encoding="utf-8-sig")
    elif isinstance(csv_content, str):
        raw_text = csv_content
    else:
        # Attempt network fetch
        try:
            req = Request(TPCI_URL, headers={"User-Agent": "SentinelExtension/1.0"})
            with urlopen(req, timeout=10) as resp:
                raw_text = resp.read().decode("utf-8-sig", errors="ignore")
        except Exception as e:
            # Fallback to local or empty
            print(f"Notice: Network fetch of chrome-mal-ids skipped ({e}). Using local fallback if provided.")
            return 0, 0

    if not raw_text:
        return 0, 0

    reader = csv.DictReader(raw_text.splitlines())
    inserted = 0
    total = 0
    now_date = datetime.now(timezone.utc).date().isoformat()

    with get_db_connection() as conn:
        for row in reader:
            ext_id = (row.get("EXTID") or row.get("extension_id") or "").strip().lower()
            if not ext_id or len(ext_id) != 32:
                continue

            total += 1
            name = (row.get("EXTID-NAME") or row.get("name") or "").strip()
            source_ref = (row.get("SOURCE") or row.get("ARTICLE") or "TPCI database").strip()
            threat = (row.get("THREAT-TYPE") or row.get("threat_family") or "malicious").strip()

            sample = SampleRecord(
                extension_id=ext_id,
                version="",
                source="chrome-mal-ids",
                source_record_id=ext_id,
                collection_date=now_date,
                label="malicious",
                label_evidence=f"TPCI malicious report: {name} (source: {source_ref})",
                label_confidence=0.95,
                threat_family=threat,
                parse_status="id_only",  # Threat intel ID only (not a downloadable package)
                category="general",
            )
            if insert_sample_record(conn, sample):
                inserted += 1

    return inserted, total


def import_sentry_ioc_records(json_content: str | Path | None = None) -> tuple[int, int]:
    """Import malicious_extension_sentry IOC repository records.

    These are ID-only records (NOT downloadable packages), maintained as threat intelligence.
    Returns (inserted_count, total_processed).
    """
    raw_data: Any = None
    if isinstance(json_content, Path) and json_content.is_file():
        raw_data = json.loads(json_content.read_text(encoding="utf-8"))
    elif isinstance(json_content, str):
        raw_data = json.loads(json_content)
    else:
        try:
            req = Request(SENTRY_URL, headers={"User-Agent": "SentinelExtension/1.0"})
            with urlopen(req, timeout=10) as resp:
                raw_data = json.loads(resp.read().decode("utf-8"))
        except Exception as e:
            print(f"Notice: Network fetch of sentry IOCs skipped ({e}). Using local fallback if provided.")
            return 0, 0

    if not raw_data:
        return 0, 0

    inserted = 0
    total = 0
    now_date = datetime.now(timezone.utc).date().isoformat()

    items = raw_data if isinstance(raw_data, list) else raw_data.get("extensions", [])

    with get_db_connection() as conn:
        for item in items:
            if isinstance(item, str):
                ext_id = item.strip().lower()
                evidence = "Sentry IOC aggregation list"
                family = "threat_intel"
            elif isinstance(item, dict):
                ext_id = (item.get("id") or item.get("extension_id") or "").strip().lower()
                evidence = item.get("reason", "Sentry IOC report")
                family = item.get("family", "threat_intel")
            else:
                continue

            if not ext_id or len(ext_id) != 32:
                continue

            total += 1
            sample = SampleRecord(
                extension_id=ext_id,
                source="malicious_extension_sentry",
                source_record_id=ext_id,
                collection_date=now_date,
                label="malicious",
                label_evidence=evidence,
                label_confidence=0.90,
                threat_family=family,
                parse_status="id_only",
            )
            if insert_sample_record(conn, sample):
                inserted += 1

    return inserted, total


def import_local_package(
    package_path: Path,
    label: str,
    source: str = "manual_archive",
    threat_family: str = "none",
    category: str = "general",
    label_evidence: str = "Local verified archive",
    benign_verification_date: str | None = None,
) -> SampleRecord | None:
    """Safely import a locally supplied .crx or .zip package with hash, manifest parse, and provenance."""
    if not package_path.is_file():
        return None

    raw_bytes = package_path.read_bytes()
    sha256 = hashlib.sha256(raw_bytes).hexdigest()

    try:
        with safe_extract_extension(raw_bytes) as (temp_dir, summary):
            manifest = parse_manifest_file(temp_dir)
            ext_name = manifest.name
            ext_ver = manifest.version
            mv = manifest.manifest_version

            # Compute normalized source hash across JavaScript and manifest files
            hasher = hashlib.sha256()
            for f in sorted(summary.files, key=lambda x: x.rel_path):
                if f.is_javascript or f.rel_path == "manifest.json":
                    file_p = temp_dir / f.rel_path
                    if file_p.is_file():
                        # Normalize whitespace and newlines for stable source hash
                        text = file_p.read_text(encoding="utf-8", errors="ignore")
                        normalized = "".join(text.split())
                        hasher.update(normalized.encode("utf-8"))
            norm_hash = hasher.hexdigest()

            sample = SampleRecord(
                extension_id=package_path.stem[:32].lower() if len(package_path.stem) >= 32 else str(uuid.uuid4())[:32],
                version=ext_ver,
                manifest_version=mv,
                sha256=sha256,
                source=source,
                source_record_id=package_path.name,
                label=label,  # type: ignore
                label_evidence=f"{label_evidence} ({ext_name})",
                label_confidence=1.0 if label in ("malicious", "benign") else 0.8,
                threat_family=threat_family,
                parse_status="parsed",
                review_status="verified",
                package_path=str(package_path.resolve()),
                normalized_source_hash=norm_hash,
                category=category,
                size_bytes=len(raw_bytes),
                benign_verification_date=benign_verification_date or (datetime.now(timezone.utc).date().isoformat() if label == "benign" else None),
            )

            with get_db_connection() as conn:
                insert_sample_record(conn, sample)
            return sample

    except Exception as e:
        # Record failed parse attempt with failure provenance
        sample = SampleRecord(
            extension_id=package_path.stem[:32].lower() if len(package_path.stem) >= 32 else str(uuid.uuid4())[:32],
            sha256=sha256,
            source=source,
            source_record_id=package_path.name,
            label=label,  # type: ignore
            label_evidence=f"Failed parse attempt: {e}",
            label_confidence=0.5,
            parse_status="failed",
            package_path=str(package_path.resolve()),
            size_bytes=len(raw_bytes),
        )
        with get_db_connection() as conn:
            insert_sample_record(conn, sample)
        return sample
