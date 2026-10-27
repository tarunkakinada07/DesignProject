"""Database schema data models."""

import uuid
from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field


class SampleRecord(BaseModel):
    internal_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    extension_id: str
    version: str = ""
    manifest_version: int | None = None
    sha256: str | None = None
    source: str  # e.g., 'chrome-mal-ids', 'malicious_extension_sentry', 'MalCryptoExt', 'manual'
    source_record_id: str = ""
    collection_date: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).date().isoformat()
    )
    first_seen: str | None = None
    last_seen: str | None = None
    label: Literal["malicious", "benign", "suspicious", "unknown"]
    label_evidence: str = ""
    label_confidence: float = 1.0
    threat_family: str = "none"
    parse_status: Literal["parsed", "failed", "id_only", "unparsed"] = "unparsed"
    review_status: Literal["unreviewed", "verified", "disputed"] = "unreviewed"
    package_path: str | None = None
    normalized_source_hash: str | None = None
    near_dup_cluster_id: str | None = None
    category: str = "general"
    size_bytes: int = 0
    benign_verification_date: str | None = None
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


class ScanHistoryRecord(BaseModel):
    scan_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    sha256: str
    extension_id: str | None = None
    extension_name: str | None = None
    version: str | None = None
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    score: float | None = None
    risk_category: str
    matched_threat_intel: bool = False
    report_json: str
