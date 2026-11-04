"""SQLite database connection and session management."""

import sqlite3
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path

from backend.app.core.config import settings

DB_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS samples (
    internal_id TEXT PRIMARY KEY,
    extension_id TEXT NOT NULL,
    version TEXT DEFAULT '',
    manifest_version INTEGER,
    sha256 TEXT,
    source TEXT NOT NULL,
    source_record_id TEXT DEFAULT '',
    collection_date TEXT NOT NULL,
    first_seen TEXT,
    last_seen TEXT,
    label TEXT NOT NULL CHECK(label IN ('malicious', 'benign', 'suspicious', 'unknown')),
    label_evidence TEXT DEFAULT '',
    label_confidence REAL DEFAULT 1.0,
    threat_family TEXT DEFAULT 'none',
    parse_status TEXT NOT NULL CHECK(parse_status IN ('parsed', 'failed', 'id_only', 'unparsed')),
    review_status TEXT NOT NULL DEFAULT 'unreviewed' CHECK(review_status IN ('unreviewed', 'verified', 'disputed')),
    package_path TEXT,
    normalized_source_hash TEXT,
    near_dup_cluster_id TEXT,
    category TEXT DEFAULT 'general',
    size_bytes INTEGER DEFAULT 0,
    benign_verification_date TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_samples_extension_id ON samples(extension_id);
CREATE INDEX IF NOT EXISTS idx_samples_sha256 ON samples(sha256);
CREATE INDEX IF NOT EXISTS idx_samples_label ON samples(label);
CREATE INDEX IF NOT EXISTS idx_samples_source ON samples(source);
CREATE INDEX IF NOT EXISTS idx_samples_cluster ON samples(near_dup_cluster_id);
CREATE INDEX IF NOT EXISTS idx_samples_parse_status ON samples(parse_status);

CREATE TABLE IF NOT EXISTS scan_history (
    scan_id TEXT PRIMARY KEY,
    sha256 TEXT NOT NULL,
    extension_id TEXT,
    extension_name TEXT,
    version TEXT,
    timestamp TEXT NOT NULL,
    score REAL,
    risk_category TEXT NOT NULL,
    matched_threat_intel INTEGER DEFAULT 0,
    report_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_scan_history_sha256 ON scan_history(sha256);
"""


def init_db(db_path: Path | None = None) -> Path:
    """Initialize SQLite database with full schema and indexes."""
    path = db_path or settings.DB_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as conn:
        conn.executescript(DB_SCHEMA_SQL)
        conn.commit()
    return path


@contextmanager
def get_db_connection(db_path: Path | None = None) -> Generator[sqlite3.Connection, None, None]:
    """Context manager yielding SQLite connection with dict/row access."""
    path = db_path or settings.DB_PATH
    if not path.is_file():
        init_db(path)
    conn = sqlite3.connect(path, timeout=10.0)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
