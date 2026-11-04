"""Schemas for scanning requests, file metadata, extraction results, and full scan assessments."""

from typing import Any

from pydantic import BaseModel, Field

from backend.app.schemas.manifest import NormalizedManifest


class ExtractedFileInfo(BaseModel):
    rel_path: str = Field(..., description="Sanitized relative path within extension")
    size_bytes: int = Field(..., description="File size in bytes")
    is_javascript: bool = Field(default=False, description="Whether the file is a JavaScript file")
    is_html: bool = Field(default=False, description="Whether the file is an HTML file")


class ExtractionSummary(BaseModel):
    sha256: str = Field(..., description="Package SHA-256 digest")
    format: str = Field(..., description="Detected package format ('crx3', 'crx2', 'zip', 'dir')")
    file_count: int = Field(..., description="Total extracted file count")
    total_bytes: int = Field(..., description="Total uncompressed size in bytes")
    js_file_count: int = Field(..., description="Number of JavaScript files")
    files: list[ExtractedFileInfo] = Field(default_factory=list)


class RiskFactor(BaseModel):
    feature_name: str
    feature_value: float
    shap_value: float
    direction: str  # "increases_risk" or "reduces_risk"
    description: str


class ScanResultResponse(BaseModel):
    scan_id: str
    sha256: str
    format: str
    manifest: NormalizedManifest
    extraction_summary: ExtractionSummary
    risk_verdict: str  # KNOWN_MALICIOUS_IOC, HIGH_RISK, SUSPICIOUS_UNCERTAIN, LOW_RISK, ANALYSIS_INCOMPLETE
    risk_verdict_label: str
    risk_score: float
    alert_threshold: float
    matched_threat_intel: bool
    threat_intel_details: dict[str, Any] | None = None
    top_risk_factors: list[RiskFactor] = Field(default_factory=list)
    protective_factors: list[RiskFactor] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    prevalence_warning: str
    limitations_disclaimer: str
    scanned_at: str


class ScanHistorySummary(BaseModel):
    scan_id: str
    sha256: str
    extension_id: str | None = None
    extension_name: str | None = None
    version: str | None = None
    timestamp: str
    score: float | None = None
    risk_category: str
    matched_threat_intel: bool


class OverviewStatsResponse(BaseModel):
    total_samples: int
    malicious_samples: int
    benign_samples: int
    suspicious_samples: int
    total_scans: int
    active_model: dict[str, Any] | None = None
