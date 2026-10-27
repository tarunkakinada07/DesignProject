"""API route definitions for health, full scanning, history, overview, and evaluation."""

import json
import sys
from typing import Any

from fastapi import APIRouter, File, HTTPException, Query, UploadFile, status

from backend.app.core.config import settings
from backend.app.core.exceptions import SentinelError
from backend.app.database.connection import get_db_connection
from backend.app.schemas.health import HealthResponse
from backend.app.schemas.scan import (
    OverviewStatsResponse,
    ScanHistorySummary,
    ScanResultResponse,
)
from backend.app.services.inference_service import run_full_inference
from backend.app.services.manifest_parser import parse_manifest_file
from backend.app.services.safe_extractor import safe_extract_extension
from ml.training.model_registry import get_active_model

router = APIRouter()
EVALUATION_REPORT_PATH = settings.BASE_DIR / "ml" / "artifacts" / "evaluation_report.json"


@router.get("/health", response_model=HealthResponse, tags=["System"])
def get_health() -> HealthResponse:
    """Return application operational status, model registration state, and runtime details."""
    model, _ = get_active_model()
    return HealthResponse(
        status="healthy",
        app_name=settings.APP_NAME,
        version=settings.APP_VERSION,
        python_version=sys.version.split()[0],
        model_loaded=model is not None,
    )


@router.post("/scan/upload", response_model=ScanResultResponse, tags=["Scanner"])
async def upload_and_scan_extension(file: UploadFile = File(...)) -> ScanResultResponse:
    """Safely upload, extract, parse, extract features, score with ML model, and persist scan report."""
    if not file.filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Filename missing from upload.",
        )

    content = await file.read()
    if len(content) == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded package is empty.",
        )

    if len(content) > settings.MAX_UPLOAD_SIZE_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Uploaded file exceeds maximum allowed size of {settings.MAX_UPLOAD_SIZE_BYTES // (1024 * 1024)} MB.",
        )

    try:
        with safe_extract_extension(content) as (temp_dir, summary):
            manifest = parse_manifest_file(temp_dir)
            result = run_full_inference(
                temp_dir=temp_dir,
                sha256=summary.sha256,
                format_str=summary.format,
                manifest=manifest,
                summary=summary,
            )
            return result
    except SentinelError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=e.safe_message,
        ) from e
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred while inspecting the extension package: {str(e)}",
        ) from e


@router.get("/overview", response_model=OverviewStatsResponse, tags=["Dashboard"])
def get_overview_stats() -> OverviewStatsResponse:
    """Return live database dataset counts, total scans performed, and active detector metadata."""
    total_samples = 0
    malicious = 0
    benign = 0
    suspicious = 0
    total_scans = 0

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT label, COUNT(*) as cnt FROM samples GROUP BY label")
        for row in cursor.fetchall():
            lbl = row["label"]
            cnt = row["cnt"]
            total_samples += cnt
            if lbl == "malicious":
                malicious = cnt
            elif lbl == "benign":
                benign = cnt
            elif lbl == "suspicious":
                suspicious = cnt

        cursor.execute("SELECT COUNT(*) as cnt FROM scan_history")
        row = cursor.fetchone()
        if row:
            total_scans = row["cnt"]

    _, model_card = get_active_model()

    return OverviewStatsResponse(
        total_samples=total_samples,
        malicious_samples=malicious,
        benign_samples=benign,
        suspicious_samples=suspicious,
        total_scans=total_scans,
        active_model=model_card,
    )


@router.get("/history", response_model=list[ScanHistorySummary], tags=["History"])
def get_scan_history(
    search: str = Query("", description="Filter by SHA-256 or extension name/ID"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> list[ScanHistorySummary]:
    """Retrieve audit history of previously inspected extensions."""
    records: list[ScanHistorySummary] = []
    with get_db_connection() as conn:
        cursor = conn.cursor()
        if search.strip():
            term = f"%{search.strip()}%"
            cursor.execute(
                """
                SELECT scan_id, sha256, extension_id, extension_name, version, timestamp, score, risk_category, matched_threat_intel
                FROM scan_history
                WHERE sha256 LIKE ? OR extension_id LIKE ? OR extension_name LIKE ?
                ORDER BY timestamp DESC
                LIMIT ? OFFSET ?
                """,
                (term, term, term, limit, offset),
            )
        else:
            cursor.execute(
                """
                SELECT scan_id, sha256, extension_id, extension_name, version, timestamp, score, risk_category, matched_threat_intel
                FROM scan_history
                ORDER BY timestamp DESC
                LIMIT ? OFFSET ?
                """,
                (limit, offset),
            )

        for row in cursor.fetchall():
            records.append(
                ScanHistorySummary(
                    scan_id=row["scan_id"],
                    sha256=row["sha256"],
                    extension_id=row["extension_id"],
                    extension_name=row["extension_name"],
                    version=row["version"],
                    timestamp=row["timestamp"],
                    score=row["score"],
                    risk_category=row["risk_category"],
                    matched_threat_intel=bool(row["matched_threat_intel"]),
                )
            )

    return records


@router.get("/history/{scan_id}", response_model=dict[str, Any], tags=["History"])
def get_scan_record_detail(scan_id: str) -> dict[str, Any]:
    """Retrieve the full JSON audit report for a specific scan."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT report_json FROM scan_history WHERE scan_id = ?", (scan_id,))
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Scan record not found.")
        try:
            return json.loads(row["report_json"])
        except Exception as e:
            raise HTTPException(status_code=500, detail="Corrupted scan report JSON in database.") from e


@router.delete("/history/{scan_id}", tags=["History"])
def delete_scan_record(scan_id: str) -> dict[str, str]:
    """Delete a scan record from audit history."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM scan_history WHERE scan_id = ?", (scan_id,))
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Scan record not found.")
    return {"status": "deleted", "scan_id": scan_id}


@router.get("/evaluation", tags=["Evaluation"])
def get_evaluation_report() -> dict[str, Any]:
    """Return the latest honest model evaluation report, bootstrap intervals, ablation, and robustness metrics."""
    if not EVALUATION_REPORT_PATH.is_file():
        raise HTTPException(
            status_code=404,
            detail="Evaluation report not found. Run `python scripts/evaluate_models.py` first.",
        )
    try:
        return json.loads(EVALUATION_REPORT_PATH.read_text(encoding="utf-8"))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read evaluation report: {str(e)}") from e


PDF_REPORT_PATH = settings.BASE_DIR / "docs" / "Sentinel_Extension_Project_Documentation_Report.pdf"


@router.get("/docs/download-pdf", tags=["Documentation"])
def download_project_report_pdf():
    """Download the official publication-grade project documentation PDF report."""
    from fastapi.responses import FileResponse
    if not PDF_REPORT_PATH.is_file():
        from scripts.generate_project_report_pdf import build_pdf
        PDF_REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
        build_pdf(PDF_REPORT_PATH)
    return FileResponse(
        str(PDF_REPORT_PATH),
        media_type="application/pdf",
        filename="Sentinel_Extension_Project_Documentation_Report.pdf",
    )
