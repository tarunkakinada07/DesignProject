"""Application configuration settings."""

from dataclasses import dataclass
from pathlib import Path


@dataclass
class Settings:
    APP_NAME: str = "Sentinel Extension Detector"
    APP_VERSION: str = "0.1.0"
    HOST: str = "127.0.0.1"
    PORT: int = 8000
    DEBUG: bool = True

    # Security Limits for Static Analysis
    MAX_UPLOAD_SIZE_BYTES: int = 25 * 1024 * 1024  # 25 MB
    MAX_EXPANDED_SIZE_BYTES: int = 50 * 1024 * 1024  # 50 MB
    MAX_FILE_COUNT: int = 500
    MAX_NESTING_DEPTH: int = 3
    MAX_SCRIPT_SIZE_BYTES: int = 5 * 1024 * 1024  # 5 MB per script
    EXTRACTION_TIMEOUT_SECONDS: float = 15.0

    # Paths
    BASE_DIR: Path = Path(__file__).resolve().parent.parent.parent.parent
    FRONTEND_DIR: Path = BASE_DIR / "frontend"
    DB_PATH: Path = BASE_DIR / "sentinel.db"


settings = Settings()
