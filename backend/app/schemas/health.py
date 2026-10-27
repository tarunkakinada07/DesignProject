"""Health check schema."""

from datetime import datetime, timezone

from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    status: str = Field(default="healthy", description="Application operational status")
    app_name: str = Field(..., description="Application name")
    version: str = Field(..., description="Application version")
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="Current server UTC timestamp",
    )
    python_version: str = Field(..., description="Runtime Python version")
    model_loaded: bool = Field(default=False, description="Whether an ML model is active")
