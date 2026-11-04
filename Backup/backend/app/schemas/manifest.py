"""Normalized manifest schema supporting both Manifest V2 (MV2) and Manifest V3 (MV3)."""

from typing import Any

from pydantic import BaseModel, Field


class ContentScriptItem(BaseModel):
    matches: list[str] = Field(default_factory=list)
    js: list[str] = Field(default_factory=list)
    css: list[str] = Field(default_factory=list)
    run_at: str = Field(default="document_idle")
    all_frames: bool = Field(default=False)
    match_about_blank: bool = Field(default=False)


class WebAccessibleResource(BaseModel):
    resources: list[str] = Field(default_factory=list)
    matches: list[str] = Field(default_factory=list)
    extension_ids: list[str] = Field(default_factory=list)


class ExternallyConnectable(BaseModel):
    matches: list[str] = Field(default_factory=list)
    ids: list[str] = Field(default_factory=list)
    accepts_tls_channel_id: bool = Field(default=False)


class NormalizedManifest(BaseModel):
    name: str = Field(..., description="Extension display name")
    version: str = Field(..., description="Extension version string")
    manifest_version: int = Field(..., description="Manifest format version (2 or 3)")
    description: str = Field(default="", description="Extension description")

    # Permissions
    permissions: list[str] = Field(default_factory=list)
    optional_permissions: list[str] = Field(default_factory=list)
    host_permissions: list[str] = Field(default_factory=list)

    # Scripts & Workers
    background_type: str = Field(
        default="none",
        description="Type of background execution: 'service_worker', 'scripts', 'page', or 'none'",
    )
    background_service_worker: str | None = None
    background_scripts: list[str] = Field(default_factory=list)
    background_persistent: bool | None = None

    content_scripts: list[ContentScriptItem] = Field(default_factory=list)

    # Security Policies & Communication
    csp: str | dict[str, Any] | None = None
    csp_has_unsafe_eval: bool = False
    csp_has_remote_sources: bool = False

    web_accessible_resources: list[WebAccessibleResource] = Field(default_factory=list)
    externally_connectable: ExternallyConnectable | None = None
    update_url: str | None = None
    update_url_is_official_store: bool = False
    native_messaging_declared: bool = False

    # Raw representation for debugging/audit
    raw_keys: list[str] = Field(default_factory=list)
