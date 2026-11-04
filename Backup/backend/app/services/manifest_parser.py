"""Strict manifest parser for Chrome Extension Manifest V2 and Manifest V3.

Extracts, normalizes, and audits:
- permissions, optional_permissions, host_permissions
- content_scripts
- background scripts, service_worker, background page
- web_accessible_resources
- externally_connectable
- Content Security Policy (CSP) flags (unsafe-eval, remote sources)
- update_url (official Chrome Web Store vs external)
- native messaging declarations
"""

import json
import re
from pathlib import Path
from typing import Any

from backend.app.core.exceptions import (
    CorruptManifestError,
    InvalidManifestError,
    ManifestNotFoundError,
)
from backend.app.schemas.manifest import (
    ContentScriptItem,
    ExternallyConnectable,
    NormalizedManifest,
    WebAccessibleResource,
)

OFFICIAL_CWS_UPDATE_URL = "https://clients2.google.com/service/update2/crx"
HOST_PATTERN_REGEX = re.compile(
    r"^(\*|https?|ftp|file)://(\*|[\w\.\*\-]+)(:\d+)?(/.*)?$|^<all_urls>$",
    re.IGNORECASE,
)


def is_host_permission(item: str) -> bool:
    """Check if a permission string represents a host or URL match pattern."""
    if not isinstance(item, str):
        return False
    item = item.strip()
    return bool(HOST_PATTERN_REGEX.match(item)) or item.startswith(("*://", "http://", "https://", "<all_urls>"))


def parse_manifest_data(raw_data: str | bytes | dict[str, Any]) -> NormalizedManifest:
    """Parse and normalize manifest content from JSON string, bytes, or parsed dict."""
    if isinstance(raw_data, (bytes, bytearray)):
        try:
            raw_data = raw_data.decode("utf-8")
        except UnicodeDecodeError as e:
            try:
                raw_data = raw_data.decode("latin-1")
            except Exception as e2:
                raise CorruptManifestError(
                    f"Manifest encoding error: {e}",
                    safe_message="manifest.json has an unreadable character encoding.",
                ) from e2

    if isinstance(raw_data, str):
        try:
            data = json.loads(raw_data)
        except json.JSONDecodeError as e:
            raise CorruptManifestError(
                f"JSON syntax error in manifest.json: {e}",
                safe_message=f"manifest.json is invalid JSON: line {e.lineno}, col {e.colno}.",
            ) from e
    elif isinstance(raw_data, dict):
        data = raw_data
    else:
        raise InvalidManifestError("Manifest data must be JSON string, bytes, or dict.")

    if not isinstance(data, dict):
        raise InvalidManifestError(
            "Root of manifest.json must be a JSON object",
            safe_message="manifest.json root must be a JSON object.",
        )

    # Required top-level attributes
    manifest_version = data.get("manifest_version")
    if manifest_version not in (2, 3):
        raise InvalidManifestError(
            f"Invalid manifest_version: {manifest_version}. Only MV2 and MV3 are supported.",
            safe_message=f"Unsupported manifest_version: {manifest_version}. Only 2 and 3 are supported.",
        )

    name = str(data.get("name", "")).strip()
    if not name:
        name = "Unnamed Extension"

    version = str(data.get("version", "0.0.0")).strip()
    description = str(data.get("description", "")).strip()

    # Permissions normalization
    raw_perms = data.get("permissions") or []
    if not isinstance(raw_perms, list):
        raw_perms = []

    raw_opt_perms = data.get("optional_permissions") or []
    if not isinstance(raw_opt_perms, list):
        raw_opt_perms = []

    raw_host_perms = data.get("host_permissions") or []
    if not isinstance(raw_host_perms, list):
        raw_host_perms = []

    clean_perms: list[str] = []
    clean_host_perms: list[str] = [str(p).strip() for p in raw_host_perms if isinstance(p, str)]
    clean_opt_perms: list[str] = [str(p).strip() for p in raw_opt_perms if isinstance(p, str)]

    # In MV2, host permissions were mixed inside "permissions"
    for p in raw_perms:
        if isinstance(p, str):
            p_clean = p.strip()
            if is_host_permission(p_clean):
                if p_clean not in clean_host_perms:
                    clean_host_perms.append(p_clean)
            else:
                clean_perms.append(p_clean)

    # Background workers / scripts
    bg = data.get("background")
    bg_type = "none"
    bg_service_worker: str | None = None
    bg_scripts: list[str] = []
    bg_persistent: bool | None = None

    if isinstance(bg, dict):
        if "service_worker" in bg and isinstance(bg["service_worker"], str):
            bg_type = "service_worker"
            bg_service_worker = bg["service_worker"].strip()
        elif "scripts" in bg and isinstance(bg["scripts"], list):
            bg_type = "scripts"
            bg_scripts = [str(s).strip() for s in bg["scripts"] if isinstance(s, str)]
            bg_persistent = bool(bg.get("persistent", True))
        elif "page" in bg and isinstance(bg["page"], str):
            bg_type = "page"
            bg_scripts = [bg["page"].strip()]
            bg_persistent = bool(bg.get("persistent", True))

    # Content scripts
    normalized_content_scripts: list[ContentScriptItem] = []
    content_scripts_raw = data.get("content_scripts") or []
    if isinstance(content_scripts_raw, list):
        for cs in content_scripts_raw:
            if not isinstance(cs, dict):
                continue
            matches = [str(m).strip() for m in cs.get("matches", []) if isinstance(m, str)]
            js = [str(j).strip() for j in cs.get("js", []) if isinstance(j, str)]
            css = [str(c).strip() for c in cs.get("css", []) if isinstance(c, str)]
            run_at = str(cs.get("run_at", "document_idle")).strip()
            all_frames = bool(cs.get("all_frames", False))
            match_about_blank = bool(cs.get("match_about_blank", False))
            normalized_content_scripts.append(
                ContentScriptItem(
                    matches=matches,
                    js=js,
                    css=css,
                    run_at=run_at,
                    all_frames=all_frames,
                    match_about_blank=match_about_blank,
                )
            )

    # Content Security Policy (CSP)
    csp_raw = data.get("content_security_policy")
    csp_has_unsafe_eval = False
    csp_has_remote_sources = False

    def inspect_csp_string(csp_text: str):
        nonlocal csp_has_unsafe_eval, csp_has_remote_sources
        lowered = csp_text.lower()
        if "'unsafe-eval'" in lowered or "unsafe-eval" in lowered:
            csp_has_unsafe_eval = True
        # Check for remote sources in script-src or default-src
        if re.search(r"(?:script-src|default-src|worker-src)[^;]*\b(https?://|http://|\*)\b", lowered):
            csp_has_remote_sources = True

    if isinstance(csp_raw, str):
        inspect_csp_string(csp_raw)
    elif isinstance(csp_raw, dict):
        for val in csp_raw.values():
            if isinstance(val, str):
                inspect_csp_string(val)

    # Web Accessible Resources
    web_resources_raw = data.get("web_accessible_resources") or []
    normalized_web_resources: list[WebAccessibleResource] = []
    if isinstance(web_resources_raw, list):
        for item in web_resources_raw:
            if isinstance(item, str):
                normalized_web_resources.append(
                    WebAccessibleResource(resources=[item.strip()], matches=["<all_urls>"])
                )
            elif isinstance(item, dict):
                res = [str(r).strip() for r in item.get("resources", []) if isinstance(r, str)]
                matches = [str(m).strip() for m in item.get("matches", []) if isinstance(m, str)]
                ext_ids = [str(e).strip() for e in item.get("extension_ids", []) if isinstance(e, str)]
                normalized_web_resources.append(
                    WebAccessibleResource(resources=res, matches=matches, extension_ids=ext_ids)
                )

    # Externally Connectable
    ext_conn_raw = data.get("externally_connectable")
    normalized_ext_conn: ExternallyConnectable | None = None
    if isinstance(ext_conn_raw, dict):
        matches = [str(m).strip() for m in ext_conn_raw.get("matches", []) if isinstance(m, str)]
        ids = [str(i).strip() for i in ext_conn_raw.get("ids", []) if isinstance(i, str)]
        accepts_tls = bool(ext_conn_raw.get("accepts_tls_channel_id", False))
        normalized_ext_conn = ExternallyConnectable(
            matches=matches, ids=ids, accepts_tls_channel_id=accepts_tls
        )

    # Update URL
    update_url = data.get("update_url")
    update_url_str = str(update_url).strip() if update_url else None
    update_url_is_cws = False
    if update_url_str:
        update_url_is_cws = update_url_str.lower().startswith(OFFICIAL_CWS_UPDATE_URL.lower())

    # Native messaging
    has_native_messaging = "nativeMessaging" in clean_perms or "nativeMessaging" in clean_opt_perms

    return NormalizedManifest(
        name=name,
        version=version,
        manifest_version=manifest_version,
        description=description,
        permissions=clean_perms,
        optional_permissions=clean_opt_perms,
        host_permissions=clean_host_perms,
        background_type=bg_type,
        background_service_worker=bg_service_worker,
        background_scripts=bg_scripts,
        background_persistent=bg_persistent,
        content_scripts=normalized_content_scripts,
        csp=csp_raw,
        csp_has_unsafe_eval=csp_has_unsafe_eval,
        csp_has_remote_sources=csp_has_remote_sources,
        web_accessible_resources=normalized_web_resources,
        externally_connectable=normalized_ext_conn,
        update_url=update_url_str,
        update_url_is_official_store=update_url_is_cws,
        native_messaging_declared=has_native_messaging,
        raw_keys=list(data.keys()),
    )


def parse_manifest_file(root_dir: Path) -> NormalizedManifest:
    """Find and parse manifest.json inside the extracted extension root directory.

    Raises:
    - ManifestNotFoundError if manifest.json does not exist.
    - CorruptManifestError if manifest.json is invalid JSON.
    - InvalidManifestError if schema is invalid.
    """
    manifest_path = root_dir / "manifest.json"
    if not manifest_path.is_file():
        raise ManifestNotFoundError(
            f"No manifest.json located at root {root_dir}",
            safe_message="Extension package does not contain a root manifest.json file.",
        )

    try:
        content = manifest_path.read_bytes()
    except OSError as e:
        raise ManifestNotFoundError(
            f"Failed to read manifest.json: {e}",
            safe_message="Failed to read manifest.json file.",
        ) from e

    return parse_manifest_data(content)
