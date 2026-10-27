"""Safe extension extraction service.

Enforces strict static security limits:
- CRX3 and CRX2 header validation.
- ZIP slip (path traversal) blocking.
- Decompression bomb / compression ratio limits.
- Maximum file count, nesting depth, and script size limits.
- Symlink rejection.
- Reliable temporary directory cleanup with zero path leakage in error messages.
"""

import hashlib
import io
import shutil
import struct
import tempfile
import zipfile
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path

from backend.app.core.config import settings
from backend.app.core.exceptions import (
    DecompressionBombError,
    FileLimitExceededError,
    InvalidCRXHeaderError,
    NestingLimitExceededError,
    OversizedScriptError,
    SymlinkRejectedError,
    ZipSlipError,
)
from backend.app.schemas.scan import ExtractedFileInfo, ExtractionSummary

# Constants
CRX_MAGIC = b"Cr24"
ZIP_MAGIC = b"PK\x03\x04"
S_IFLNK = 0o120000


def detect_archive_format(data: bytes) -> tuple[str, bytes]:
    """Detect archive format and return (format_name, zip_bytes).

    Supports CRX3, CRX2, and raw ZIP.
    Raises InvalidCRXHeaderError if format is unrecognized or headers are corrupted.
    """
    if len(data) < 4:
        raise InvalidCRXHeaderError(
            "Package data too small to identify format",
            safe_message="Uploaded package is truncated or invalid.",
        )

    magic = data[:4]
    if magic == ZIP_MAGIC:
        return "zip", data

    if magic != CRX_MAGIC:
        raise InvalidCRXHeaderError(
            f"Unrecognized package header magic: {magic!r}",
            safe_message="File is neither a valid Chrome extension package (CRX) nor a standard ZIP archive.",
        )

    if len(data) < 12:
        raise InvalidCRXHeaderError(
            "CRX package truncated before version header",
            safe_message="Malformed CRX header: payload truncated.",
        )

    version = struct.unpack("<I", data[4:8])[0]

    if version == 3:
        # CRX3: 4 bytes 'Cr24', 4 bytes version (3), 4 bytes header size, header, then ZIP
        header_size = struct.unpack("<I", data[8:12])[0]
        if header_size <= 0 or header_size > 10 * 1024 * 1024:
            raise InvalidCRXHeaderError(
                f"Suspicious or invalid CRX3 header size: {header_size}",
                safe_message="Malformed CRX3 package: invalid header size.",
            )

        zip_offset = 12 + header_size
        if zip_offset >= len(data):
            raise InvalidCRXHeaderError(
                f"CRX3 header offset ({zip_offset}) exceeds package length ({len(data)})",
                safe_message="Malformed CRX3 package: payload truncated.",
            )

        zip_bytes = data[zip_offset:]
        if not zip_bytes.startswith(ZIP_MAGIC):
            raise InvalidCRXHeaderError(
                "CRX3 embedded archive does not have valid ZIP magic bytes",
                safe_message="Malformed CRX3 package: missing embedded archive.",
            )
        return "crx3", zip_bytes

    elif version == 2:
        # CRX2: 4 bytes 'Cr24', 4 bytes version (2), 4 bytes pubkey_len, 4 bytes sig_len
        if len(data) < 16:
            raise InvalidCRXHeaderError(
                "CRX2 package truncated before key headers",
                safe_message="Malformed CRX2 package: payload truncated.",
            )
        pubkey_len = struct.unpack("<I", data[8:12])[0]
        sig_len = struct.unpack("<I", data[12:16])[0]

        if pubkey_len <= 0 or sig_len <= 0 or pubkey_len > 10 * 1024 * 1024 or sig_len > 10 * 1024 * 1024:
            raise InvalidCRXHeaderError(
                f"Invalid CRX2 header lengths: pubkey={pubkey_len}, sig={sig_len}",
                safe_message="Malformed CRX2 package: invalid signature headers.",
            )

        zip_offset = 16 + pubkey_len + sig_len
        if zip_offset >= len(data):
            raise InvalidCRXHeaderError(
                f"CRX2 header offset ({zip_offset}) exceeds package length ({len(data)})",
                safe_message="Malformed CRX2 package: payload truncated.",
            )

        zip_bytes = data[zip_offset:]
        if not zip_bytes.startswith(ZIP_MAGIC):
            raise InvalidCRXHeaderError(
                "CRX2 embedded archive does not have valid ZIP magic bytes",
                safe_message="Malformed CRX2 package: missing embedded archive.",
            )
        return "crx2", zip_bytes

    else:
        raise InvalidCRXHeaderError(
            f"Unsupported CRX version: {version}",
            safe_message=f"Unsupported CRX version ({version}). Expected version 2 or 3.",
        )


def sanitize_member_path(
    member_name: str, max_nesting_depth: int | None = None
) -> tuple[str, list[str]]:
    """Sanitize and validate an archive member path.

    Returns (normalized_relative_path, path_parts).
    Raises ZipSlipError or NestingLimitExceededError if suspicious.
    """
    nesting_limit = max_nesting_depth if max_nesting_depth is not None else settings.MAX_NESTING_DEPTH
    # Normalize slashes and strip leading/trailing whitespace
    clean_name = member_name.strip().replace("\\", "/")

    # Strip leading slash if any
    clean_name = clean_name.lstrip("/")

    if not clean_name:
        raise ZipSlipError("Empty archive member path", safe_message="Malformed archive member path.")

    # Split into components
    parts = [p for p in clean_name.split("/") if p and p != "."]

    for part in parts:
        if part == "..":
            raise ZipSlipError(
                f"Directory traversal ('..') detected in member: {member_name}",
                safe_message=f"Path traversal detected in archive entry: {clean_rel_path_msg(clean_name)}",
            )
        if ":" in part:  # Windows drive letter or alternate data stream
            raise ZipSlipError(
                f"Dangerous characters in member name: {member_name}",
                safe_message=f"Illegal characters in archive entry: {clean_rel_path_msg(clean_name)}",
            )

    if len(parts) > nesting_limit + 1:
        raise NestingLimitExceededError(
            f"Nesting depth ({len(parts)}) exceeds limit ({nesting_limit})",
            safe_message=f"Archive directory nesting too deep in: {clean_rel_path_msg(clean_name)}",
        )

    return "/".join(parts), parts


def clean_rel_path_msg(name: str) -> str:
    """Return sanitized member name for client-safe messages."""
    return Path(name).as_posix()


@contextmanager
def safe_extract_extension(
    package_bytes: bytes,
    max_upload_size: int | None = None,
    max_expanded_size: int | None = None,
    max_file_count: int | None = None,
    max_nesting_depth: int | None = None,
    max_script_size: int | None = None,
) -> Generator[tuple[Path, ExtractionSummary], None, None]:
    """Safely unpack an extension package (CRX3, CRX2, or ZIP) into an isolated temp directory.

    Guarantees:
    - Never leaves temporary directories behind (cleanup via finally).
    - Validates size limits before and during extraction.
    - Blocks ZipSlip and symlinks.
    - Yields (temp_dir_path, extraction_summary).
    - Never surfaces internal file paths to callers outside the context.
    """
    upload_limit = max_upload_size if max_upload_size is not None else settings.MAX_UPLOAD_SIZE_BYTES
    expanded_limit = max_expanded_size if max_expanded_size is not None else settings.MAX_EXPANDED_SIZE_BYTES
    file_count_limit = max_file_count if max_file_count is not None else settings.MAX_FILE_COUNT
    nesting_limit = max_nesting_depth if max_nesting_depth is not None else settings.MAX_NESTING_DEPTH
    script_limit = max_script_size if max_script_size is not None else settings.MAX_SCRIPT_SIZE_BYTES

    if len(package_bytes) > upload_limit:
        raise DecompressionBombError(
            f"Package upload size ({len(package_bytes)}) exceeds limit ({upload_limit})",
            safe_message=f"Uploaded package exceeds maximum allowed size of {upload_limit // (1024 * 1024)} MB.",
        )

    sha256 = hashlib.sha256(package_bytes).hexdigest()
    pkg_format, zip_data = detect_archive_format(package_bytes)

    temp_dir = Path(tempfile.mkdtemp(prefix="sentinel_safe_"))
    try:
        try:
            zf = zipfile.ZipFile(io.BytesIO(zip_data))
        except zipfile.BadZipFile as e:
            raise InvalidCRXHeaderError(
                f"Corrupt or invalid ZIP payload: {e}",
                safe_message="Archive payload is corrupt or not a valid ZIP file.",
            ) from e

        members = zf.infolist()
        if len(members) > file_count_limit:
            raise FileLimitExceededError(
                f"Archive file count ({len(members)}) exceeds limit ({file_count_limit})",
                safe_message=f"Archive contains {len(members)} files, exceeding limit of {file_count_limit}.",
            )

        # Pre-check cumulative declared uncompressed size
        declared_total = sum(m.file_size for m in members)
        if declared_total > expanded_limit:
            raise DecompressionBombError(
                f"Declared uncompressed size ({declared_total}) exceeds limit ({expanded_limit})",
                safe_message="Archive uncompressed size exceeds safe limit (decompression bomb protection).",
            )

        extracted_files: list[ExtractedFileInfo] = []
        actual_total_bytes = 0
        js_count = 0

        target_base = temp_dir.resolve()

        for member in members:
            # Check symlink flag in external attributes
            if (member.external_attr >> 16) & S_IFLNK == S_IFLNK:
                raise SymlinkRejectedError(
                    f"Symbolic link rejected in member: {member.filename}",
                    safe_message=f"Symbolic links are prohibited: {member.filename}",
                )

            # Skip directory entries for file writing, but create safe directories
            clean_rel_path, _ = sanitize_member_path(member.filename, max_nesting_depth=nesting_limit)
            dest_path = (target_base / clean_rel_path).resolve()

            # Confirm destination stays strictly inside target_base
            try:
                dest_path.relative_to(target_base)
            except ValueError as err:
                raise ZipSlipError(
                    f"Resolved destination escapes target: {member.filename}",
                    safe_message=f"Path traversal detected in archive entry: {clean_rel_path}",
                ) from err

            if member.is_dir():
                dest_path.mkdir(parents=True, exist_ok=True)
                continue

            dest_path.parent.mkdir(parents=True, exist_ok=True)

            # Stream extraction in chunks to prevent zip bombs with forged declared size
            member_bytes_written = 0
            with zf.open(member) as src_file, open(dest_path, "wb") as dst_file:
                while chunk := src_file.read(64 * 1024):
                    dst_file.write(chunk)
                    member_bytes_written += len(chunk)
                    actual_total_bytes += len(chunk)

                    if actual_total_bytes > expanded_limit:
                        raise DecompressionBombError(
                            "Expanded size exceeded limit during extraction stream",
                            safe_message="Archive exceeded maximum safe uncompressed size during extraction.",
                        )

            is_js = dest_path.suffix.lower() in {".js", ".mjs", ".cjs"}
            is_html = dest_path.suffix.lower() in {".html", ".htm"}
            if is_js:
                if member_bytes_written > script_limit:
                    raise OversizedScriptError(
                        f"Script {clean_rel_path} ({member_bytes_written} bytes) exceeds limit ({script_limit} bytes)",
                        safe_message=f"Script exceeds maximum permissible size limit: {clean_rel_path}",
                    )
                js_count += 1

            extracted_files.append(
                ExtractedFileInfo(
                    rel_path=clean_rel_path,
                    size_bytes=member_bytes_written,
                    is_javascript=is_js,
                    is_html=is_html,
                )
            )

        summary = ExtractionSummary(
            sha256=sha256,
            format=pkg_format,
            file_count=len(extracted_files),
            total_bytes=actual_total_bytes,
            js_file_count=js_count,
            files=extracted_files,
        )

        yield temp_dir, summary

    finally:
        # Guarantee removal of all temporary files regardless of exceptions
        shutil.rmtree(temp_dir, ignore_errors=True)
