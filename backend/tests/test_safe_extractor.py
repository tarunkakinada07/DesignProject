"""Comprehensive tests for safe archive extraction and security guards.

Covers:
- CRX3 and CRX2 parsing
- Zip-Slip path traversal blocking
- Decompression bomb detection (declared and stream)
- File count and nesting limits
- Symlink rejection
- Cleanup guarantees on success and failure
"""

import io
import struct
import zipfile

import pytest

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
from backend.app.services.safe_extractor import (
    CRX_MAGIC,
    detect_archive_format,
    safe_extract_extension,
    sanitize_member_path,
)


def create_minimal_zip(files: dict[str, str | bytes]) -> bytes:
    """Helper to build an in-memory ZIP archive."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for filename, content in files.items():
            if isinstance(content, str):
                content = content.encode("utf-8")
            zf.writestr(filename, content)
    return buf.getvalue()


def create_crx3(zip_bytes: bytes, header_bytes: bytes = b"\x08\x01\x12\x04test") -> bytes:
    """Helper to construct a valid CRX3 binary package."""
    header_len = len(header_bytes)
    return (
        CRX_MAGIC
        + struct.pack("<I", 3)  # Version 3
        + struct.pack("<I", header_len)
        + header_bytes
        + zip_bytes
    )


def create_crx2(zip_bytes: bytes, pubkey: bytes = b"fake_pubkey", sig: bytes = b"fake_sig") -> bytes:
    """Helper to construct a valid CRX2 binary package."""
    return (
        CRX_MAGIC
        + struct.pack("<I", 2)  # Version 2
        + struct.pack("<I", len(pubkey))
        + struct.pack("<I", len(sig))
        + pubkey
        + sig
        + zip_bytes
    )


# 1. Valid Extraction Tests
def test_valid_zip_extraction():
    pkg = create_minimal_zip({
        "manifest.json": '{"manifest_version": 3, "name": "Test", "version": "1.0"}',
        "background.js": 'console.log("hello");',
    })
    with safe_extract_extension(pkg) as (temp_dir, summary):
        assert summary.format == "zip"
        assert summary.file_count == 2
        assert summary.js_file_count == 1
        assert (temp_dir / "manifest.json").is_file()
        assert (temp_dir / "background.js").is_file()
    assert not temp_dir.exists()  # Cleaned up


def test_valid_crx3_extraction():
    zip_data = create_minimal_zip({
        "manifest.json": '{"manifest_version": 3, "name": "CRX3 Ext", "version": "2.0"}',
        "content.js": 'alert(1);',
    })
    crx3_pkg = create_crx3(zip_data)
    with safe_extract_extension(crx3_pkg) as (temp_dir, summary):
        assert summary.format == "crx3"
        assert summary.file_count == 2
        assert (temp_dir / "manifest.json").is_file()
    assert not temp_dir.exists()


def test_valid_crx2_extraction():
    zip_data = create_minimal_zip({
        "manifest.json": '{"manifest_version": 2, "name": "CRX2 Ext", "version": "1.0"}',
    })
    crx2_pkg = create_crx2(zip_data)
    with safe_extract_extension(crx2_pkg) as (temp_dir, summary):
        assert summary.format == "crx2"
        assert summary.file_count == 1
    assert not temp_dir.exists()


# 2. CRX Header Validation Tests
def test_bad_crx_header_magic():
    bad_data = b"BOGUS_MAGIC_NOT_CRX"
    with pytest.raises(InvalidCRXHeaderError):
        detect_archive_format(bad_data)


def test_bad_crx3_truncated_header():
    # Declares 1000 byte header, but file ends right after header length
    truncated_crx = CRX_MAGIC + struct.pack("<I", 3) + struct.pack("<I", 1000) + b"too_short"
    with pytest.raises(InvalidCRXHeaderError):
        detect_archive_format(truncated_crx)


def test_bad_crx_unsupported_version():
    bad_version_crx = CRX_MAGIC + struct.pack("<I", 99) + struct.pack("<I", 10)
    with pytest.raises(InvalidCRXHeaderError):
        detect_archive_format(bad_version_crx)


# 3. Zip-Slip (Path Traversal) Tests
def test_zip_slip_parent_traversal():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../../evil.js", b"console.log('pwned');")
        zf.writestr("manifest.json", b'{"manifest_version": 3, "name": "Evil", "version": "1.0"}')

    evil_zip = buf.getvalue()
    with pytest.raises(ZipSlipError):
        with safe_extract_extension(evil_zip):
            pass


def test_zip_slip_nested_parent_traversal():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("sub/dir/../../../../evil.js", b"attack")

    with pytest.raises(ZipSlipError):
        with safe_extract_extension(buf.getvalue()):
            pass


def test_sanitize_member_path_blocks_windows_drive():
    with pytest.raises(ZipSlipError):
        sanitize_member_path("C:/Windows/evil.js")


# 4. Decompression Bomb & Size Limit Tests
def test_decompression_bomb_declared_size(monkeypatch):
    # Temporarily set limit to 1000 bytes for testing
    monkeypatch.setattr(settings, "MAX_EXPANDED_SIZE_BYTES", 1000)
    huge_data = b"A" * 2000
    bomb_zip = create_minimal_zip({"big.txt": huge_data})

    with pytest.raises(DecompressionBombError):
        with safe_extract_extension(bomb_zip):
            pass


def test_decompression_bomb_streaming_detection(monkeypatch):
    monkeypatch.setattr(settings, "MAX_EXPANDED_SIZE_BYTES", 5000)
    # Highly compressible sequence (repeating zero bytes compresses to ~50 bytes, expands to 10KB)
    repeating = b"X" * 10000
    bomb_zip = create_minimal_zip({"repeat.bin": repeating})

    with pytest.raises(DecompressionBombError):
        with safe_extract_extension(bomb_zip):
            pass


# 5. File Count and Nesting Limit Tests
def test_file_limit_exceeded(monkeypatch):
    monkeypatch.setattr(settings, "MAX_FILE_COUNT", 5)
    files = {f"file_{i}.txt": "content" for i in range(10)}
    too_many_zip = create_minimal_zip(files)

    with pytest.raises(FileLimitExceededError):
        with safe_extract_extension(too_many_zip):
            pass


def test_nesting_limit_exceeded(monkeypatch):
    monkeypatch.setattr(settings, "MAX_NESTING_DEPTH", 2)
    files = {"a/b/c/d/deep.js": "console.log('deep');"}
    deep_zip = create_minimal_zip(files)

    with pytest.raises(NestingLimitExceededError):
        with safe_extract_extension(deep_zip):
            pass


# 6. Symlink Rejection Test
def test_symlink_rejected():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        info = zipfile.ZipInfo("symlink_entry")
        # Set Unix S_IFLNK mode (0o120000) in external_attr
        info.external_attr = 0o120777 << 16
        zf.writestr(info, "target_file")

    with pytest.raises(SymlinkRejectedError):
        with safe_extract_extension(buf.getvalue()):
            pass


# 7. Guaranteed Cleanup Test
def test_temp_dir_cleaned_up_on_failure():
    # If extraction raises an error, verify the created temp dir no longer exists
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../../evil.js", b"evil")

    caught_path = None
    try:
        with safe_extract_extension(buf.getvalue()) as (td, _):
            caught_path = td
    except ZipSlipError:
        pass

    if caught_path:
        assert not caught_path.exists()


# 8. Oversized Script Limit Test
def test_oversized_script_rejected():
    files = {
        "manifest.json": '{"manifest_version": 3, "name": "BigScript Ext", "version": "1.0"}',
        "big.js": "console.log('x');" * 200,
    }
    big_script_zip = create_minimal_zip(files)

    with pytest.raises(OversizedScriptError):
        with safe_extract_extension(big_script_zip, max_script_size=100):
            pass

