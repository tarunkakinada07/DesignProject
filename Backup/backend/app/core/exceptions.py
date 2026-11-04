"""Custom exceptions for safe extraction, parsing, and pipeline enforcement."""


class SentinelError(Exception):
    """Base exception for Sentinel Extension Detector."""

    def __init__(self, message: str, safe_message: str | None = None):
        super().__init__(message)
        # safe_message contains no internal server paths or sensitive details
        self.safe_message = safe_message or message


class ArchiveSecurityError(SentinelError):
    """Raised when an uploaded extension package violates security constraints."""

    pass


class InvalidCRXHeaderError(ArchiveSecurityError):
    """Raised when a CRX header is malformed, truncated, or invalid."""

    pass


class ZipSlipError(ArchiveSecurityError):
    """Raised when an archive member attempts directory traversal."""

    pass


class DecompressionBombError(ArchiveSecurityError):
    """Raised when an archive violates size or expansion ratio limits."""

    pass


class SymlinkRejectedError(ArchiveSecurityError):
    """Raised when an archive member contains a symbolic or hard link."""

    pass


class FileLimitExceededError(ArchiveSecurityError):
    """Raised when an archive exceeds the maximum permissible file count."""

    pass


class NestingLimitExceededError(ArchiveSecurityError):
    """Raised when directory nesting depth exceeds configured limit."""

    pass


class OversizedScriptError(SentinelError):
    """Raised when a single script exceeds the maximum permissible size."""

    pass


class ManifestError(SentinelError):
    """Base exception for manifest parsing errors."""

    pass


class ManifestNotFoundError(ManifestError):
    """Raised when manifest.json is absent in the extension root."""

    pass


class CorruptManifestError(ManifestError):
    """Raised when manifest.json contains invalid JSON syntax."""

    pass


class InvalidManifestError(ManifestError):
    """Raised when manifest.json lacks required schema attributes."""

    pass
