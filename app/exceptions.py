"""Custom exceptions for the Digital Signature Application."""


class CryptoAppError(Exception):
    """Base exception for the application."""


class InvalidPackageError(CryptoAppError):
    """Raised when the JSON package is malformed or missing required fields."""


class VerificationError(CryptoAppError):
    """Raised when signature verification fails (tampered data, wrong key, etc.)."""
