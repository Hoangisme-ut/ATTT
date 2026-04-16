"""Cryptographic service: hashing, signing, verifying."""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15

from app.constants import DEFAULT_ENCODING, DEFAULT_HASH_ALGORITHM, DEFAULT_SIGNATURE_SCHEME
from app.exceptions import VerificationError
from app.models.metadata import Metadata
from app.models.signed_package import SignedPackage, VerificationResult


def _digest_hex(message: str, encoding: str = DEFAULT_ENCODING) -> str:
    return hashlib.sha256(message.encode(encoding)).hexdigest().upper()


def _crypto_hash(message: str, encoding: str = DEFAULT_ENCODING) -> SHA256.SHA256Hash:
    return SHA256.new(message.encode(encoding))


def public_key_fingerprint(public_key: RSA.RsaKey) -> str:
    """Return colon-separated SHA-256 hex fingerprint of the DER-encoded public key."""
    der = public_key.export_key(format="DER")
    digest = hashlib.sha256(der).hexdigest().upper()
    pairs = [digest[i: i + 2] for i in range(0, len(digest), 2)]
    return ":".join(pairs)


def sign_message(
    message: str,
    private_key: RSA.RsaKey,
    public_key: RSA.RsaKey,
    encoding: str = DEFAULT_ENCODING,
) -> SignedPackage:
    """Sign *message* with *private_key* and embed the signer's fingerprint."""
    digest_obj = _crypto_hash(message, encoding)
    signature_bytes = pkcs1_15.new(private_key).sign(digest_obj)
    signature_b64 = base64.b64encode(signature_bytes).decode("ascii")
    fingerprint = public_key_fingerprint(public_key)

    return SignedPackage(
        metadata=Metadata(encoding=encoding),
        message=message,
        signature=signature_b64,
        signer_fingerprint=fingerprint,
    )


def verify_package(package: SignedPackage, public_key: RSA.RsaKey) -> VerificationResult:
    """Verify *package* against *public_key*."""
    if package.metadata.hash_algorithm.upper() != DEFAULT_HASH_ALGORITHM:
        raise VerificationError("Thuật toán băm trong gói không được hỗ trợ.")
    if package.metadata.signature_scheme != DEFAULT_SIGNATURE_SCHEME:
        raise VerificationError("Chuẩn chữ ký trong gói không được hỗ trợ.")

    expected_fingerprint = public_key_fingerprint(public_key)
    package_fingerprint = package.signer_fingerprint
    message_digest_hex = _digest_hex(package.message, package.metadata.encoding)

    try:
        signature_bytes = base64.b64decode(package.signature, validate=True)
    except binascii.Error as exc:
        raise VerificationError("Chuỗi chữ ký Base64 không hợp lệ hoặc đã bị hỏng.") from exc

    try:
        # PKCS#1 v1.5 API verifies the digest against the signature internally.
        # It does not return an extracted hash for us, it only raises on mismatch.
        digest_obj = _crypto_hash(package.message, package.metadata.encoding)
        pkcs1_15.new(public_key).verify(digest_obj, signature_bytes)
    except (ValueError, TypeError) as exc:
        raise VerificationError(
            "Xác minh thất bại: chữ ký không hợp lệ hoặc dữ liệu đã bị thay đổi."
        ) from exc

    if not hmac.compare_digest(expected_fingerprint, package_fingerprint):
        raise VerificationError(
            "Xác minh toán học thành công nhưng fingerprint không khớp với public key đang dùng. "
            "Có dấu hiệu dùng sai khóa hoặc mạo danh."
        )

    return VerificationResult(
        is_valid=True,
        message_digest_hex=message_digest_hex,
        status_message="VERIFIED - INTEGRITY GUARANTEED",
        expected_fingerprint=expected_fingerprint,
        package_fingerprint=package_fingerprint,
    )


def digest_hex(message: str, encoding: str = DEFAULT_ENCODING) -> str:
    """Convenience wrapper — used by CLI and GUI to display the SHA-256 digest."""
    return _digest_hex(message, encoding)
