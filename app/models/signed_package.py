"""Data models: SignedPackage and VerificationResult."""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass

from app.exceptions import InvalidPackageError
from app.models.metadata import Metadata


@dataclass
class SignedPackage:
    """Represents a complete signed JSON package ready for export and transport."""

    metadata: Metadata
    message: str
    signature: str          # Base64-encoded RSA signature
    signer_fingerprint: str # SHA-256 fingerprint of the signer's public key

    def to_dict(self) -> dict:
        return {
            "metadata": asdict(self.metadata),
            "message": self.message,
            "signature": self.signature,
            "signer_fingerprint": self.signer_fingerprint,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)

    @classmethod
    def from_dict(cls, data: dict) -> "SignedPackage":
        try:
            metadata = Metadata(**data["metadata"])
            message = data["message"]
            signature = data["signature"]
            signer_fingerprint = data["signer_fingerprint"]
        except (KeyError, TypeError) as exc:
            raise InvalidPackageError("Gói JSON không đúng cấu trúc yêu cầu.") from exc

        if not all(isinstance(v, str) for v in (message, signature, signer_fingerprint)):
            raise InvalidPackageError(
                "Các trường message, signature và signer_fingerprint phải là chuỗi."
            )

        return cls(
            metadata=metadata,
            message=message,
            signature=signature,
            signer_fingerprint=signer_fingerprint,
        )

    @classmethod
    def from_json(cls, content: str) -> "SignedPackage":
        try:
            data = json.loads(content)
        except json.JSONDecodeError as exc:
            raise InvalidPackageError("Không đọc được JSON hoặc tệp bị hỏng.") from exc
        return cls.from_dict(data)


@dataclass
class VerificationResult:
    """Result object returned after a successful verification."""

    is_valid: bool
    message_digest_hex: str
    status_message: str
    expected_fingerprint: str
    package_fingerprint: str
