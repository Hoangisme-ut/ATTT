"""Core engine: high-level façade that orchestrates services."""
from __future__ import annotations

from pathlib import Path
from typing import Tuple

from app.constants import DEFAULT_KEY_SIZE
from app.models.signed_package import SignedPackage, VerificationResult
from app.services import crypto_service, storage_service
from app.services.keystore_service import KeyStore


class DigitalSignatureApp:
    """Top-level application object.

    Composes *KeyStore*, *crypto_service*, and *storage_service* so that
    the CLI, GUI, and tests can all share the same business logic.
    """

    def __init__(self, keystore_dir: Path | str = "keystore") -> None:
        self.keystore = KeyStore(keystore_dir)

    # ------------------------------------------------------------------
    # Key management
    # ------------------------------------------------------------------

    def generate_keys(
        self, owner: str, key_size: int = DEFAULT_KEY_SIZE
    ) -> Tuple[Path, Path, str]:
        """Generate an RSA key pair for *owner*."""
        return self.keystore.generate_keypair(owner=owner, key_size=key_size)

    # ------------------------------------------------------------------
    # Signing
    # ------------------------------------------------------------------

    def sign_to_package(self, owner: str, message: str) -> SignedPackage:
        """Sign *message* using *owner*'s private key and return a package."""
        private_key = self.keystore.load_private_key(owner)
        public_key = self.keystore.load_public_key(owner)
        return crypto_service.sign_message(
            message=message, private_key=private_key, public_key=public_key,
        )

    def sign_to_file(
        self, owner: str, message: str, output_path: Path | str
    ) -> SignedPackage:
        """Sign *message* and persist the JSON package to *output_path*."""
        package = self.sign_to_package(owner, message)
        storage_service.save_text(output_path, package.to_json())
        return package

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------

    def verify_from_file(
        self, package_path: Path | str, public_key_path: Path | str
    ) -> VerificationResult:
        """Load a signed JSON package and verify it against a public key file."""
        content = storage_service.read_text(package_path)
        package = SignedPackage.from_json(content)
        public_key = self.keystore.load_public_key_from_file(public_key_path)
        return crypto_service.verify_package(package, public_key)
