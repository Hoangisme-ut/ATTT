"""Keystore service: RSA key generation, loading, and persistence."""
from __future__ import annotations

from pathlib import Path
from typing import Tuple

from Crypto.PublicKey import RSA

from app.constants import DEFAULT_KEY_SIZE
from app.exceptions import CryptoAppError
from app.services.crypto_service import public_key_fingerprint


class KeyStore:
    """Manages RSA key pairs on disk under a structured directory layout.

    Layout::

        <base_dir>/
            private/<owner>_private.pem
            public/<owner>_public.pem
    """

    def __init__(self, base_dir: Path | str = "keystore") -> None:
        self.base_dir = Path(base_dir)
        self.private_dir = self.base_dir / "private"
        self.public_dir = self.base_dir / "public"
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.private_dir.mkdir(parents=True, exist_ok=True)
        self.public_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Path helpers
    # ------------------------------------------------------------------

    def private_key_path(self, owner: str) -> Path:
        return self.private_dir / f"{owner}_private.pem"

    def public_key_path(self, owner: str) -> Path:
        return self.public_dir / f"{owner}_public.pem"

    # ------------------------------------------------------------------
    # Key generation
    # ------------------------------------------------------------------

    def generate_keypair(
        self, owner: str, key_size: int = DEFAULT_KEY_SIZE
    ) -> Tuple[Path, Path, str]:
        """Generate an RSA key pair, persist to PEM files, return paths + fingerprint."""
        if key_size < 2048:
            raise CryptoAppError("Kích thước khóa phải từ 2048-bit trở lên.")

        private_path = self.private_key_path(owner)
        public_path = self.public_key_path(owner)

        if private_path.exists() or public_path.exists():
            raise CryptoAppError(f"Khóa cho '{owner}' đã tồn tại! Vui lòng chọn tên khác.")

        key = RSA.generate(key_size)

        private_path.write_bytes(key.export_key(format="PEM"))
        public_path.write_bytes(key.publickey().export_key(format="PEM"))

        fingerprint = public_key_fingerprint(key.publickey())
        return private_path, public_path, fingerprint

    # ------------------------------------------------------------------
    # Key loading
    # ------------------------------------------------------------------

    def load_private_key(self, owner: str) -> RSA.RsaKey:
        path = self.private_key_path(owner)
        if not path.exists():
            raise CryptoAppError(f"Không tìm thấy private key của '{owner}' tại {path}")
        return RSA.import_key(path.read_bytes())

    def load_public_key(self, owner: str) -> RSA.RsaKey:
        path = self.public_key_path(owner)
        if not path.exists():
            raise CryptoAppError(f"Không tìm thấy public key của '{owner}' tại {path}")
        return RSA.import_key(path.read_bytes())

    def load_public_key_from_file(self, path: Path | str) -> RSA.RsaKey:
        file_path = Path(path)
        if not file_path.exists():
            raise CryptoAppError(f"Không tìm thấy public key tại {file_path}")
        return RSA.import_key(file_path.read_bytes())
