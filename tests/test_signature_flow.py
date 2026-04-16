"""Integration tests for the digital signature flow."""
import io
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory

from app.cli.cli_app import main
from app.core.engine import DigitalSignatureApp
from app.exceptions import VerificationError
from app.models.signed_package import SignedPackage


class SignatureFlowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = TemporaryDirectory()
        self.base_path = Path(self.temp_dir.name)
        self.app = DigitalSignatureApp(self.base_path / "keystore")
        self.app.generate_keys("user1", 2048)
        self.app.generate_keys("user2", 2048)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_sign_and_verify_success(self) -> None:
        message = "Chuyen 1 trieu dong"
        package_path = self.base_path / "signed.json"
        self.app.sign_to_file("user1", message, package_path)
        result = self.app.verify_from_file(
            package_path, self.base_path / "keystore" / "public" / "user1_public.pem"
        )
        self.assertTrue(result.is_valid)
        self.assertEqual(result.status_message, "VERIFIED - INTEGRITY GUARANTEED")
        # Confirm the digest field contains the SHA-256 of the original message
        import hashlib
        expected_digest = hashlib.sha256(message.encode("utf-8")).hexdigest().upper()
        self.assertEqual(result.message_digest_hex, expected_digest)

    def test_verify_fails_when_message_tampered(self) -> None:
        package = self.app.sign_to_package("user1", "Chuyen 1 trieu dong")
        tampered = SignedPackage(
            metadata=package.metadata,
            message="Chuyen 100 trieu dong",
            signature=package.signature,
            signer_fingerprint=package.signer_fingerprint,
        )
        public_key = self.app.keystore.load_public_key("user1")
        
        # Test direct package verification
        from app.services import crypto_service
        with self.assertRaises(VerificationError):
            crypto_service.verify_package(tampered, public_key)

    def test_verify_fails_with_wrong_public_key(self) -> None:
        package_path = self.base_path / "signed.json"
        self.app.sign_to_file("user1", "Noi dung goc", package_path)
        with self.assertRaises(VerificationError):
            self.app.verify_from_file(
                package_path, self.base_path / "keystore" / "public" / "user2_public.pem"
            )

    def test_invalid_base64_signature_raises(self) -> None:
        package = self.app.sign_to_package("user1", "Hello")
        broken = SignedPackage(
            metadata=package.metadata,
            message=package.message,
            signature="@@@invalid-base64@@@",
            signer_fingerprint=package.signer_fingerprint,
        )
        public_key = self.app.keystore.load_public_key("user1")
        from app.services import crypto_service
        with self.assertRaises(VerificationError):
            crypto_service.verify_package(broken, public_key)

    def test_main_without_args_returns_zero(self) -> None:
        from unittest.mock import patch
        with patch('app.cli.cli_app._is_tk_available', return_value=False):
            buf = io.StringIO()
            with redirect_stdout(buf):
                exit_code = main([])
            self.assertEqual(exit_code, 0)
            self.assertIn("Quick Start:", buf.getvalue())

    def test_main_does_not_raise_system_exit(self) -> None:
        from unittest.mock import patch
        with patch('app.cli.cli_app._is_tk_available', return_value=False):
            try:
                main([])
            except SystemExit as exc:  # pragma: no cover
                self.fail(f"main() không nên raise SystemExit nữa, nhưng đã raise: {exc}")
