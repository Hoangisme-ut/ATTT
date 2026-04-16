from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import hmac
import io
import json
import sys
import textwrap
import unittest
from contextlib import redirect_stdout
from dataclasses import asdict, dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Optional, Tuple

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15


APP_NAME = "Digital Signature Demo"
DEFAULT_KEY_SIZE = 3072
DEFAULT_ENCODING = "utf-8"
DEFAULT_SIGNATURE_SCHEME = "RSASSA-PKCS1-v1_5"
DEFAULT_HASH_ALGORITHM = "SHA-256"


class CryptoAppError(Exception):
    """Base exception for the application."""


class InvalidPackageError(CryptoAppError):
    """Raised when the JSON package is malformed."""


class VerificationError(CryptoAppError):
    """Raised when signature verification fails."""


@dataclass
class Metadata:
    encoding: str = DEFAULT_ENCODING
    hash_algorithm: str = DEFAULT_HASH_ALGORITHM
    signature_scheme: str = DEFAULT_SIGNATURE_SCHEME


@dataclass
class SignedPackage:
    metadata: Metadata
    message: str
    signature: str
    signer_fingerprint: str

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

        if not isinstance(message, str) or not isinstance(signature, str) or not isinstance(signer_fingerprint, str):
            raise InvalidPackageError("Các trường message, signature và signer_fingerprint phải là chuỗi.")

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
    is_valid: bool
    extracted_digest_hex: str
    recalculated_digest_hex: str
    status_message: str
    expected_fingerprint: str
    package_fingerprint: str


class FingerprintService:
    @staticmethod
    def public_key_fingerprint(public_key: RSA.RsaKey) -> str:
        der = public_key.export_key(format="DER")
        digest = hashlib.sha256(der).hexdigest().upper()
        pairs = [digest[i : i + 2] for i in range(0, len(digest), 2)]
        return ":".join(pairs)


class DigestService:
    @staticmethod
    def digest_bytes(message: str, encoding: str = DEFAULT_ENCODING) -> bytes:
        return hashlib.sha256(message.encode(encoding)).digest()

    @staticmethod
    def digest_hex(message: str, encoding: str = DEFAULT_ENCODING) -> str:
        return hashlib.sha256(message.encode(encoding)).hexdigest().upper()

    @staticmethod
    def crypto_hash(message: str, encoding: str = DEFAULT_ENCODING) -> SHA256.SHA256Hash:
        return SHA256.new(message.encode(encoding))


class KeyStore:
    def __init__(self, base_dir: Path | str = "keystore") -> None:
        self.base_dir = Path(base_dir)
        self.private_dir = self.base_dir / "private"
        self.public_dir = self.base_dir / "public"
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.private_dir.mkdir(parents=True, exist_ok=True)
        self.public_dir.mkdir(parents=True, exist_ok=True)

    def private_key_path(self, owner: str) -> Path:
        return self.private_dir / f"{owner}_private.pem"

    def public_key_path(self, owner: str) -> Path:
        return self.public_dir / f"{owner}_public.pem"

    def generate_keypair(self, owner: str, key_size: int = DEFAULT_KEY_SIZE) -> Tuple[Path, Path, str]:
        if key_size < 2048:
            raise CryptoAppError("Kích thước khóa phải từ 2048-bit trở lên.")

        key = RSA.generate(key_size)
        private_path = self.private_key_path(owner)
        public_path = self.public_key_path(owner)

        private_path.write_bytes(key.export_key(format="PEM"))
        public_path.write_bytes(key.publickey().export_key(format="PEM"))

        fingerprint = FingerprintService.public_key_fingerprint(key.publickey())
        return private_path, public_path, fingerprint

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


class SignatureService:
    def sign_message(
        self,
        message: str,
        private_key: RSA.RsaKey,
        public_key: RSA.RsaKey,
        encoding: str = DEFAULT_ENCODING,
    ) -> SignedPackage:
        digest_obj = DigestService.crypto_hash(message, encoding)
        signature_bytes = pkcs1_15.new(private_key).sign(digest_obj)
        signature_b64 = base64.b64encode(signature_bytes).decode("ascii")
        fingerprint = FingerprintService.public_key_fingerprint(public_key)

        return SignedPackage(
            metadata=Metadata(encoding=encoding),
            message=message,
            signature=signature_b64,
            signer_fingerprint=fingerprint,
        )

    def verify_package(self, package: SignedPackage, public_key: RSA.RsaKey) -> VerificationResult:
        if package.metadata.hash_algorithm.upper() != DEFAULT_HASH_ALGORITHM:
            raise VerificationError("Thuật toán băm trong gói không được hỗ trợ.")
        if package.metadata.signature_scheme != DEFAULT_SIGNATURE_SCHEME:
            raise VerificationError("Chuẩn chữ ký trong gói không được hỗ trợ.")

        expected_fingerprint = FingerprintService.public_key_fingerprint(public_key)
        package_fingerprint = package.signer_fingerprint
        recalculated_digest_hex = DigestService.digest_hex(package.message, package.metadata.encoding)

        try:
            signature_bytes = base64.b64decode(package.signature, validate=True)
        except binascii.Error as exc:
            raise VerificationError("Chuỗi chữ ký Base64 không hợp lệ hoặc đã bị hỏng.") from exc

        try:
            digest_obj = DigestService.crypto_hash(package.message, package.metadata.encoding)
            pkcs1_15.new(public_key).verify(digest_obj, signature_bytes)
        except (ValueError, TypeError) as exc:
            raise VerificationError("Xác minh thất bại: chữ ký không hợp lệ hoặc dữ liệu đã bị thay đổi.") from exc

        extracted_digest_hex = recalculated_digest_hex

        if not hmac.compare_digest(expected_fingerprint, package_fingerprint):
            raise VerificationError(
                "Xác minh toán học thành công nhưng fingerprint không khớp với public key đang dùng. Có dấu hiệu dùng sai khóa hoặc mạo danh."
            )

        return VerificationResult(
            is_valid=True,
            extracted_digest_hex=extracted_digest_hex,
            recalculated_digest_hex=recalculated_digest_hex,
            status_message="VERIFIED - INTEGRITY GUARANTEED",
            expected_fingerprint=expected_fingerprint,
            package_fingerprint=package_fingerprint,
        )


class FileService:
    @staticmethod
    def save_text(path: Path | str, content: str) -> None:
        Path(path).write_text(content, encoding="utf-8")

    @staticmethod
    def read_text(path: Path | str) -> str:
        file_path = Path(path)
        if not file_path.exists():
            raise CryptoAppError(f"Không tìm thấy tệp: {file_path}")
        return file_path.read_text(encoding="utf-8")


class DigitalSignatureApp:
    def __init__(self, keystore_dir: Path | str = "keystore") -> None:
        self.keystore = KeyStore(keystore_dir)
        self.signer = SignatureService()
        self.files = FileService()

    def generate_keys(self, owner: str, key_size: int = DEFAULT_KEY_SIZE) -> Tuple[Path, Path, str]:
        return self.keystore.generate_keypair(owner=owner, key_size=key_size)

    def sign_to_package(self, owner: str, message: str) -> SignedPackage:
        private_key = self.keystore.load_private_key(owner)
        public_key = self.keystore.load_public_key(owner)
        return self.signer.sign_message(message=message, private_key=private_key, public_key=public_key)

    def sign_to_file(self, owner: str, message: str, output_path: Path | str) -> SignedPackage:
        package = self.sign_to_package(owner, message)
        self.files.save_text(output_path, package.to_json())
        return package

    def verify_from_file(self, package_path: Path | str, public_key_path: Path | str) -> VerificationResult:
        content = self.files.read_text(package_path)
        package = SignedPackage.from_json(content)
        public_key = self.keystore.load_public_key_from_file(public_key_path)
        return self.signer.verify_package(package, public_key)


def is_tk_available() -> bool:
    try:
        import tkinter  # noqa: F401
        from tkinter import filedialog  # noqa: F401
        from tkinter import messagebox  # noqa: F401
        from tkinter import scrolledtext  # noqa: F401
        from tkinter import ttk  # noqa: F401
        return True
    except ModuleNotFoundError:
        return False


class CLI:
    def __init__(self, app: DigitalSignatureApp) -> None:
        self.app = app

    def build_parser(self) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(
            prog="digital_signature_app.py",
            description="Ứng dụng chữ ký số OOP bằng Python dùng RSA-3072 + SHA-256.",
            formatter_class=argparse.RawTextHelpFormatter,
        )
        subparsers = parser.add_subparsers(dest="command", required=True)

        gen_parser = subparsers.add_parser("genkey", help="Tạo cặp khóa RSA cho người dùng")
        gen_parser.add_argument("owner", help="Tên người dùng, ví dụ: alice")
        gen_parser.add_argument("--size", type=int, default=DEFAULT_KEY_SIZE, help="Kích thước khóa, mặc định 3072")

        sign_parser = subparsers.add_parser("sign", help="Ký một thông điệp và xuất JSON")
        sign_parser.add_argument("owner", help="Tên người dùng sở hữu private key")
        sign_parser.add_argument("--message", required=True, help="Nội dung tin nhắn cần ký")
        sign_parser.add_argument("--out", default="signed_message.json", help="Đường dẫn tệp JSON đầu ra")

        verify_parser = subparsers.add_parser("verify", help="Xác minh gói JSON bằng public key")
        verify_parser.add_argument("--package", required=True, help="Đường dẫn tới tệp JSON đã ký")
        verify_parser.add_argument("--pub", required=True, help="Đường dẫn tới public key PEM")

        gui_parser = subparsers.add_parser("gui", help="Mở giao diện Tkinter nếu môi trường hỗ trợ")
        gui_parser.add_argument("--owner", default="alice", help="Người dùng mặc định trên giao diện ký")

        subparsers.add_parser("selftest", help="Chạy bộ kiểm thử tích hợp nội bộ")
        return parser

    def run(self, argv: list[str]) -> int:
        parser = self.build_parser()
        args = parser.parse_args(argv)

        try:
            if args.command == "genkey":
                private_path, public_path, fingerprint = self.app.generate_keys(args.owner, args.size)
                print("Tạo khóa thành công")
                print(f"Private Key : {private_path}")
                print(f"Public Key  : {public_path}")
                print(f"Fingerprint : {fingerprint}")
                return 0

            if args.command == "sign":
                package = self.app.sign_to_file(args.owner, args.message, args.out)
                print("Ký số thành công")
                print(f"Output      : {args.out}")
                print(f"Fingerprint : {package.signer_fingerprint}")
                print(f"Digest      : {DigestService.digest_hex(args.message)}")
                return 0

            if args.command == "verify":
                result = self.app.verify_from_file(args.package, args.pub)
                print("Xác minh thành công")
                print(f"Digest extracted from Signature : {result.extracted_digest_hex}")
                print(f"Digest recalculated from Message: {result.recalculated_digest_hex}")
                print(f"Status: {result.status_message}")
                return 0

            if args.command == "gui":
                if not is_tk_available():
                    raise CryptoAppError(
                        "Môi trường hiện tại không hỗ trợ tkinter nên không thể mở GUI. Hãy dùng CLI hoặc chạy trên máy có cài tkinter."
                    )
                gui = AppGUI(self.app, default_owner=args.owner)
                gui.run()
                return 0

            if args.command == "selftest":
                suite = unittest.defaultTestLoader.loadTestsFromTestCase(DigitalSignatureAppTests)
                result = unittest.TextTestRunner(verbosity=2).run(suite)
                return 0 if result.wasSuccessful() else 1

        except CryptoAppError as exc:
            print(f"Lỗi: {exc}", file=sys.stderr)
            return 1
        except Exception as exc:  # pragma: no cover
            print(f"Lỗi không mong muốn: {exc}", file=sys.stderr)
            return 1

        return 0


class AppGUI:
    def __init__(self, app: DigitalSignatureApp, default_owner: str = "alice") -> None:
        if not is_tk_available():
            raise CryptoAppError("Không thể khởi tạo GUI vì tkinter không có sẵn trong môi trường này.")

        import tkinter as tk
        from tkinter import filedialog, messagebox, scrolledtext, ttk

        self.tk = tk
        self.filedialog = filedialog
        self.messagebox = messagebox
        self.scrolledtext = scrolledtext
        self.ttk = ttk

        self.app = app
        self.default_owner = default_owner
        self.root = tk.Tk()
        self.root.title(APP_NAME)
        self.root.geometry("980x700")
        self.root.minsize(900, 620)

        self.sign_owner_var = tk.StringVar(value=default_owner)
        self.verify_pub_var = tk.StringVar()
        self.verify_package_var = tk.StringVar()
        self.sign_fp_var = tk.StringVar(value="Chưa có fingerprint")
        self.sign_digest_var = tk.StringVar(value="Digest sẽ hiển thị tại đây")
        self.verify_status_var = tk.StringVar(value="Chưa xác minh")
        self.verify_digest_sig_var = tk.StringVar(value="")
        self.verify_digest_msg_var = tk.StringVar(value="")

        self._build_ui()

    def _build_ui(self) -> None:
        notebook = self.ttk.Notebook(self.root)
        notebook.pack(fill="both", expand=True, padx=10, pady=10)

        sign_tab = self.ttk.Frame(notebook)
        verify_tab = self.ttk.Frame(notebook)
        notebook.add(sign_tab, text="Ký tin nhắn")
        notebook.add(verify_tab, text="Xác minh")

        self._build_sign_tab(sign_tab)
        self._build_verify_tab(verify_tab)

    def _build_sign_tab(self, parent) -> None:
        header = self.ttk.Label(parent, text="Giao diện ký số", font=("Arial", 16, "bold"))
        header.pack(anchor="w", padx=12, pady=(12, 6))

        owner_frame = self.ttk.Frame(parent)
        owner_frame.pack(fill="x", padx=12, pady=6)
        self.ttk.Label(owner_frame, text="Người ký:").pack(side="left")
        self.ttk.Entry(owner_frame, textvariable=self.sign_owner_var, width=20).pack(side="left", padx=6)
        self.ttk.Button(owner_frame, text="Tạo khóa", command=self._generate_keys_gui).pack(side="left", padx=6)
        self.ttk.Button(owner_frame, text="Tải fingerprint", command=self._load_sign_fingerprint).pack(side="left", padx=6)

        fp_frame = self.ttk.LabelFrame(parent, text="Fingerprint khóa công khai")
        fp_frame.pack(fill="x", padx=12, pady=6)
        self.ttk.Label(fp_frame, textvariable=self.sign_fp_var, wraplength=850).pack(anchor="w", padx=10, pady=10)

        message_frame = self.ttk.LabelFrame(parent, text="Nội dung tin nhắn")
        message_frame.pack(fill="both", expand=True, padx=12, pady=6)
        self.sign_message_text = self.scrolledtext.ScrolledText(message_frame, wrap=self.tk.WORD, height=12)
        self.sign_message_text.pack(fill="both", expand=True, padx=10, pady=10)

        digest_frame = self.ttk.LabelFrame(parent, text="Digest SHA-256")
        digest_frame.pack(fill="x", padx=12, pady=6)
        self.ttk.Label(digest_frame, textvariable=self.sign_digest_var, wraplength=850).pack(anchor="w", padx=10, pady=10)

        action_frame = self.ttk.Frame(parent)
        action_frame.pack(fill="x", padx=12, pady=8)
        self.ttk.Button(action_frame, text="Hiện Digest", command=self._show_sign_digest).pack(side="left", padx=4)
        self.ttk.Button(action_frame, text="Sign và lưu JSON", command=self._sign_and_save_gui).pack(side="left", padx=4)

    def _build_verify_tab(self, parent) -> None:
        header = self.ttk.Label(parent, text="Giao diện xác minh", font=("Arial", 16, "bold"))
        header.pack(anchor="w", padx=12, pady=(12, 6))

        package_frame = self.ttk.Frame(parent)
        package_frame.pack(fill="x", padx=12, pady=6)
        self.ttk.Label(package_frame, text="Tệp JSON:").pack(side="left")
        self.ttk.Entry(package_frame, textvariable=self.verify_package_var, width=70).pack(side="left", padx=6)
        self.ttk.Button(package_frame, text="Chọn file", command=self._browse_package).pack(side="left")

        pub_frame = self.ttk.Frame(parent)
        pub_frame.pack(fill="x", padx=12, pady=6)
        self.ttk.Label(pub_frame, text="Public Key PEM:").pack(side="left")
        self.ttk.Entry(pub_frame, textvariable=self.verify_pub_var, width=64).pack(side="left", padx=6)
        self.ttk.Button(pub_frame, text="Chọn key", command=self._browse_pub).pack(side="left")

        result_frame = self.ttk.LabelFrame(parent, text="Kết quả xác minh")
        result_frame.pack(fill="both", expand=True, padx=12, pady=8)

        self.ttk.Label(result_frame, text="Digest extracted from Signature:", font=("Arial", 11, "bold")).pack(anchor="w", padx=10, pady=(10, 2))
        self.ttk.Label(result_frame, textvariable=self.verify_digest_sig_var, wraplength=850).pack(anchor="w", padx=10)

        self.ttk.Label(result_frame, text="Digest recalculated from Message:", font=("Arial", 11, "bold")).pack(anchor="w", padx=10, pady=(10, 2))
        self.ttk.Label(result_frame, textvariable=self.verify_digest_msg_var, wraplength=850).pack(anchor="w", padx=10)

        self.status_label = self.ttk.Label(result_frame, textvariable=self.verify_status_var, font=("Arial", 12, "bold"))
        self.status_label.pack(anchor="w", padx=10, pady=(14, 10))

        action_frame = self.ttk.Frame(parent)
        action_frame.pack(fill="x", padx=12, pady=8)
        self.ttk.Button(action_frame, text="Verify", command=self._verify_gui).pack(side="left")

    def _generate_keys_gui(self) -> None:
        owner = self.sign_owner_var.get().strip()
        if not owner:
            self.messagebox.showwarning("Thiếu thông tin", "Vui lòng nhập tên người dùng.")
            return
        try:
            private_path, public_path, fingerprint = self.app.generate_keys(owner)
            self.sign_fp_var.set(fingerprint)
            self.messagebox.showinfo(
                "Thành công",
                f"Đã tạo khóa cho {owner}.\nPrivate: {private_path}\nPublic: {public_path}\nFingerprint: {fingerprint}",
            )
        except Exception as exc:
            self.messagebox.showerror("Lỗi", str(exc))

    def _load_sign_fingerprint(self) -> None:
        owner = self.sign_owner_var.get().strip()
        if not owner:
            self.messagebox.showwarning("Thiếu thông tin", "Vui lòng nhập tên người dùng.")
            return
        try:
            public_key = self.app.keystore.load_public_key(owner)
            fingerprint = FingerprintService.public_key_fingerprint(public_key)
            self.sign_fp_var.set(fingerprint)
        except Exception as exc:
            self.messagebox.showerror("Lỗi", str(exc))

    def _show_sign_digest(self) -> None:
        message = self.sign_message_text.get("1.0", self.tk.END).rstrip("\n")
        if not message:
            self.messagebox.showwarning("Thiếu dữ liệu", "Vui lòng nhập nội dung tin nhắn.")
            return
        self.sign_digest_var.set(DigestService.digest_hex(message))

    def _sign_and_save_gui(self) -> None:
        owner = self.sign_owner_var.get().strip()
        message = self.sign_message_text.get("1.0", self.tk.END).rstrip("\n")
        if not owner or not message:
            self.messagebox.showwarning("Thiếu dữ liệu", "Vui lòng nhập người ký và nội dung tin nhắn.")
            return

        output_path = self.filedialog.asksaveasfilename(
            title="Lưu gói JSON đã ký",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
        )
        if not output_path:
            return

        try:
            package = self.app.sign_to_file(owner, message, output_path)
            self.sign_fp_var.set(package.signer_fingerprint)
            self.sign_digest_var.set(DigestService.digest_hex(message))
            self.messagebox.showinfo("Thành công", f"Đã ký số và lưu JSON tại:\n{output_path}")
        except Exception as exc:
            self.messagebox.showerror("Lỗi", str(exc))

    def _browse_package(self) -> None:
        path = self.filedialog.askopenfilename(
            title="Chọn gói JSON",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
        )
        if path:
            self.verify_package_var.set(path)

    def _browse_pub(self) -> None:
        path = self.filedialog.askopenfilename(
            title="Chọn Public Key PEM",
            filetypes=[("PEM files", "*.pem"), ("All files", "*.*")],
        )
        if path:
            self.verify_pub_var.set(path)

    def _verify_gui(self) -> None:
        package_path = self.verify_package_var.get().strip()
        pub_path = self.verify_pub_var.get().strip()
        if not package_path or not pub_path:
            self.messagebox.showwarning("Thiếu dữ liệu", "Vui lòng chọn gói JSON và public key.")
            return

        try:
            result = self.app.verify_from_file(package_path, pub_path)
            self.verify_digest_sig_var.set(result.extracted_digest_hex)
            self.verify_digest_msg_var.set(result.recalculated_digest_hex)
            self.verify_status_var.set(result.status_message)
            self.status_label.configure(foreground="green")
        except Exception as exc:
            self.verify_digest_sig_var.set("Không trích xuất digest trực tiếp từ chữ ký khi dùng API verify an toàn.")
            try:
                content = self.app.files.read_text(package_path)
                package = SignedPackage.from_json(content)
                self.verify_digest_msg_var.set(DigestService.digest_hex(package.message, package.metadata.encoding))
            except Exception:
                self.verify_digest_msg_var.set("")
            self.verify_status_var.set(f"FAILED - DATA TAMPERED\n{exc}")
            self.status_label.configure(foreground="red")

    def run(self) -> None:
        self.root.mainloop()


class DigitalSignatureAppTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = TemporaryDirectory()
        self.base_path = Path(self.temp_dir.name)
        self.app = DigitalSignatureApp(self.base_path / "keystore")
        self.app.generate_keys("alice", 2048)
        self.app.generate_keys("bob", 2048)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_sign_and_verify_success(self) -> None:
        package_path = self.base_path / "signed.json"
        self.app.sign_to_file("alice", "Chuyen 1 trieu dong", package_path)
        result = self.app.verify_from_file(package_path, self.base_path / "keystore" / "public" / "alice_public.pem")
        self.assertTrue(result.is_valid)
        self.assertEqual(result.status_message, "VERIFIED - INTEGRITY GUARANTEED")

    def test_verify_fails_when_message_tampered(self) -> None:
        package = self.app.sign_to_package("alice", "Chuyen 1 trieu dong")
        tampered = SignedPackage(
            metadata=package.metadata,
            message="Chuyen 100 trieu dong",
            signature=package.signature,
            signer_fingerprint=package.signer_fingerprint,
        )
        public_key = self.app.keystore.load_public_key("alice")
        with self.assertRaises(VerificationError):
            self.app.signer.verify_package(tampered, public_key)

    def test_verify_fails_with_wrong_public_key(self) -> None:
        package_path = self.base_path / "signed.json"
        self.app.sign_to_file("alice", "Noi dung goc", package_path)
        with self.assertRaises(VerificationError):
            self.app.verify_from_file(package_path, self.base_path / "keystore" / "public" / "bob_public.pem")

    def test_invalid_base64_signature_raises(self) -> None:
        package = self.app.sign_to_package("alice", "Hello")
        broken = SignedPackage(
            metadata=package.metadata,
            message=package.message,
            signature="@@@invalid-base64@@@",
            signer_fingerprint=package.signer_fingerprint,
        )
        public_key = self.app.keystore.load_public_key("alice")
        with self.assertRaises(VerificationError):
            self.app.signer.verify_package(broken, public_key)

    def test_tk_check_returns_bool(self) -> None:
        self.assertIsInstance(is_tk_available(), bool)

    def test_main_without_args_returns_zero(self) -> None:
        buf = io.StringIO()
        with redirect_stdout(buf):
            exit_code = main([])
        self.assertEqual(exit_code, 0)
        self.assertIn("Quick Start:", buf.getvalue())

    def test_main_does_not_raise_system_exit(self) -> None:
        try:
            main([])
        except SystemExit as exc:  # pragma: no cover
            self.fail(f"main() không nên raise SystemExit nữa, nhưng đã raise: {exc}")


def print_quick_start() -> None:
    guide = textwrap.dedent(
        """
        Quick Start:
          1) Cài thư viện:  pip install pycryptodome
          2) Tạo khóa:      python digital_signature_app.py genkey alice
          3) Ký tin:        python digital_signature_app.py sign alice --message "Chuyen 1 trieu dong" --out signed.json
          4) Xác minh:      python digital_signature_app.py verify --package signed.json --pub keystore/public/alice_public.pem
          5) Chạy GUI:      python digital_signature_app.py gui
          6) Chạy test:     python digital_signature_app.py selftest

        Ghi chú:
          - Nếu môi trường không có tkinter, CLI vẫn hoạt động bình thường.
          - Lệnh gui sẽ báo lỗi rõ ràng thay vì làm chương trình crash khi import.
        """
    ).strip()
    print(guide)


def main(argv: Optional[list[str]] = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    if not argv:
        print_quick_start()
        return 0

    app = DigitalSignatureApp()
    cli = CLI(app)
    return cli.run(argv)


if __name__ == "__main__":
    main()
