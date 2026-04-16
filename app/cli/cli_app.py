"""CLI entry point for the Digital Signature Application.

This module is imported by ``main.py`` and provides the ``main()`` function
that is the single unified entry point for the entire application:
genkey, sign, verify, gui, and selftest commands.
"""
from __future__ import annotations

import argparse
import sys
import textwrap
import unittest
from typing import Optional

from app.constants import APP_NAME, DEFAULT_KEY_SIZE
from app.core.engine import DigitalSignatureApp
from app.exceptions import CryptoAppError
from app.services import crypto_service


# ---------------------------------------------------------------------------
# Quick-start banner (shown when no arguments are given)
# ---------------------------------------------------------------------------

def _print_quick_start() -> None:
    guide = textwrap.dedent(
        """\
        Quick Start:
          1) Cài thư viện:  pip install pycryptodome
          2) Tạo khóa:      python main.py genkey user1
          3) Ký tin:        python main.py sign user1 --message "Chuyen 1 trieu dong" --out signed.json
          4) Xác minh:      python main.py verify --package signed.json --pub keystore/public/user1_public.pem
          5) Chạy GUI:      python main.py gui
          6) Chạy test:     python main.py selftest

        Ghi chú:
          - Nếu môi trường không có tkinter, CLI vẫn hoạt động bình thường.
          - Lệnh gui sẽ báo lỗi rõ ràng thay vì làm chương trình crash khi import.
        """
    )
    print(guide.rstrip())


# ---------------------------------------------------------------------------
# Tkinter availability check
# ---------------------------------------------------------------------------

def _is_tk_available() -> bool:
    try:
        import tkinter  # noqa: F401
        from tkinter import filedialog, messagebox, scrolledtext, ttk  # noqa: F401
        return True
    except ModuleNotFoundError:
        return False


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="main.py",
        description="Ứng dụng chữ ký số OOP bằng Python dùng RSA-3072 + SHA-256.",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # genkey
    gen_parser = subparsers.add_parser("genkey", help="Tạo cặp khóa RSA cho người dùng")
    gen_parser.add_argument("owner", help="Tên người dùng, ví dụ: user1")
    gen_parser.add_argument(
        "--size", type=int, default=DEFAULT_KEY_SIZE,
        help="Kích thước khóa, mặc định 3072",
    )

    # sign
    sign_parser = subparsers.add_parser("sign", help="Ký một thông điệp và xuất JSON")
    sign_parser.add_argument("owner", help="Tên người dùng sở hữu private key")
    sign_parser.add_argument("--message", required=True, help="Nội dung tin nhắn cần ký")
    sign_parser.add_argument("--out", default="signed_message.json", help="Đường dẫn tệp JSON đầu ra")

    # verify
    verify_parser = subparsers.add_parser("verify", help="Xác minh gói JSON bằng public key")
    verify_parser.add_argument("--package", required=True, help="Đường dẫn tới tệp JSON đã ký")
    verify_parser.add_argument("--pub", required=True, help="Đường dẫn tới public key PEM")

    # gui
    gui_parser = subparsers.add_parser("gui", help="Mở giao diện Tkinter nếu môi trường hỗ trợ")
    gui_parser.add_argument("--owner", default="user1", help="Người dùng mặc định trên giao diện ký")

    # selftest
    subparsers.add_parser("selftest", help="Chạy bộ kiểm thử tích hợp nội bộ")

    return parser


# ---------------------------------------------------------------------------
# Command dispatch
# ---------------------------------------------------------------------------

def _run(app: DigitalSignatureApp, args: argparse.Namespace) -> int:
    """Execute the parsed command. Returns an exit code (0 = success)."""

    if args.command == "genkey":
        private_path, public_path, fingerprint = app.generate_keys(args.owner, args.size)
        print("Tạo khóa thành công")
        print(f"Private Key : {private_path}")
        print(f"Public Key  : {public_path}")
        print(f"Fingerprint : {fingerprint}")
        return 0

    if args.command == "sign":
        package = app.sign_to_file(args.owner, args.message, args.out)
        print("Ký số thành công")
        print(f"Output      : {args.out}")
        print(f"Fingerprint : {package.signer_fingerprint}")
        print(f"Digest      : {crypto_service.digest_hex(args.message)}")
        return 0

    if args.command == "verify":
        from app.services import storage_service
        from app.models.signed_package import SignedPackage
        message_content = ""
        try:
            content = storage_service.read_text(args.package)
            pkg = SignedPackage.from_json(content)
            message_content = pkg.message
        except Exception:
            pass

        try:
            result = app.verify_from_file(args.package, args.pub)
            print("Xác minh thành công")
            print(f"Status        : {result.status_message}")
            print(f"Message Digest: {result.message_digest_hex}")
            print("\n--- NỘI DUNG TIN NHẮN (ĐÁNG TIN CẬY) ---")
            print(message_content)
            print("----------------------------------------")
            return 0
        except CryptoAppError as exc:
            print(f"Lỗi xác minh: {exc}")
            if message_content:
                print("\n--- NỘI DUNG TIN NHẮN (CẢNH BÁO: KHÔNG ĐÁNG TIN CẬY / BỊ THAY ĐỔI) ---")
                print(message_content)
                print("----------------------------------------------------------------------")
            return 1

    if args.command == "gui":
        if not _is_tk_available():
            raise CryptoAppError(
                "Môi trường hiện tại không hỗ trợ tkinter nên không thể mở GUI. "
                "Hãy dùng CLI hoặc chạy trên máy có cài tkinter."
            )
        from app.gui.main_window import AppGUI
        gui = AppGUI(app, default_owner=args.owner)
        gui.run()
        return 0

    if args.command == "selftest":
        from tests.test_signature_flow import SignatureFlowTests
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(SignatureFlowTests)
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        return 0 if result.wasSuccessful() else 1

    return 0


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def main(argv: Optional[list[str]] = None) -> int:
    """Unified entry point. Returns an integer exit code (never calls sys.exit)."""
    argv = argv if argv is not None else sys.argv[1:]

    if not argv:
        if _is_tk_available():
            argv = ["gui"]
        else:
            _print_quick_start()
            return 0

    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        app = DigitalSignatureApp()
        return _run(app, args)
    except CryptoAppError as exc:
        print(f"Lỗi: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:  # pragma: no cover
        print(f"Lỗi không mong muốn: {exc}", file=sys.stderr)
        return 2
