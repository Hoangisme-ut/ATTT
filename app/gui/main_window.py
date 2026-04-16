"""Tkinter GUI for the Digital Signature Application.

This module is imported **lazily** (only when the ``gui`` command is used)
so that the rest of the application works fine without tkinter installed.
"""
from __future__ import annotations

from app.constants import APP_NAME
from app.core.engine import DigitalSignatureApp
from app.exceptions import CryptoAppError
from app.models.signed_package import SignedPackage
from app.services import crypto_service


def _is_tk_available() -> bool:
    try:
        import tkinter  # noqa: F401
        return True
    except ModuleNotFoundError:
        return False


class AppGUI:
    """Two-tab Tkinter GUI: Sign tab + Verify tab."""

    def __init__(self, app: DigitalSignatureApp, default_owner: str = "user1") -> None:
        if not _is_tk_available():
            raise CryptoAppError(
                "Không thể khởi tạo GUI vì tkinter không có sẵn trong môi trường này."
            )

        import tkinter as tk
        from tkinter import filedialog, messagebox, scrolledtext, ttk

        self.tk = tk
        self.filedialog = filedialog
        self.messagebox = messagebox
        self.scrolledtext = scrolledtext
        self.ttk = ttk

        self.app = app
        self.default_owner = default_owner

        # ---- Main window ----
        self.root = tk.Tk()
        self.root.title(APP_NAME)
        self.root.geometry("980x700")
        self.root.minsize(900, 620)

        # ---- Tkinter variables ----
        self.sign_owner_var = tk.StringVar(value=default_owner)
        self.verify_pub_var = tk.StringVar()
        self.verify_package_var = tk.StringVar()
        self.sign_fp_var = tk.StringVar(value="Chưa có fingerprint")
        self.sign_digest_var = tk.StringVar(value="Mã băm (Digest) sẽ hiển thị tại đây")
        self.verify_status_var = tk.StringVar(value="Chưa xác minh")
        self.verify_digest_msg_var = tk.StringVar(value="")

        self._build_ui()

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

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

        # Owner row
        owner_frame = self.ttk.Frame(parent)
        owner_frame.pack(fill="x", padx=12, pady=6)
        self.ttk.Label(owner_frame, text="Người ký:").pack(side="left")
        self.ttk.Entry(owner_frame, textvariable=self.sign_owner_var, width=20).pack(side="left", padx=6)
        self.ttk.Button(owner_frame, text="Tạo khóa", command=self._generate_keys_gui).pack(side="left", padx=6)
        self.ttk.Button(owner_frame, text="Tải fingerprint", command=self._load_sign_fingerprint).pack(side="left", padx=6)

        # Fingerprint display
        fp_frame = self.ttk.LabelFrame(parent, text="Fingerprint khóa công khai")
        fp_frame.pack(fill="x", padx=12, pady=6)
        self.ttk.Label(fp_frame, textvariable=self.sign_fp_var, wraplength=850).pack(anchor="w", padx=10, pady=10)

        # Message input
        message_frame = self.ttk.LabelFrame(parent, text="Nội dung tin nhắn")
        message_frame.pack(fill="both", expand=True, padx=12, pady=6)
        self.sign_message_text = self.scrolledtext.ScrolledText(message_frame, wrap=self.tk.WORD, height=12)
        self.sign_message_text.pack(fill="both", expand=True, padx=10, pady=10)

        # Digest display
        digest_frame = self.ttk.LabelFrame(parent, text="Digest SHA-256")
        digest_frame.pack(fill="x", padx=12, pady=6)
        self.ttk.Label(digest_frame, textvariable=self.sign_digest_var, wraplength=850).pack(anchor="w", padx=10, pady=10)

        # Action buttons
        action_frame = self.ttk.Frame(parent)
        action_frame.pack(fill="x", padx=12, pady=8)
        self.ttk.Button(action_frame, text="Hiện Digest", command=self._show_sign_digest).pack(side="left", padx=4)
        self.ttk.Button(action_frame, text="Sign và lưu JSON", command=self._sign_and_save_gui).pack(side="left", padx=4)

    def _build_verify_tab(self, parent) -> None:
        header = self.ttk.Label(parent, text="Giao diện xác minh", font=("Arial", 16, "bold"))
        header.pack(anchor="w", padx=12, pady=(12, 6))

        # Package path
        package_frame = self.ttk.Frame(parent)
        package_frame.pack(fill="x", padx=12, pady=6)
        self.ttk.Label(package_frame, text="Tệp JSON:").pack(side="left")
        self.ttk.Entry(package_frame, textvariable=self.verify_package_var, width=70).pack(side="left", padx=6)
        self.ttk.Button(package_frame, text="Chọn file", command=self._browse_package).pack(side="left")

        # Public key path
        pub_frame = self.ttk.Frame(parent)
        pub_frame.pack(fill="x", padx=12, pady=6)
        self.ttk.Label(pub_frame, text="Public Key PEM:").pack(side="left")
        self.ttk.Entry(pub_frame, textvariable=self.verify_pub_var, width=64).pack(side="left", padx=6)
        self.ttk.Button(pub_frame, text="Chọn key", command=self._browse_pub).pack(side="left")

        # Receiver Message Display
        msg_frame = self.ttk.LabelFrame(parent, text="Nội dung tin nhắn trong gói JSON")
        msg_frame.pack(fill="both", expand=True, padx=12, pady=6)
        self.verify_message_text = self.scrolledtext.ScrolledText(msg_frame, wrap=self.tk.WORD, height=6)
        self.verify_message_text.pack(fill="both", expand=True, padx=10, pady=10)
        self.verify_message_text.insert("1.0", "Nội dung sẽ hiển thị tại đây sau khi xác minh...")
        self.verify_message_text.config(state="disabled")

        # Result display
        result_frame = self.ttk.LabelFrame(parent, text="Kết quả xác minh")
        result_frame.pack(fill="both", expand=True, padx=12, pady=8)

        self.ttk.Label(result_frame, text="Mã băm (Digest) SHA-256 (Tính từ nội dung gói JSON):", font=("Arial", 11, "bold")).pack(anchor="w", padx=10, pady=(10, 2))
        self.ttk.Label(result_frame, textvariable=self.verify_digest_msg_var, wraplength=850).pack(anchor="w", padx=10)

        self.status_label = self.ttk.Label(result_frame, textvariable=self.verify_status_var, font=("Arial", 12, "bold"))
        self.status_label.pack(anchor="w", padx=10, pady=(14, 10))

        # Action buttons
        action_frame = self.ttk.Frame(parent)
        action_frame.pack(fill="x", padx=12, pady=8)
        self.ttk.Button(action_frame, text="Verify", command=self._verify_gui).pack(side="left")

    # ------------------------------------------------------------------
    # Event handlers — Sign tab
    # ------------------------------------------------------------------

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
            fingerprint = crypto_service.public_key_fingerprint(public_key)
            self.sign_fp_var.set(fingerprint)
        except Exception as exc:
            self.messagebox.showerror("Lỗi", str(exc))

    def _show_sign_digest(self) -> None:
        message = self.sign_message_text.get("1.0", self.tk.END).rstrip("\n")
        if not message:
            self.messagebox.showwarning("Thiếu dữ liệu", "Vui lòng nhập nội dung tin nhắn.")
            return
        self.sign_digest_var.set(crypto_service.digest_hex(message))

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
            self.sign_digest_var.set(crypto_service.digest_hex(message))
            self.messagebox.showinfo("Thành công", f"Đã ký số và lưu JSON tại:\n{output_path}")
        except Exception as exc:
            self.messagebox.showerror("Lỗi", str(exc))

    # ------------------------------------------------------------------
    # Event handlers — Verify tab
    # ------------------------------------------------------------------

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

        self.verify_message_text.config(state="normal")
        self.verify_message_text.delete("1.0", self.tk.END)

        message_content = ""
        from app.services import storage_service
        from app.models.signed_package import SignedPackage
        try:
            content = storage_service.read_text(package_path)
            pkg = SignedPackage.from_json(content)
            message_content = pkg.message
        except Exception:
            self.verify_message_text.insert("1.0", "(Không đọc được gói JSON để lấy tin nhắn)")

        try:
            result = self.app.verify_from_file(package_path, pub_path)
            self.verify_digest_msg_var.set(result.message_digest_hex)
            self.verify_status_var.set(result.status_message)
            self.status_label.configure(foreground="green")
            
            if message_content:
                self.verify_message_text.insert("1.0", message_content)
                self.verify_message_text.insert(self.tk.END, "\n\n[ĐÁNG TIN CẬY - TÍNH TOÀN VẸN ĐƯỢC ĐẢM BẢO]")
                
        except Exception as exc:
            if message_content:
                self.verify_message_text.insert("1.0", message_content)
                self.verify_message_text.insert(self.tk.END, "\n\n[CẢNH BÁO: KHÔNG ĐÁNG TIN CẬY / BỊ THAY ĐỔI / SAI KHÓA]")
                try:
                    self.verify_digest_msg_var.set(
                        crypto_service.digest_hex(pkg.message, pkg.metadata.encoding)
                    )
                except Exception:
                    self.verify_digest_msg_var.set("(Không tính được Digest)")
            else:
                self.verify_digest_msg_var.set("(Không đọc được gói JSON)")
            
            self.verify_status_var.set(f"THẤT BẠI - XÁC MINH KHÔNG THÀNH CÔNG\n{exc}")
            self.status_label.configure(foreground="red")
            
        self.verify_message_text.config(state="disabled")

    # ------------------------------------------------------------------
    # Run
    # ------------------------------------------------------------------

    def run(self) -> None:
        self.root.mainloop()
