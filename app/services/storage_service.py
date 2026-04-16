"""Storage service: simple file read/write helpers."""
from __future__ import annotations

from pathlib import Path

from app.exceptions import CryptoAppError


def save_text(path: Path | str, content: str) -> None:
    """Write *content* to *path* as UTF-8 text."""
    file_path = Path(path)
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_text(content, encoding="utf-8")


def read_text(path: Path | str) -> str:
    """Read and return UTF-8 text from *path*.

    Raises:
        CryptoAppError: if the file does not exist.
    """
    file_path = Path(path)
    if not file_path.exists():
        raise CryptoAppError(f"Không tìm thấy tệp: {file_path}")
    return file_path.read_text(encoding="utf-8")
