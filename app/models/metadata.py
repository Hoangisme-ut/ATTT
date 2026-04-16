"""Data models: Metadata."""
from __future__ import annotations

from dataclasses import dataclass

from app.constants import DEFAULT_ENCODING, DEFAULT_HASH_ALGORITHM, DEFAULT_SIGNATURE_SCHEME


@dataclass
class Metadata:
    """Package metadata describing encoding and cryptographic algorithms used."""

    encoding: str = DEFAULT_ENCODING
    hash_algorithm: str = DEFAULT_HASH_ALGORITHM
    signature_scheme: str = DEFAULT_SIGNATURE_SCHEME
