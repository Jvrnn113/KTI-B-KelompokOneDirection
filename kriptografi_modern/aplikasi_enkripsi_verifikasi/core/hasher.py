"""Modul hashing SHA-256 dan verifikasi integritas data.

Diadaptasi dan disempurnakan dari implementasi awal pada fitur2.py agar
mendukung masukan ``str`` maupun ``bytes`` serta perbandingan digest aman
menggunakan ``hmac.compare_digest``.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Union

STATUS_VALID = "DATA VALID"
STATUS_MODIFIED = "DATA TELAH DIMODIFIKASI"
_HEX_CHARS = set("0123456789abcdefABCDEF")


def is_valid_sha256_hex(hash_value: str) -> bool:
    """Memeriksa apakah string merupakan hash SHA-256 64 karakter hex yang valid."""
    return (
        isinstance(hash_value, str)
        and len(hash_value) == 64
        and all(ch in _HEX_CHARS for ch in hash_value)
    )


def compute_sha256(data: Union[str, bytes]) -> str:
    """Menghitung nilai digest SHA-256 (64 karakter hex lowercase).

    Args:
        data: Pesan berupa ``str`` (di-encode UTF-8) atau ``bytes``.

    Returns:
        String 64 karakter heksadesimal huruf kecil.

    Raises:
        TypeError: Jika ``data`` bukan ``str`` maupun ``bytes``.
    """
    if isinstance(data, str):
        payload = data.encode("utf-8")
    elif isinstance(data, (bytes, bytearray)):
        payload = bytes(data)
    else:
        raise TypeError("Data untuk hashing harus bertipe str atau bytes.")

    return hashlib.sha256(payload).hexdigest()


def verify_integrity(
    original_hash: str, decrypted_bytes: bytes
) -> tuple[bool, str]:
    """Memverifikasi integritas byte hasil dekripsi terhadap hash SHA-256 awal.

    Args:
        original_hash: Hash SHA-256 metadata asli (64 karakter hex).
        decrypted_bytes: Byte mentah hasil dekripsi.

    Returns:
        Tuple ``(is_valid, decrypted_hash)`` di mana ``is_valid`` bernilai
        ``True`` jika hash cocok 100% menggunakan perbandingan constant-time.

    Raises:
        TypeError: Jika ``decrypted_bytes`` bukan bytes/bytearray.
        ValueError: Jika ``original_hash`` kosong atau bukan format 64 hex.
    """
    if not isinstance(original_hash, str) or original_hash.strip() == "":
        raise ValueError("Hash asli (original_hash) tidak boleh kosong.")
    normalized_original = original_hash.strip().lower()
    if not is_valid_sha256_hex(normalized_original):
        raise ValueError(
            "Format original_hash tidak valid (harus 64 karakter heksadesimal SHA-256)."
        )
    if not isinstance(decrypted_bytes, (bytes, bytearray)):
        raise TypeError("Parameter decrypted_bytes harus bertipe bytes.")

    decrypted_hash = compute_sha256(bytes(decrypted_bytes))
    is_valid = hmac.compare_digest(normalized_original, decrypted_hash.lower())
    return is_valid, decrypted_hash


def get_integrity_status(is_valid: bool) -> str:
    """Mengembalikan label status integritas standar sesuai PRD."""
    return STATUS_VALID if is_valid else STATUS_MODIFIED


def calculate_bit_difference(hash1_hex: str, hash2_hex: str) -> tuple[int, int, float]:
    """Menghitung jumlah dan persentase perbedaan bit antara dua hash SHA-256.

    Digunakan pada simulasi Avalanche Effect untuk memperlihatkan perubahan
    drastis pada digest meskipun masukan hanya berbeda 1 karakter.

    Returns:
        Tuple ``(diff_bits, total_bits, percentage)``.
    """
    h1 = hash1_hex.strip().lower()
    h2 = hash2_hex.strip().lower()
    if not is_valid_sha256_hex(h1) or not is_valid_sha256_hex(h2):
        raise ValueError("Kedua hash harus berupa 64 karakter heksadesimal SHA-256.")

    val1 = int(h1, 16)
    val2 = int(h2, 16)
    diff_bits = bin(val1 ^ val2).count("1")
    total_bits = 256
    percentage = (diff_bits / total_bits) * 100.0
    return diff_bits, total_bits, percentage
