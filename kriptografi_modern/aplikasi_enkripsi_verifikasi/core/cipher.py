"""Modul enkripsi dan dekripsi XOR Multi-Byte pada level byte UTF-8.

Diadaptasi dan disempurnakan dari implementasi awal pada fitur1.py agar
mendukung validasi input menyeluruh, encoding Hexadecimal dan Base64, serta
dekripsi aman ke bytes tanpa memicu crash UnicodeDecodeError.
"""

from __future__ import annotations

import base64
import binascii

SUPPORTED_ENCODINGS = ("hex", "base64")
_HEX_CHARS = set("0123456789abcdefABCDEF")


def _normalize_encoding(encoding: str) -> str:
    """Memvalidasi dan menormalkan nama encoding keluaran/masukan."""
    if not isinstance(encoding, str):
        raise ValueError("Format encoding harus berupa string.")
    normalized = encoding.strip().lower()
    if normalized not in SUPPORTED_ENCODINGS:
        raise ValueError(
            f"Encoding '{encoding}' tidak didukung. Gunakan 'hex' atau 'base64'."
        )
    return normalized


def xor_bytes(data: bytes, key: bytes) -> bytes:
    """Menerapkan operasi bitwise XOR antara byte data dan kunci dengan key cycling.

    Args:
        data: Urutan byte masukan yang akan di-XOR.
        key: Urutan byte kunci rahasia.

    Returns:
        Byte hasil operasi XOR dengan panjang sama dengan ``data``.

    Raises:
        TypeError: Jika ``data`` atau ``key`` bukan bertipe bytes/bytearray.
        ValueError: Jika ``data`` atau ``key`` kosong.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("Parameter data harus bertipe bytes.")
    if not isinstance(key, (bytes, bytearray)):
        raise TypeError("Parameter key harus bertipe bytes.")
    if len(data) == 0:
        raise ValueError("Data byte tidak boleh kosong.")
    if len(key) == 0:
        raise ValueError("Kunci byte tidak boleh kosong.")

    key_len = len(key)
    return bytes(b ^ key[idx % key_len] for idx, b in enumerate(data))


def encrypt_text(plaintext: str, key: str, encoding: str = "hex") -> str:
    """Mengenkripsi plaintext UTF-8 menggunakan XOR Multi-Byte menjadi string terenkode.

    Args:
        plaintext: Teks asli yang akan dienkripsi.
        key: Kunci rahasia UTF-8.
        encoding: Format representasi ciphertext, ``'hex'`` (default) atau ``'base64'``.

    Returns:
        String ciphertext dalam format Hexadecimal atau Base64.

    Raises:
        ValueError: Jika plaintext kosong/hanya spasi, key kosong, atau encoding tidak valid.
    """
    if not isinstance(plaintext, str) or plaintext.strip() == "":
        raise ValueError("Plaintext tidak boleh kosong atau hanya berisi spasi.")
    if not isinstance(key, str) or key == "":
        raise ValueError("Kunci rahasia tidak boleh kosong.")

    encoding_norm = _normalize_encoding(encoding)
    plain_bytes = plaintext.encode("utf-8")
    key_bytes = key.encode("utf-8")
    cipher_bytes = xor_bytes(plain_bytes, key_bytes)

    if encoding_norm == "hex":
        return cipher_bytes.hex()
    return base64.b64encode(cipher_bytes).decode("ascii")


def decrypt_to_bytes(ciphertext: str, key: str, encoding: str = "hex") -> bytes:
    """Mendekripsi ciphertext (Hex atau Base64) menjadi byte mentah hasil XOR.

    Fungsi ini mengembalikan ``bytes`` (bukan ``str``) sehingga tidak akan
    mengalami ``UnicodeDecodeError`` ketika kunci salah atau ciphertext dimanipulasi.

    Args:
        ciphertext: String ciphertext dalam format Hex atau Base64.
        key: Kunci rahasia UTF-8.
        encoding: Format representasi ciphertext (``'hex'`` atau ``'base64'``).

    Returns:
        Byte mentah hasil dekripsi XOR.

    Raises:
        ValueError: Jika ciphertext kosong, key kosong, encoding salah,
            atau format Hex/Base64 tidak valid.
    """
    if not isinstance(ciphertext, str) or ciphertext.strip() == "":
        raise ValueError("Ciphertext tidak boleh kosong.")
    if not isinstance(key, str) or key == "":
        raise ValueError("Kunci rahasia tidak boleh kosong.")

    encoding_norm = _normalize_encoding(encoding)
    cleaned = ciphertext.strip()

    if encoding_norm == "hex":
        if len(cleaned) % 2 != 0 or any(ch not in _HEX_CHARS for ch in cleaned):
            raise ValueError(
                "Format ciphertext Hexadecimal tidak valid "
                "(harus panjang genap dan hanya karakter 0-9, a-f)."
            )
        try:
            cipher_bytes = bytes.fromhex(cleaned)
        except ValueError as err:
            raise ValueError(
                "Format ciphertext Hexadecimal tidak valid."
            ) from err
    else:
        try:
            cipher_bytes = base64.b64decode(
                cleaned.encode("ascii"), validate=True
            )
        except (binascii.Error, ValueError, UnicodeEncodeError) as err:
            raise ValueError(
                "Format ciphertext Base64 tidak valid."
            ) from err

    if len(cipher_bytes) == 0:
        raise ValueError("Ciphertext tidak menghasilkan data byte yang valid.")

    key_bytes = key.encode("utf-8")
    return xor_bytes(cipher_bytes, key_bytes)


def decode_utf8_safe(data: bytes) -> tuple[bool, str]:
    """Mencoba mendekode bytes menjadi string UTF-8 secara aman tanpa crash.

    Returns:
        Tuple ``(is_valid_utf8, text_or_error_info)``.
    """
    try:
        return True, data.decode("utf-8")
    except UnicodeDecodeError:
        return False, ""
