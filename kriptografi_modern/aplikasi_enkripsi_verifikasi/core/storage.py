"""Modul penyimpanan dan pembacaan file teks (.txt) serta paket metadata (.json).

Menyelaraskan penyimpanan metadata dari fitur2.py ke skema JSON standar PRD:
``algorithm``, ``encoding``, ``ciphertext``, ``original_hash``, ``created_at``.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any

from core.cipher import SUPPORTED_ENCODINGS
from core.hasher import is_valid_sha256_hex

ALGORITHM_NAME = "XOR-MultiByte"
REQUIRED_FIELDS = ("algorithm", "encoding", "ciphertext", "original_hash")


def save_package(
    filepath: str, ciphertext: str, original_hash: str, encoding: str
) -> str:
    """Menyimpan paket ciphertext dan metadata integritas ke file JSON.

    Membuat parent directory secara otomatis jika belum tersedia.

    Args:
        filepath: Lokasi file JSON tujuan.
        ciphertext: String ciphertext hasil enkripsi.
        original_hash: Hash SHA-256 pesan asli (64 karakter hex).
        encoding: Format encoding ciphertext (``'hex'`` atau ``'base64'``).

    Returns:
        Path absolut file yang tersimpan sebagai string.

    Raises:
        ValueError: Jika parameter tidak valid atau kosong.
        OSError: Jika gagal menulis ke disk (misal izin ditolak).
    """
    if not isinstance(filepath, str) or filepath.strip() == "":
        raise ValueError("Path file tujuan tidak boleh kosong.")
    if not isinstance(ciphertext, str) or ciphertext.strip() == "":
        raise ValueError("Ciphertext tidak boleh kosong.")
    if not isinstance(encoding, str):
        raise ValueError("Encoding tidak boleh kosong.")

    encoding_norm = encoding.strip().lower()
    if encoding_norm not in SUPPORTED_ENCODINGS:
        raise ValueError(
            f"Encoding '{encoding}' tidak valid. Harus 'hex' atau 'base64'."
        )

    hash_norm = original_hash.strip().lower() if isinstance(original_hash, str) else ""
    if not is_valid_sha256_hex(hash_norm):
        raise ValueError(
            "original_hash harus berupa 64 karakter heksadesimal SHA-256 yang valid."
        )

    target = Path(filepath.strip())
    if target.exists() and target.is_dir():
        raise ValueError(f"Path tujuan adalah direktori, bukan file: {target}")

    target.parent.mkdir(parents=True, exist_ok=True)
    package = {
        "algorithm": ALGORITHM_NAME,
        "encoding": encoding_norm,
        "ciphertext": ciphertext.strip(),
        "original_hash": hash_norm,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    target.write_text(
        json.dumps(package, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return str(target.resolve())


def load_package(filepath: str) -> dict[str, Any]:
    """Membaca dan memvalidasi paket data terenkripsi dari file JSON.

    Args:
        filepath: Path menuju file paket JSON.

    Returns:
        Dictionary paket yang telah tervalidasi.

    Raises:
        FileNotFoundError: Jika file tidak ditemukan.
        ValueError: Jika JSON korup, struktur salah, field wajib hilang,
            encoding tidak valid, atau format hash tidak valid.
        OSError: Jika terjadi kesalahan pembacaan file (misal permission error).
    """
    if not isinstance(filepath, str) or filepath.strip() == "":
        raise ValueError("Path file paket JSON tidak boleh kosong.")

    target = Path(filepath.strip())
    if not target.exists():
        raise FileNotFoundError(f"File paket JSON tidak ditemukan: {target}")
    if not target.is_file():
        raise ValueError(f"Path bukan merupakan file yang valid: {target}")

    try:
        raw_content = target.read_text(encoding="utf-8")
    except UnicodeDecodeError as err:
        raise ValueError(
            f"File '{target}' bukan file teks UTF-8 yang valid."
        ) from err

    try:
        data = json.loads(raw_content)
    except json.JSONDecodeError as err:
        raise ValueError(f"Format JSON pada '{target}' rusak/tidak valid: {err}") from err

    if not isinstance(data, dict):
        raise ValueError("Isi file JSON harus berupa objek/dictionary.")

    missing = [field for field in REQUIRED_FIELDS if field not in data]
    if missing:
        raise ValueError(
            f"Field wajib tidak lengkap pada file JSON: {', '.join(missing)}."
        )

    for field in REQUIRED_FIELDS:
        if not isinstance(data[field], str) or data[field].strip() == "":
            raise ValueError(
                f"Field '{field}' harus berupa string dan tidak boleh kosong."
            )

    encoding_norm = data["encoding"].strip().lower()
    if encoding_norm not in SUPPORTED_ENCODINGS:
        raise ValueError(
            f"Nilai encoding '{data['encoding']}' tidak valid. "
            "Harus 'hex' atau 'base64'."
        )

    hash_norm = data["original_hash"].strip().lower()
    if not is_valid_sha256_hex(hash_norm):
        raise ValueError(
            "Field 'original_hash' harus berupa 64 karakter heksadesimal SHA-256."
        )

    normalized = dict(data)
    normalized["algorithm"] = data["algorithm"].strip()
    normalized["encoding"] = encoding_norm
    normalized["ciphertext"] = data["ciphertext"].strip()
    normalized["original_hash"] = hash_norm
    return normalized


def read_text_file(filepath: str) -> str:
    """Membaca isi file teks UTF-8 untuk dijadikan input pesan.

    Args:
        filepath: Path menuju file ``.txt``.

    Returns:
        Konten teks dari file.

    Raises:
        FileNotFoundError: Jika file tidak ditemukan.
        ValueError: Jika path kosong, bukan file, gagal decode UTF-8, atau file kosong.
        OSError: Jika gagal membaca file karena masalah izin akses.
    """
    if not isinstance(filepath, str) or filepath.strip() == "":
        raise ValueError("Path file teks tidak boleh kosong.")

    target = Path(filepath.strip())
    if not target.exists():
        raise FileNotFoundError(f"File teks tidak ditemukan: {target}")
    if not target.is_file():
        raise ValueError(f"Path bukan merupakan file yang valid: {target}")

    try:
        content = target.read_text(encoding="utf-8")
    except UnicodeDecodeError as err:
        raise ValueError(
            f"File '{target}' tidak dapat dibaca sebagai teks UTF-8."
        ) from err

    if content.strip() == "":
        raise ValueError("Isi file teks kosong atau hanya berisi spasi.")

    return content
