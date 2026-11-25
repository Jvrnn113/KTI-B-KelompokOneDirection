from datetime import datetime, timezone
import hashlib


def hitung_sha256(pesan: str) -> str:
    """Menghitung digest SHA-256 (64 karakter hex) dari teks UTF-8."""
    if not isinstance(pesan, str):
        raise TypeError("Pesan harus berupa string.")
    if pesan.strip() == "":
        raise ValueError("Pesan tidak boleh kosong atau hanya spasi.")
    return hashlib.sha256(pesan.encode("utf-8")).hexdigest()


def buat_metadata_integritas(pesan_asli: str) -> dict:
    """Membungkus nilai hash SHA-256 pesan asli ke dalam metadata."""
    digest = hitung_sha256(pesan_asli)
    return {
        "algoritma": "SHA-256",
        "hash_sha256": digest,
        "panjang_pesan": len(pesan_asli),
        "dibuat_pada": datetime.now(timezone.utc).isoformat(),
    }
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path


def hitung_sha256(pesan: str) -> str:
    """Menghitung digest SHA-256 (64 karakter hex) dari teks UTF-8."""
    if not isinstance(pesan, str):
        raise TypeError("Pesan harus berupa string.")
    if pesan.strip() == "":
        raise ValueError("Pesan tidak boleh kosong atau hanya spasi.")
    return hashlib.sha256(pesan.encode("utf-8")).hexdigest()


def buat_metadata_integritas(pesan_asli: str) -> dict:
    """Membungkus nilai hash SHA-256 pesan asli ke dalam metadata."""
    digest = hitung_sha256(pesan_asli)
    return {
        "algoritma": "SHA-256",
        "hash_sha256": digest,
        "panjang_pesan": len(pesan_asli),
        "dibuat_pada": datetime.now(timezone.utc).isoformat(),
    }


def simpan_metadata_json(metadata: dict, path_file: str = "metadata_integritas.json") -> Path:
    """Menyimpan metadata hash ke file JSON agar bisa dibaca ulang saat validasi."""
    target = Path(path_file)
    target.write_text(json.dumps(metadata, indent=2, ensure_ascii=False), encoding="utf-8")
    return target


def muat_metadata_json(path_file: str = "metadata_integritas.json") -> dict:
    """Membaca kembali metadata hash dari file JSON."""
    target = Path(path_file)
    if not target.exists():
        raise FileNotFoundError(f"File metadata tidak ditemukan: {target}")
    return json.loads(target.read_text(encoding="utf-8"))


if __name__ == "__main__":
    teks_uji = input("Masukkan pesan asli untuk di-hash: ")
    try:
        meta = buat_metadata_integritas(teks_uji)
        file_tersimpan = simpan_metadata_json(meta)
        print("\nMetadata integritas berhasil dibuat:")
        print(json.dumps(meta, indent=2, ensure_ascii=False))
        print(f"Tersimpan di: {file_tersimpan}")
    except (TypeError, ValueError, OSError) as err:
        print(f"Gagal memproses integritas: {err}")