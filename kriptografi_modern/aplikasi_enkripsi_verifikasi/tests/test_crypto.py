"""Unit test komprehensif untuk CryptoVerify CLI menggunakan unittest."""

from __future__ import annotations

import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from cli.controller import CLIController, tamper_ciphertext
from core.cipher import decode_utf8_safe, decrypt_to_bytes, encrypt_text, xor_bytes
from core.hasher import (
    STATUS_MODIFIED,
    STATUS_VALID,
    calculate_bit_difference,
    compute_sha256,
    get_integrity_status,
    verify_integrity,
)
from core.storage import ALGORITHM_NAME, load_package, read_text_file, save_package


class TestCryptoVerifyCore(unittest.TestCase):
    """Pengujian unit untuk modul core (cipher, hasher, storage) dan CLI."""

    def test_tc01_encrypt_decrypt_hex_normal(self) -> None:
        """TC-01: Enkripsi & dekripsi Hex dengan kunci lebih pendek dari pesan."""
        plaintext = "Transfer Rp 5.000.000 ke Rekening #123456! (Prioritas 1)"
        key = "Kunci123"  # Lebih pendek dari plaintext

        original_hash = compute_sha256(plaintext)
        ciphertext = encrypt_text(plaintext, key, encoding="hex")
        decrypted_bytes = decrypt_to_bytes(ciphertext, key, encoding="hex")

        is_valid, decrypted_hash = verify_integrity(original_hash, decrypted_bytes)
        is_utf8, decrypted_text = decode_utf8_safe(decrypted_bytes)

        self.assertTrue(is_valid)
        self.assertEqual(get_integrity_status(is_valid), STATUS_VALID)
        self.assertEqual(original_hash, decrypted_hash)
        self.assertTrue(is_utf8)
        self.assertEqual(decrypted_text, plaintext)

    def test_tc02_encrypt_decrypt_base64_long_key_multiline_utf8(self) -> None:
        """TC-02: Enkripsi & dekripsi Base64 dengan kunci lebih panjang & multiline UTF-8."""
        plaintext = "Baris 1: Halo Dunia!\nBaris 2: Sisi Kriptografi — UTF-8: café €100"
        key = "KunciRahasiaYangSangatPanjangSekaliMelebihiPanjangPlaintextUntukUjiKey"

        original_hash = compute_sha256(plaintext)
        ciphertext = encrypt_text(plaintext, key, encoding="base64")
        decrypted_bytes = decrypt_to_bytes(ciphertext, key, encoding="base64")

        is_valid, decrypted_hash = verify_integrity(original_hash, decrypted_bytes)
        is_utf8, decrypted_text = decode_utf8_safe(decrypted_bytes)

        self.assertTrue(is_valid)
        self.assertEqual(get_integrity_status(is_valid), STATUS_VALID)
        self.assertEqual(original_hash, decrypted_hash)
        self.assertTrue(is_utf8)
        self.assertEqual(decrypted_text, plaintext)

    def test_tc03_tampered_ciphertext_triggers_modified_status(self) -> None:
        """TC-03: Manipulasi 1 bit ciphertext terdeteksi sebagai DATA TELAH DIMODIFIKASI."""
        plaintext = "Dokumen rahasia negara nomor 998877"
        key = "rahasia-tim"

        for encoding in ("hex", "base64"):
            with self.subTest(encoding=encoding):
                original_hash = compute_sha256(plaintext)
                ciphertext = encrypt_text(plaintext, key, encoding=encoding)
                tampered = tamper_ciphertext(ciphertext, encoding=encoding)

                self.assertNotEqual(ciphertext, tampered)
                decrypted_bytes = decrypt_to_bytes(tampered, key, encoding=encoding)
                is_valid, decrypted_hash = verify_integrity(
                    original_hash, decrypted_bytes
                )

                self.assertFalse(is_valid)
                self.assertEqual(get_integrity_status(is_valid), STATUS_MODIFIED)
                self.assertNotEqual(original_hash, decrypted_hash)

    def test_tc04_wrong_key_no_crash_even_non_utf8_bytes(self) -> None:
        """TC-04: Kunci berbeda 1 karakter tidak crash walau hasil byte non-UTF-8."""
        plaintext = "Pesan rahasia untuk pengujian kunci salah"
        correct_key = "KunciBenar1"
        wrong_key = "KunciBenar2"

        original_hash = compute_sha256(plaintext)
        ciphertext = encrypt_text(plaintext, correct_key, encoding="hex")
        decrypted_bytes = decrypt_to_bytes(ciphertext, wrong_key, encoding="hex")

        is_valid, _ = verify_integrity(original_hash, decrypted_bytes)
        self.assertFalse(is_valid)
        self.assertEqual(get_integrity_status(is_valid), STATUS_MODIFIED)

        # Uji skenario byte hasil dekripsi secara spesifik bukan UTF-8 valid (0xFF, 0xFE)
        forced_invalid_utf8_cipher = bytes([0xFF ^ 0x41, 0xFE ^ 0x42]).hex()
        raw_bytes = decrypt_to_bytes(forced_invalid_utf8_cipher, "AB", encoding="hex")
        self.assertEqual(raw_bytes, b"\xff\xfe")
        is_utf8, safe_text = decode_utf8_safe(raw_bytes)
        self.assertFalse(is_utf8)
        self.assertEqual(safe_text, "")
        is_valid_non_utf8, _ = verify_integrity(original_hash, raw_bytes)
        self.assertFalse(is_valid_non_utf8)
        self.assertEqual(get_integrity_status(is_valid_non_utf8), STATUS_MODIFIED)

    def test_tc05_empty_input_validation_raises_value_error(self) -> None:
        """TC-05: Input kosong memunculkan ValueError secara tepat."""
        with self.assertRaises(ValueError):
            xor_bytes(b"", b"key")
        with self.assertRaises(ValueError):
            xor_bytes(b"data", b"")

        with self.assertRaises(ValueError):
            encrypt_text("", "kunci")
        with self.assertRaises(ValueError):
            encrypt_text("   \t\n  ", "kunci")
        with self.assertRaises(ValueError):
            encrypt_text("halo", "")
        with self.assertRaises(ValueError):
            encrypt_text("halo", "kunci", encoding="rot13")

        with self.assertRaises(ValueError):
            decrypt_to_bytes("", "kunci")
        with self.assertRaises(ValueError):
            decrypt_to_bytes("   ", "kunci")
        with self.assertRaises(ValueError):
            decrypt_to_bytes("4142", "")

    def test_tc06_corrupted_formats_and_missing_json_fields(self) -> None:
        """TC-06: Format rusak (hex, base64, JSON korup/hilang/kurang field) ditangani."""
        # Hex panjang ganjil & karakter bukan hex
        with self.assertRaises(ValueError):
            decrypt_to_bytes("abc", "kunci", encoding="hex")
        with self.assertRaises(ValueError):
            decrypt_to_bytes("zzzz", "kunci", encoding="hex")
        with self.assertRaises(ValueError):
            decrypt_to_bytes("41 42", "kunci", encoding="hex")

        # Base64 tidak valid
        with self.assertRaises(ValueError):
            decrypt_to_bytes("!!!not_base64!!!", "kunci", encoding="base64")

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)

            # File tidak ada
            with self.assertRaises(FileNotFoundError):
                load_package(str(tmp / "tidak_ada.json"))

            # JSON korup
            corrupt_path = tmp / "corrupt.json"
            corrupt_path.write_text("{invalid json", encoding="utf-8")
            with self.assertRaises(ValueError):
                load_package(str(corrupt_path))

            # Field wajib kurang
            incomplete_path = tmp / "incomplete.json"
            incomplete_path.write_text(
                json.dumps({"algorithm": "XOR-MultiByte", "encoding": "hex"}),
                encoding="utf-8",
            )
            with self.assertRaises(ValueError):
                load_package(str(incomplete_path))

            # Encoding tidak valid di JSON
            bad_enc_path = tmp / "bad_enc.json"
            bad_enc_path.write_text(
                json.dumps(
                    {
                        "algorithm": "XOR-MultiByte",
                        "encoding": "binary",
                        "ciphertext": "4142",
                        "original_hash": "a" * 64,
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaises(ValueError):
                load_package(str(bad_enc_path))

            # Hash bukan 64 char hex
            bad_hash_path = tmp / "bad_hash.json"
            bad_hash_path.write_text(
                json.dumps(
                    {
                        "algorithm": "XOR-MultiByte",
                        "encoding": "hex",
                        "ciphertext": "4142",
                        "original_hash": "12345",
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaises(ValueError):
                load_package(str(bad_hash_path))

    def test_tc07_json_package_round_trip(self) -> None:
        """TC-07: Simpan dan muat paket JSON round-trip berjalan sukses."""
        plaintext = "Laporan Keuangan Kuartal IV: Laba Rp 120.000.000"
        key = "SecretKey!2026"
        encoding = "base64"

        original_hash = compute_sha256(plaintext)
        ciphertext = encrypt_text(plaintext, key, encoding=encoding)

        with tempfile.TemporaryDirectory() as tmpdir:
            target_file = Path(tmpdir) / "nested" / "paket.json"
            saved_path = save_package(
                str(target_file),
                ciphertext=ciphertext,
                original_hash=original_hash,
                encoding=encoding,
            )
            self.assertTrue(Path(saved_path).exists())

            loaded = load_package(saved_path)
            self.assertEqual(loaded["algorithm"], ALGORITHM_NAME)
            self.assertEqual(loaded["encoding"], encoding)
            self.assertEqual(loaded["ciphertext"], ciphertext)
            self.assertEqual(loaded["original_hash"], original_hash)
            self.assertIn("created_at", loaded)

            decrypted_bytes = decrypt_to_bytes(
                loaded["ciphertext"], key, encoding=loaded["encoding"]
            )
            is_valid, decrypted_hash = verify_integrity(
                loaded["original_hash"], decrypted_bytes
            )
            self.assertTrue(is_valid)
            self.assertEqual(decrypted_hash, original_hash)
            self.assertEqual(decrypted_bytes.decode("utf-8"), plaintext)

    def test_read_text_file_and_avalanche_helper(self) -> None:
        """Uji pembacaan file teks UTF-8 dan perhitungan Avalanche Effect."""
        with tempfile.TemporaryDirectory() as tmpdir:
            txt_path = Path(tmpdir) / "pesan.txt"
            txt_path.write_text("Pesan dari file teks.\nBaris kedua.", encoding="utf-8")
            content = read_text_file(str(txt_path))
            self.assertIn("Pesan dari file teks.", content)

            empty_txt = Path(tmpdir) / "kosong.txt"
            empty_txt.write_text("   \n  ", encoding="utf-8")
            with self.assertRaises(ValueError):
                read_text_file(str(empty_txt))

        h1 = compute_sha256("Transfer Rp 5.000.000 ke Rekening 123456")
        h2 = compute_sha256("Transfer Rp 5.000.000 ke Rekening 123457")
        diff_bits, total_bits, pct = calculate_bit_difference(h1, h2)
        self.assertEqual(total_bits, 256)
        self.assertGreater(diff_bits, 80)
        self.assertGreater(pct, 30.0)

    def test_cli_smoke_flows_and_interrupt_handling(self) -> None:
        """Smoke test alur CLI interaktif (Enkripsi, Dekripsi, Simulasi, Keluar)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            json_path = str(Path(tmpdir) / "demo.json")
            inputs = iter(
                [
                    "9",  # pilihan menu invalid
                    "1",  # menu enkripsi
                    "1",  # input teks langsung
                    "Pesan Uji CLI 2026",
                    "kunci-cli",
                    "1",  # encoding hex
                    "y",  # simpan json
                    json_path,
                    "2",  # menu dekripsi
                    "1",  # muat dari json
                    json_path,
                    "kunci-cli",
                    "3",  # menu simulasi
                    "1",  # Mode A
                    "1",  # muat dari json
                    json_path,
                    "kunci-cli",
                    "3",  # menu simulasi
                    "2",  # Mode B
                    "",   # default original text
                    "",   # default modified text
                    "0",  # keluar
                ]
            )
            stdout_buf = io.StringIO()
            with patch("builtins.input", side_effect=lambda _: next(inputs)):
                with patch("sys.stdout", stdout_buf):
                    CLIController().run()

            output = stdout_buf.getvalue()
            self.assertIn("DATA VALID", output)
            self.assertIn("DATA TELAH DIMODIFIKASI", output)
            self.assertIn("Terima kasih telah menggunakan CryptoVerify CLI", output)

        # Uji KeyboardInterrupt ditangani rapi tanpa crash
        stdout_buf_int = io.StringIO()
        with patch("builtins.input", side_effect=KeyboardInterrupt):
            with patch("sys.stdout", stdout_buf_int):
                CLIController().run()
        self.assertIn("Terima kasih telah menggunakan CryptoVerify CLI", stdout_buf_int.getvalue())


if __name__ == "__main__":
    unittest.main()
