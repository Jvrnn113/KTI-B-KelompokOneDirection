"""Lapisan Controller untuk mengorkestrasi alur fitur CryptoVerify CLI."""

from __future__ import annotations

import base64
from pathlib import Path

from cli.view import CLIView
from core.cipher import decode_utf8_safe, decrypt_to_bytes, encrypt_text
from core.hasher import (
    calculate_bit_difference,
    compute_sha256,
    get_integrity_status,
    verify_integrity,
)
from core.storage import (
    ALGORITHM_NAME,
    load_package,
    read_text_file,
    save_package,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT_LABEL = "output/pesan_terenkripsi.json"
DEFAULT_OUTPUT_JSON = str(PROJECT_ROOT / "output" / "pesan_terenkripsi.json")
DEFAULT_AVALANCHE_ORIGINAL = "Transfer Rp 5.000.000 ke Rekening 123456"
DEFAULT_AVALANCHE_MODIFIED = "Transfer Rp 5.000.000 ke Rekening 123457"
_HEX_PREVIEW_LIMIT = 48


def _format_hex_preview(data: bytes) -> str:
    """Membuat ringkasan hex byte agar aman ditampilkan di terminal."""
    hex_str = data.hex()
    if len(hex_str) <= _HEX_PREVIEW_LIMIT * 2:
        return hex_str
    return f"{hex_str[:_HEX_PREVIEW_LIMIT * 2]}... ({len(data)} bytes)"


def tamper_ciphertext(ciphertext: str, encoding: str) -> str:
    """Memodifikasi tepat 1 bit pada ciphertext tanpa merusak format encoding.

    Args:
        ciphertext: String ciphertext asli (Hex atau Base64).
        encoding: Format encoding (``'hex'`` atau ``'base64'``).

    Returns:
        Ciphertext baru yang berbeda 1 bit dari aslinya.
    """
    enc = encoding.strip().lower()
    cleaned = ciphertext.strip()
    if enc == "hex":
        raw = bytearray.fromhex(cleaned)
        if not raw:
            raise ValueError("Ciphertext kosong tidak dapat dimanipulasi.")
        raw[-1] ^= 0x01
        return raw.hex()
    if enc == "base64":
        raw = bytearray(base64.b64decode(cleaned.encode("ascii"), validate=True))
        if not raw:
            raise ValueError("Ciphertext kosong tidak dapat dimanipulasi.")
        raw[-1] ^= 0x01
        return base64.b64encode(bytes(raw)).decode("ascii")
    raise ValueError(f"Encoding '{encoding}' tidak didukung untuk simulasi.")


def _auto_modify_one_char(text: str) -> str:
    """Mengubah 1 karakter terakhir pada teks untuk simulasi Avalanche Effect."""
    if text == DEFAULT_AVALANCHE_ORIGINAL:
        return DEFAULT_AVALANCHE_MODIFIED
    last_char = text[-1]
    replacement = chr(ord(last_char) + 1) if last_char != "z" else "a"
    return text[:-1] + replacement


class CLIController:
    """Pengendali utama alur Enkripsi, Dekripsi, dan Simulasi pada CLI."""

    def __init__(self, view: CLIView | None = None) -> None:
        self.view = view or CLIView()

    def run(self) -> None:
        """Menjalankan loop interaktif menu utama CLI hingga pengguna keluar."""
        try:
            self.view.show_banner()
            while True:
                choice = self.view.show_main_menu()
                if choice == "1":
                    self._handle_encrypt()
                elif choice == "2":
                    self._handle_decrypt()
                elif choice == "3":
                    self._handle_simulation()
                elif choice == "0":
                    self.view.show_goodbye()
                    break
                else:
                    self.view.show_error(
                        "Pilihan menu tidak valid. Masukkan angka 0, 1, 2, atau 3."
                    )
        except (KeyboardInterrupt, EOFError):
            self.view.show_info("\nInput dihentikan oleh pengguna.")
            self.view.show_goodbye()

    def _prompt_non_empty_key(self) -> str | None:
        """Meminta kunci rahasia dari pengguna dan menolak input kosong."""
        key = self.view.prompt("Masukkan kunci rahasia: ")
        if key == "":
            self.view.show_error("Kunci rahasia tidak boleh kosong.")
            return None
        return key

    def _prompt_encoding_choice(self) -> str | None:
        """Meminta pilihan format encoding (Hex default atau Base64)."""
        choice = self.view.show_encoding_menu()
        if choice in ("", "1"):
            return "hex"
        if choice == "2":
            return "base64"
        self.view.show_error("Pilihan encoding tidak valid. Pilih 1 (Hex) atau 2 (Base64).")
        return None

    def _handle_encrypt(self) -> None:
        """Mengorkestrasi FR-02: Enkripsi pesan, hitung SHA-256, dan simpan JSON."""
        source = self.view.show_encryption_source_menu()
        if source == "0":
            return
        if source == "1":
            plaintext = self.view.prompt("Masukkan pesan (plaintext): ")
            if plaintext.strip() == "":
                self.view.show_error(
                    "Pesan tidak boleh kosong atau hanya berisi spasi."
                )
                return
        elif source == "2":
            filepath = self.view.prompt_stripped("Masukkan path file .txt: ")
            try:
                plaintext = read_text_file(filepath)
                self.view.show_info(
                    f"Berhasil membaca {len(plaintext)} karakter dari '{filepath}'."
                )
            except (FileNotFoundError, ValueError, OSError) as err:
                self.view.show_error(f"Gagal membaca file teks: {err}")
                return
        else:
            self.view.show_error("Pilihan sumber pesan tidak valid. Pilih 0, 1, atau 2.")
            return

        key = self._prompt_non_empty_key()
        if key is None:
            return

        encoding = self._prompt_encoding_choice()
        if encoding is None:
            return

        try:
            original_hash = compute_sha256(plaintext)
            ciphertext = encrypt_text(plaintext, key, encoding=encoding)
        except (TypeError, ValueError) as err:
            self.view.show_error(f"Proses enkripsi gagal: {err}")
            return

        self.view.show_encryption_result(
            algorithm=ALGORITHM_NAME,
            encoding=encoding,
            original_hash=original_hash,
            ciphertext=ciphertext,
        )

        save_opt = self.view.prompt_stripped(
            "Simpan paket ke file .json? (y/n) [y]: "
        ).lower()
        if save_opt in ("", "y", "ya"):
            custom_path = self.view.prompt_stripped(
                f"Masukkan path file tujuan [{DEFAULT_OUTPUT_LABEL}]: "
            )
            target_path = custom_path if custom_path else DEFAULT_OUTPUT_JSON
            try:
                saved = save_package(
                    filepath=target_path,
                    ciphertext=ciphertext,
                    original_hash=original_hash,
                    encoding=encoding,
                )
                self.view.show_success(f"Paket JSON tersimpan di: {saved}")
            except (ValueError, OSError) as err:
                self.view.show_error(f"Gagal menyimpan file JSON: {err}")

    def _handle_decrypt(self) -> None:
        """Mengorkestrasi FR-03: Dekripsi data dan verifikasi integritas SHA-256."""
        source = self.view.show_decryption_source_menu()
        if source == "0":
            return
        if source == "1":
            filepath = self.view.prompt_stripped(
                f"Masukkan path file .json [{DEFAULT_OUTPUT_LABEL}]: "
            )
            target_path = filepath if filepath else DEFAULT_OUTPUT_JSON
            try:
                package = load_package(target_path)
            except (FileNotFoundError, ValueError, OSError) as err:
                self.view.show_error(f"Gagal memuat paket JSON: {err}")
                return
            encoding = package["encoding"]
            ciphertext = package["ciphertext"]
            original_hash = package["original_hash"]
            self.view.show_info(
                f"Paket dimuat (Algoritma: {package['algorithm']}, Encoding: {encoding})."
            )
        elif source == "2":
            encoding = self._prompt_encoding_choice()
            if encoding is None:
                return
            ciphertext = self.view.prompt_stripped("Masukkan ciphertext: ")
            if not ciphertext:
                self.view.show_error("Ciphertext tidak boleh kosong.")
                return
            original_hash = self.view.prompt_stripped(
                "Masukkan Hash SHA-256 Asli (64 char hex): "
            )
            if not original_hash:
                self.view.show_error("Hash SHA-256 asli tidak boleh kosong.")
                return
        else:
            self.view.show_error("Pilihan sumber data tidak valid. Pilih 0, 1, atau 2.")
            return

        key = self._prompt_non_empty_key()
        if key is None:
            return

        try:
            decrypted_bytes = decrypt_to_bytes(ciphertext, key, encoding=encoding)
            is_valid, decrypted_hash = verify_integrity(
                original_hash, decrypted_bytes
            )
        except (TypeError, ValueError) as err:
            self.view.show_error(f"Proses dekripsi/validasi gagal: {err}")
            return

        status = get_integrity_status(is_valid)
        is_utf8, decrypted_text = decode_utf8_safe(decrypted_bytes)
        self.view.show_decryption_result(
            original_hash=original_hash.strip().lower(),
            decrypted_hash=decrypted_hash,
            status=status,
            is_valid=is_valid,
            is_utf8=is_utf8,
            decrypted_text=decrypted_text,
            raw_hex_preview=_format_hex_preview(decrypted_bytes),
        )

    def _handle_simulation(self) -> None:
        """Mengorkestrasi FR-04: Simulasi manipulasi data (Mode A dan Mode B)."""
        mode = self.view.show_simulation_menu()
        if mode == "0":
            return
        if mode == "1":
            self._run_simulation_mode_a()
        elif mode == "2":
            self._run_simulation_mode_b()
        else:
            self.view.show_error("Pilihan mode simulasi tidak valid. Pilih 0, 1, atau 2.")

    def _run_simulation_mode_a(self) -> None:
        """Mode A: Modifikasi 1 bit ciphertext dan uji deteksi integritas."""
        source = self.view.show_simulation_a_source_menu()
        if source == "0":
            return
        if source == "1":
            filepath = self.view.prompt_stripped(
                f"Masukkan path file .json [{DEFAULT_OUTPUT_LABEL}]: "
            )
            target_path = filepath if filepath else DEFAULT_OUTPUT_JSON
            try:
                package = load_package(target_path)
            except (FileNotFoundError, ValueError, OSError) as err:
                self.view.show_error(f"Gagal memuat paket JSON: {err}")
                return
            encoding = package["encoding"]
            original_ciphertext = package["ciphertext"]
            original_hash = package["original_hash"]
            key = self._prompt_non_empty_key()
            if key is None:
                return
        elif source == "2":
            plaintext = self.view.prompt(
                f"Masukkan pesan [{DEFAULT_AVALANCHE_ORIGINAL}]: "
            )
            if plaintext == "":
                plaintext = DEFAULT_AVALANCHE_ORIGINAL
            elif plaintext.strip() == "":
                self.view.show_error("Pesan tidak boleh hanya berisi spasi.")
                return

            key = self.view.prompt("Masukkan kunci rahasia [kunci-demo-2026]: ")
            if key == "":
                key = "kunci-demo-2026"

            encoding = self._prompt_encoding_choice()
            if encoding is None:
                return

            try:
                original_hash = compute_sha256(plaintext)
                original_ciphertext = encrypt_text(plaintext, key, encoding=encoding)
            except (TypeError, ValueError) as err:
                self.view.show_error(f"Gagal menyiapkan data simulasi: {err}")
                return
        else:
            self.view.show_error("Pilihan sumber tidak valid. Pilih 0, 1, atau 2.")
            return

        try:
            tampered_ciphertext = tamper_ciphertext(original_ciphertext, encoding)
            decrypted_bytes = decrypt_to_bytes(
                tampered_ciphertext, key, encoding=encoding
            )
            is_valid, decrypted_hash = verify_integrity(
                original_hash, decrypted_bytes
            )
        except (TypeError, ValueError) as err:
            self.view.show_error(f"Simulasi gagal dijalankan: {err}")
            return

        status = get_integrity_status(is_valid)
        is_utf8, decrypted_text = decode_utf8_safe(decrypted_bytes)
        self.view.show_simulation_a_result(
            encoding=encoding,
            original_ciphertext=original_ciphertext,
            tampered_ciphertext=tampered_ciphertext,
            original_hash=original_hash,
            decrypted_hash=decrypted_hash,
            status=status,
            is_utf8=is_utf8,
            decrypted_text=decrypted_text,
            raw_hex_preview=_format_hex_preview(decrypted_bytes),
        )

    def _run_simulation_mode_b(self) -> None:
        """Mode B: Uji Avalanche Effect SHA-256 dengan perubahan 1 karakter teks."""
        text_original = self.view.prompt(
            f"Masukkan kalimat asli [{DEFAULT_AVALANCHE_ORIGINAL}]: "
        )
        if text_original == "":
            text_original = DEFAULT_AVALANCHE_ORIGINAL
        elif text_original.strip() == "":
            self.view.show_error("Kalimat asli tidak boleh hanya berisi spasi.")
            return

        suggested = _auto_modify_one_char(text_original)
        text_modified = self.view.prompt(
            f"Masukkan kalimat termodifikasi [{suggested}]: "
        )
        if text_modified == "":
            text_modified = suggested
        elif text_modified.strip() == "":
            self.view.show_error(
                "Kalimat termodifikasi tidak boleh hanya berisi spasi."
            )
            return

        hash_original = compute_sha256(text_original)
        is_valid, hash_modified = verify_integrity(
            hash_original, text_modified.encode("utf-8")
        )
        diff_bits, total_bits, diff_bit_pct = calculate_bit_difference(
            hash_original, hash_modified
        )
        diff_hex_chars = sum(
            1 for a, b in zip(hash_original, hash_modified) if a != b
        )
        status = get_integrity_status(is_valid)

        self.view.show_simulation_b_result(
            text_original=text_original,
            text_modified=text_modified,
            hash_original=hash_original,
            hash_modified=hash_modified,
            diff_bits=diff_bits,
            total_bits=total_bits,
            diff_bit_pct=diff_bit_pct,
            diff_hex_chars=diff_hex_chars,
            status=status,
        )
