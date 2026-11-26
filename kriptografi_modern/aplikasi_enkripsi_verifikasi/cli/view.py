"""Lapisan View untuk CryptoVerify CLI menggunakan format ASCII bersih."""

from __future__ import annotations

LINE_WIDTH = 74
DOUBLE_LINE = "=" * LINE_WIDTH
SINGLE_LINE = "-" * LINE_WIDTH


class CLIView:
    """Menangani seluruh tampilan menu, hasil, dan prompt masukan terminal."""

    def show_banner(self) -> None:
        """Menampilkan header aplikasi dengan garis pemisah ASCII."""
        print()
        print(DOUBLE_LINE)
        print("  CryptoVerify CLI - Aplikasi Enkripsi & Verifikasi Integritas Data")
        print("  Algoritma: XOR Multi-Byte (UTF-8) + SHA-256 Integrity Check")
        print(DOUBLE_LINE)

    def show_main_menu(self) -> str:
        """Menampilkan menu utama dan mengembalikan pilihan pengguna."""
        print()
        print(SINGLE_LINE)
        print("MENU UTAMA")
        print(SINGLE_LINE)
        print("1. Enkripsi Pesan & Buat Hash SHA-256")
        print("2. Dekripsi Pesan & Validasi Integritas")
        print("3. Simulasi Manipulasi Data (Uji Avalanche Effect)")
        print("0. Keluar")
        print(SINGLE_LINE)
        return input("Pilih menu (0-3): ").strip()

    def show_encryption_source_menu(self) -> str:
        """Menampilkan pilihan sumber pesan untuk proses enkripsi."""
        print()
        print(SINGLE_LINE)
        print("MODUL ENKRIPSI & PEMBUATAN METADATA HASH")
        print(SINGLE_LINE)
        print("Sumber pesan:")
        print("1. Input teks langsung di terminal")
        print("2. Baca pesan dari file .txt")
        print("0. Kembali ke menu utama")
        return input("Pilih sumber pesan (0-2): ").strip()

    def show_encoding_menu(self) -> str:
        """Menampilkan pilihan format encoding keluaran ciphertext."""
        print("\nFormat encoding ciphertext:")
        print("1. Hexadecimal [default]")
        print("2. Base64")
        return input("Pilih encoding (1/2, Enter untuk default): ").strip()

    def show_decryption_source_menu(self) -> str:
        """Menampilkan pilihan sumber data untuk proses dekripsi."""
        print()
        print(SINGLE_LINE)
        print("MODUL DEKRIPSI & VALIDASI INTEGRITAS")
        print(SINGLE_LINE)
        print("Sumber data terenkripsi:")
        print("1. Muat dari file paket .json")
        print("2. Input manual (encoding, ciphertext, original_hash)")
        print("0. Kembali ke menu utama")
        return input("Pilih sumber data (0-2): ").strip()

    def show_simulation_menu(self) -> str:
        """Menampilkan pilihan mode simulasi manipulasi data."""
        print()
        print(SINGLE_LINE)
        print("MODUL SIMULASI MANIPULASI DATA & AVALANCHE EFFECT")
        print(SINGLE_LINE)
        print("1. Mode A - Simulasi Manipulasi Ciphertext (1 bit diubah)")
        print("2. Mode B - Simulasi Avalanche Effect pada Teks (1 karakter diubah)")
        print("0. Kembali ke menu utama")
        return input("Pilih mode simulasi (0-2): ").strip()

    def show_simulation_a_source_menu(self) -> str:
        """Menampilkan pilihan sumber data untuk simulasi Mode A."""
        print("\nSumber data untuk Mode A:")
        print("1. Muat paket dari file .json")
        print("2. Input pesan & kunci baru secara cepat")
        print("0. Kembali")
        return input("Pilih sumber (0-2): ").strip()

    def prompt(self, message: str) -> str:
        """Membaca masukan string mentah dari pengguna tanpa mengubah spasi."""
        return input(message)

    def prompt_stripped(self, message: str) -> str:
        """Membaca masukan string dari pengguna dan menghapus spasi tepi."""
        return input(message).strip()

    def show_encryption_result(
        self,
        algorithm: str,
        encoding: str,
        original_hash: str,
        ciphertext: str,
    ) -> None:
        """Menampilkan ringkasan hasil enkripsi dan hash SHA-256."""
        print()
        print(SINGLE_LINE)
        print("HASIL ENKRIPSI & METADATA INTEGRITAS")
        print(SINGLE_LINE)
        print(f"Algoritma             : {algorithm}")
        print(f"Encoding              : {encoding}")
        print(f"Hash SHA-256 Asli     : {original_hash}")
        print(f"Ciphertext            : {ciphertext}")
        print(SINGLE_LINE)

    def show_decryption_result(
        self,
        original_hash: str,
        decrypted_hash: str,
        status: str,
        is_valid: bool,
        is_utf8: bool,
        decrypted_text: str,
        raw_hex_preview: str,
    ) -> None:
        """Menampilkan hasil dekripsi serta status validasi integritas."""
        print()
        print(SINGLE_LINE)
        print("HASIL DEKRIPSI & VALIDASI INTEGRITAS")
        print(SINGLE_LINE)
        print(f"Hash Awal (Metadata)  : {original_hash}")
        print(f"Hash Hasil Dekripsi   : {decrypted_hash}")
        print(f"Status Integritas     : {status}")
        print(SINGLE_LINE)

        if is_valid and is_utf8:
            print("[+] Pesan Asli Utuh:")
            print(decrypted_text)
        elif not is_valid and is_utf8:
            print(
                "[!] PERINGATAN: Ciphertext atau kunci telah berubah sehingga "
                "hash tidak cocok!"
            )
            print("[!] Teks Hasil Dekripsi (Termodifikasi):")
            print(decrypted_text)
        elif not is_utf8:
            print(
                "[!] PERINGATAN: Byte hasil dekripsi rusak / bukan UTF-8 yang sah "
                "(indikasi manipulasi ciphertext atau kunci rahasia salah)."
            )
            print(f"[*] Preview Byte (Hex): {raw_hex_preview}")
        else:
            print(f"[*] Byte Hasil (Hex)  : {raw_hex_preview}")
        print(SINGLE_LINE)

    def show_simulation_a_result(
        self,
        encoding: str,
        original_ciphertext: str,
        tampered_ciphertext: str,
        original_hash: str,
        decrypted_hash: str,
        status: str,
        is_utf8: bool,
        decrypted_text: str,
        raw_hex_preview: str,
    ) -> None:
        """Menampilkan hasil simulasi manipulasi 1 bit pada ciphertext."""
        print()
        print(SINGLE_LINE)
        print("HASIL SIMULASI MODE A - MANIPULASI CIPHERTEXT")
        print(SINGLE_LINE)
        print(f"Encoding                  : {encoding}")
        print(f"Ciphertext Asli           : {original_ciphertext}")
        print(f"Ciphertext Termodifikasi  : {tampered_ciphertext}")
        print("-" * LINE_WIDTH)
        print(f"Hash Awal (Metadata)      : {original_hash}")
        print(f"Hash Hasil Dekripsi       : {decrypted_hash}")
        print(f"Status Integritas         : {status}")
        print("-" * LINE_WIDTH)
        if is_utf8:
            print(f"Hasil Dekripsi (UTF-8)    : {decrypted_text}")
        else:
            print(
                "Hasil Dekripsi            : [Byte bukan UTF-8 valid akibat manipulasi]"
            )
            print(f"Preview Byte (Hex)        : {raw_hex_preview}")
        print(SINGLE_LINE)

    def show_simulation_b_result(
        self,
        text_original: str,
        text_modified: str,
        hash_original: str,
        hash_modified: str,
        diff_bits: int,
        total_bits: int,
        diff_bit_pct: float,
        diff_hex_chars: int,
        status: str,
    ) -> None:
        """Menampilkan hasil simulasi Avalanche Effect antara dua teks."""
        print()
        print(SINGLE_LINE)
        print("HASIL SIMULASI MODE B - AVALANCHE EFFECT (SHA-256)")
        print(SINGLE_LINE)
        print(f"Teks Asli         : {text_original}")
        print(f"Teks Termodifikasi: {text_modified}")
        print("-" * LINE_WIDTH)
        print(f"Hash Teks Asli    : {hash_original}")
        print(f"Hash Teks Ubah    : {hash_modified}")
        print("-" * LINE_WIDTH)
        print(
            f"Perbedaan Bit     : {diff_bits}/{total_bits} bit ({diff_bit_pct:.2f}%)"
        )
        print(f"Perbedaan Hex     : {diff_hex_chars}/64 karakter hex")
        print(f"Status Integritas : {status}")
        print(SINGLE_LINE)

    def show_success(self, message: str) -> None:
        """Menampilkan pesan keberhasilan."""
        print(f"[+] {message}")

    def show_info(self, message: str) -> None:
        """Menampilkan pesan informasi."""
        print(f"[*] {message}")

    def show_error(self, message: str) -> None:
        """Menampilkan pesan kesalahan."""
        print(f"[!] {message}")

    def show_goodbye(self) -> None:
        """Menampilkan pesan keluar yang rapi."""
        print()
        print(DOUBLE_LINE)
        print("  Terima kasih telah menggunakan CryptoVerify CLI. Program selesai.")
        print(DOUBLE_LINE)
