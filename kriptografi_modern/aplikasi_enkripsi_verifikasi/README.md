# Cryptography App - Aplikasi Enkripsi & Verifikasi Integritas Data

Aplikasi berbasis Command Line Interface (CLI) menggunakan Python 3.8+ (zero external dependencies) yang mengombinasikan **enkripsi XOR Multi-Byte (level byte UTF-8)** dan **verifikasi integritas data SHA-256**.

## Fitur Utama

1. **Enkripsi Pesan & Metadata Integritas SHA-256 (`FR-02`)**
   - Mendukung input pesan langsung dari terminal maupun pembacaan dari file `.txt` (UTF-8).
   - Menghitung digest **SHA-256** (64 karakter hex) dari pesan asli sebelum enkripsi.
   - Mengenkripsi pesan dengan **XOR Multi-Byte** dan mendukung representasi **Hexadecimal** (default) atau **Base64**.
   - Menyimpan ciphertext beserta metadata integritas ke file paket `.json`.
2. **Dekripsi Pesan & Validasi Integritas (`FR-03`)**
   - Memuat paket dari file `.json` maupun input manual (`encoding`, `ciphertext`, `original_hash`).
   - Mendekripsi ke byte mentah (`bytes`) lalu menghitung ulang SHA-256 dan membandingkannya secara aman dengan `hmac.compare_digest`.
   - Menampilkan status tepat **`DATA VALID`** atau **`DATA TELAH DIMODIFIKASI`**.
   - Aman dari crash `UnicodeDecodeError` apabila kunci salah atau ciphertext dimanipulasi hingga menghasilkan byte non-UTF-8.
3. **Simulasi Manipulasi Data & Uji Avalanche Effect (`FR-04`)**
   - **Mode A (Manipulasi Ciphertext):** Membalik 1 bit pada ciphertext lalu mendekripsi dengan kunci yang benar untuk membuktikan deteksi manipulasi (`DATA TELAH DIMODIFIKASI`).
   - **Mode B (Avalanche Effect pada Teks):** Membandingkan dua kalimat yang hanya berbeda 1 karakter untuk memperlihatkan perubahan bit SHA-256 secara drastis.

## Alur Algoritma

### 1. XOR Multi-Byte (UTF-8 Byte-Level)
- Plaintext dan kunci rahasia dikonversi menjadi urutan byte UTF-8 (`P` dan `K`).
- Setiap byte di-XOR menggunakan pengulangan kunci (*key cycling*):
  `C[i] = P[i] ^ K[i % len(K)]`
- Byte hasil enkripsi kemudian dikodekan ke string `hex` atau `base64`.
- Karena bekerja di level byte UTF-8, proses enkripsi-dekripsi bersifat 100% *lossless* untuk spasi, angka, tanda baca, *newline*, dan karakter UTF-8.

### 2. Verifikasi Integritas SHA-256
- Sebelum enkripsi, dihitung `original_hash = SHA256(plaintext_utf8)`.
- Saat dekripsi, ciphertext di-decode menjadi bytes lalu di-XOR kembali dengan kunci menjadi `decrypted_bytes`.
- Hash dihitung ulang langsung dari `decrypted_bytes` (`decrypted_hash = SHA256(decrypted_bytes)`).
- Perbandingan menggunakan `hmac.compare_digest`:
  - Cocok 100% -> `DATA VALID`
  - Berbeda -> `DATA TELAH DIMODIFIKASI`

### 3. Skema Paket Metadata JSON
```json
{
  "algorithm": "XOR-MultiByte",
  "encoding": "hex",
  "ciphertext": "<string hex atau base64>",
  "original_hash": "<64 karakter hex SHA-256>",
  "created_at": "<ISO-8601 timestamp>"
}
```

## Struktur Proyek

```text
aplikasi_enkripsi_verifikasi/
├── main.py                  # Entry point aplikasi CLI
├── core/
│   ├── __init__.py
│   ├── cipher.py            # Logika XOR Multi-Byte (Hex & Base64)
│   ├── hasher.py            # Logika SHA-256 & verifikasi integritas
│   └── storage.py           # Baca/tulis file teks (.txt) & paket (.json)
├── cli/
│   ├── __init__.py
│   ├── view.py              # Tampilan menu, banner ASCII, output & prompt
│   └── controller.py        # Orkestrasi alur Enkripsi, Dekripsi, & Simulasi
├── tests/
│   ├── __init__.py
│   └── test_crypto.py       # Unit test lengkap (unittest)
└── README.md                # Dokumentasi proyek
```

## Cara Menjalankan Aplikasi

Masuk ke folder `kriptografi_modern/aplikasi_enkripsi_verifikasi`, lalu jalankan:

```bash
python main.py
```

## Cara Menjalankan Unit Test

Dari folder `kriptografi_modern/aplikasi_enkripsi_verifikasi`, jalankan:

```bash
python -m unittest discover -s tests -v
```

## Panduan Skenario Demo

1. **Enkripsi & Simpan Paket JSON:**
   - Pilih menu `1`, pilih `1` (Input teks langsung), masukkan pesan misal `Transfer Rp 5.000.000 ke Rekening 123456`, masukkan kunci misal `KunciTim01`, pilih encoding `1` (Hex), lalu simpan ke `output/pesan_terenkripsi.json`.
2. **Dekripsi Valid:**
   - Pilih menu `2`, pilih `1` (Muat dari file `.json`), tekan Enter untuk memakai `output/pesan_terenkripsi.json`, lalu masukkan kunci `KunciTim01`. Status akan menampilkan `DATA VALID` beserta pesan utuh.
3. **Dekripsi Kunci Salah:**
   - Ulangi menu `2` dengan file yang sama, tetapi masukkan kunci berbeda misal `KunciTim02`. Program tidak akan crash meskipun hasil byte rusak/non-UTF-8 dan status menampilkan `DATA TELAH DIMODIFIKASI`.
4. **Simulasi Manipulasi & Avalanche Effect:**
   - Pilih menu `3`, lalu uji **Mode A** (1 bit ciphertext diubah) dan **Mode B** (perubahan 1 karakter misal `123456` -> `123457`) untuk melihat persentase perbedaan bit SHA-256 dan status `DATA TELAH DIMODIFIKASI`.
5. **Uji Error Handling:**
   - Coba masukkan pilihan menu huruf/angka di luar rentang, pesan/kunci kosong, format Hex ganjil (`abc`), atau path file `.json` yang tidak ada; aplikasi akan menampilkan pesan kesalahan rapi tanpa traceback.
