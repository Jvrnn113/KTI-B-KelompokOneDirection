# KTI-B-KelompokOneDirection
## Project Mata Kuliah Keamanan Teknologi Informasi - B (KTI)
----
### Deskripsi Tugas
<br>
- Membuat program berbasis CLI (Command Line Interface) menggunakan bahasa Python atau C++
yang mengimplementasikan kombinasi enkripsi dan pemeriksaan integritas data.
### Fitur - fitur :
Fitur 1 (Modul Enkripsi): Program menerima input pesan teks dan kunci rahasia dari pengguna, lalu
mengenkripsinya (boleh menggunakan XOR Multi-Byte, AES via library, atau simulasi RSA).
Fitur 2 (Modul Integritas Hash): Program otomatis menghitung nilai hash (SHA-256) dari pesan asli sebelum
dienkripsi dan menyimpannya sebagai metadata.
Fitur 3 (Modul Dekripsi & Validasi): Saat melakukan dekripsi, program mencocokkan kembali hash hasil dekripsi
dengan hash awal untuk menampilkan status 'DATA VALID' atau 'DATA TELAH DIMODIFIKASI'.

