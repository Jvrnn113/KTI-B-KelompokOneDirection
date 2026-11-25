import sys


def xor_encrypt(plaintext: str, key: str) -> str:
  """Mengenkripsi teks (kapital, kecil, spasi, simbol) menjadi string Hex."""
 
  data_bytes = plaintext.encode("utf-8")
  key_bytes = key.encode("utf-8")

  # Operasi XOR per byte agar akurat untuk semua karakter & spasi
  cipher_bytes = bytes(
      [b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data_bytes)]
  )
  return cipher_bytes.hex()


def xor_decrypt(cipher_hex: str, key: str) -> str:
  """Mendekripsi string Hex kembali ke plaintext asli (termasuk huruf besar/kecil & spasi)."""
  try:
    cipher_bytes = bytes.fromhex(cipher_hex)
  except ValueError:
    raise ValueError("Format Ciphertext harus berupa Hexadecimal yang valid!")

  key_bytes = key.encode("utf-8")

  decrypted_bytes = bytes(
      [b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(cipher_bytes)]
  )
  return decrypted_bytes.decode("utf-8")


def main():
  while True:
    print("\n=== PROGRAM KRIPTOGRAFI XOR CLI ===")
    print("1. Enkripsi Teks (Plaintext -> Hex)")
    print("2. Dekripsi Teks (Hex -> Plaintext)")
    print("3. Keluar")

    pilihan = input("Pilih menu (1/2/3): ").strip()

    if pilihan == "1":
      # Tidak menggunakan .strip() agar spasi di awal/akhir teks tetap ikut terenkripsi
      plaintext = input("Masukkan Plaintext : ")
      kunci = input("Masukkan Kunci     : ")

      
      hasil_hex = xor_encrypt(plaintext, kunci)
      print(f"\n[+] Plaintext Asli : '{plaintext}'")
      print(f"[+] Cipher (Hex)   : {hasil_hex}")
    

    elif pilihan == "2":
      cipher_hex = input("Masukkan Cipher Hex: ").strip()
      kunci = input("Masukkan Kunci     : ")

    elif pilihan == "3":
      print("Program selesai.")
      sys.exit()
    else:
      print("[!] Pilihan tidak valid, silakan pilih 1, 2, atau 3.")


if __name__ == "__main__":
  main()