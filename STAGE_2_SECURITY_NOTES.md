# Secure Vault - Catatan Perbaikan Tahap 2

## Ruang lingkup yang diterapkan

Tahap 2 memperkeras alur unggah, pembukuan kuota, penyimpanan chunk, dan integritas audit.

1. **Validasi berkas di server**: ukuran file 1 byte sampai 500 MiB, jumlah chunk harus cocok dengan ukuran file (chunk plaintext 5 MiB), batas total 100 chunk, hash SHA-256 64 karakter hex, DEK terbungkus berukuran sesuai AES-KW 256-bit, serta metadata nama/tag dengan format ciphertext+IV.
2. **Validasi chunk**: indeks harus berada dalam rentang, IV Base64 harus mewakili 12 byte, AAD wajib sama dengan `<fileId>-<index>`, dan ukuran ciphertext harus sama dengan ukuran plaintext chunk ditambah tag AES-GCM 16 byte.
3. **Retry upload aman**: unggahan ulang dengan konten, IV, dan AAD identik dikembalikan sebagai sukses idempoten; chunk yang sudah ada dengan konten berbeda ditolak HTTP 409.
4. **Finalisasi idempoten**: unggahan tak dapat difinalisasi sampai semua indeks chunk ada dan ukuran serta hash ciphertext cocok. Pemanggilan `complete` berulang tidak membebankan kuota atau menambah event selesai kedua kali.
5. **Kuota**: jumlah byte dicadangkan atomik pada inisialisasi dan dilepas satu kali pada penghapusan, termasuk unggahan yang belum selesai. Endpoint admin menolak kuota noninteger atau kuota yang lebih kecil daripada penggunaan saat ini.
6. **Pemulihan unggahan parsial**: daftar berkas menyertakan status `uploading`; UI menonaktifkan unduh/detail untuk unggahan parsial tetapi tetap menyediakan tombol hapus, sehingga reservasi kuota bisa dilepas.
7. **Integritas ciphertext**: SHA-256 ciphertext disimpan untuk setiap chunk dan dicek lagi ketika finalisasi dan sebelum chunk dikirim saat unduh.
8. **Audit hash v2**: hash baru mencakup ID, nomor urut, timestamp, aktor, aksi, file ID, status, IP, user-agent, detail, dan hash sebelumnya dengan serialisasi JSON terurut. Nomor urut dan tautan genesis juga divalidasi.
9. **Fail-closed untuk database JSON rusak**: JSON yang tidak valid atau koleksi penting yang hilang menghasilkan error, tidak lagi memicu reset database otomatis.
10. **Serialisasi request JSON**: lock file privat mengunci keseluruhan transaksi request untuk mencegah lost-update pada backend JSON satu-host.
11. **Konfigurasi ukuran upload**: launcher lokal menetapkan `upload_max_filesize=8M` dan `post_max_size=10M`, agar ciphertext chunk 5 MiB plus tag dan overhead multipart dapat diterima PHP.

## Pengujian yang dijalankan

Jalankan dari root repositori:

```bash
python backend_php/tests/security_stage1.py
python backend_php/tests/security_stage2.py
```

Tes Tahap 2 meliputi uji unggahan ciphertext berukuran 5 MiB dengan konfigurasi PHP yang digunakan launcher, dimensi berkas negatif/zero/oversized, chunk count salah, metadata kunci dan hash salah, AAD salah, indeks out-of-range, panjang ciphertext salah, retry identik, duplikat berbeda, complete sebelum seluruh chunk, complete berulang, pemeriksaan hash ciphertext sebelum unduh, perubahan user-agent audit, serta pelepasan kuota untuk berkas lengkap dan parsial.

## Migrasi audit lama

Catatan audit Tahap 1 tidak memasukkan IP, user-agent, ID log, atau nomor urut ke hash. Verifier tetap mendukung hash v1 agar rantai lama bisa dibaca, tetapi tidak bisa menjamin integritas atribut yang tidak pernah di-hash.

Sebelum migrasi, hentikan penulisan aplikasi, buat backup di luar direktori runtime, dan simpan SHA-256 backup secara independen. Setelah peninjauan operator terhadap metadata historis, jalankan:

```bash
php backend_php/scripts/migrate_audit_v2.php
```

Skrip meminta konfirmasi `MIGRATE-AUDIT-V2`. Migrasi hanya mengikat metadata yang tersimpan saat migrasi. Ia **tidak dapat membuktikan** bahwa atribut pada log v1 tidak pernah dimanipulasi sebelumnya. Untuk jaminan lebih kuat, simpan anchor hash backup di sistem terpisah/WORM.

## Batasan yang belum selesai

- Backend runtime **masih menggunakan JSON**, bukan database relasional. Lock request hanya mitigasi sementara untuk satu host dan dapat menahan request paralel. Jangan gunakan ini sebagai pengganti PostgreSQL/MySQL transaksional di produksi.
- `backend_php/db/schema.sql` telah diperbarui sebagai referensi skema MySQL, tetapi aplikasi belum mengaktifkan PDO/driver SQL atau melakukan migrasi data. Lingkungan uji saat perubahan ini dibuat tidak menyediakan driver PDO database, sehingga migrasi relasional tidak diklaim selesai.
- Build penuh Vite harus diulang pada lingkungan dengan dependensi frontend terpasang. Sintaks TSX dapat diperiksa terpisah, tetapi itu bukan pengganti build dan type-check penuh.
- Audit hash chain di database yang sama bukan bukti anti-repudiation terhadap administrator yang dapat mengganti seluruh database. Produksi memerlukan ekspor/anchor log ke layanan append-only/WORM yang terpisah.
- Hash plaintext berkas masih disimpan di server dan dapat menjadi metadata korelasi. Ini harus dipertimbangkan dalam threat model zero-knowledge.
