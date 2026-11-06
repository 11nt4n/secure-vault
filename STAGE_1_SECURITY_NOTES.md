# Secure Vault: Catatan Perbaikan Tahap 1

Tahap ini menutup jalur paling kritis pada autentikasi dan penyimpanan konfigurasi. Ini bukan pernyataan bahwa seluruh aplikasi telah aman untuk produksi.

## Perubahan

1. Registrasi publik selalu menetapkan `role=user`; field `role` dari klien tidak dipercaya.
2. MFA statis `123456` dihapus. Pengguna menambahkan secret TOTP ke aplikasi authenticator, memverifikasi kode enam digit, lalu baru menerima JWT. Maksimal lima percobaan per tantangan, challenge berumur lima menit, dan pencegahan pemakaian ulang counter TOTP yang sudah diterima.
3. Secret TOTP dienkripsi menggunakan AES-256-GCM di penyimpanan runtime. Kunci enkripsi berbeda dari secret JWT.
4. JWT tidak memiliki secret fallback di source. Secret harus disediakan lewat environment atau file lokal privat yang dibuat oleh `backend_php/scripts/init_local_secrets.php`. Klaim `iat` dan `exp` wajib divalidasi.
5. Password baru memiliki minimal 12 karakter dan di-hash dengan Argon2id bila tersedia (atau `PASSWORD_DEFAULT`). Hash lama dapat diverifikasi satu kali dan di-upgrade setelah login berhasil.
6. Akun admin/user demo tidak lagi dibuat otomatis. Admin hanya dapat ditetapkan oleh operator server melalui `backend_php/scripts/promote_admin.php`.
7. Database dan storage runtime dipindahkan secara default ke `var/secure-vault/`, di luar web root. Database yang berisi demo credential dan token MFA lama tidak lagi disertakan dalam paket sumber.
8. CORS memakai allowlist, respons tidak lagi memantulkan origin sembarang, dan detail exception internal tidak dikirim ke klien.
9. Passphrase demo di UI dihapus. Passphrase dan kunci master yang disimpan aktif setelah inisialisasi tidak lagi dibiarkan dalam state form dengan nilai demo; Master Key aktif diimpor kembali sebagai non-extractable.

## Menjalankan pengujian regresi

Dari root proyek dengan PHP 8 dan Python 3:

```bash
python backend_php/tests/security_stage1.py
```

Pemeriksaan sintaks backend:

```bash
find backend_php -name '*.php' -print0 | xargs -0 -n1 php -l
```

Build frontend belum dapat dikonfirmasi pada lingkungan pembuat karena `npm ci` mengalami timeout ketika mengambil dependensi. Jalankan `npm ci` lalu `npm run build` dari `frontend/` di lingkungan yang bisa mengakses registry npm.


## Batasan yang masih terbuka setelah Tahap 1

- Endpoint password login belum memiliki rate limiting global berbasis akun/IP. Pembatasan lima percobaan hanya berlaku pada masing-masing tantangan TOTP; rate limiting login menjadi prioritas perbaikan selanjutnya.
- Belum ada recovery code atau workflow reset/re-enrollment MFA mandiri. Pengguna yang kehilangan perangkat authenticator memerlukan prosedur pemulihan operator yang terkontrol.
- Validasi unggahan/kuota, transaksi multi-proses untuk penyimpanan JSON, dan integritas penuh seluruh atribut audit belum diperbaiki dalam tahap ini.
- Build penuh Vite dan typecheck TypeScript belum dapat dijalankan karena instalasi dependensi npm timeout. Transpilasi sintaks TypeScript/TSX berhasil, tetapi ini bukan pengganti build penuh.

## Catatan migrasi yang penting

- Paket tidak lagi membawa `backend_php/data/database.json` berisi akun demo. Database lama tidak diimpor otomatis. Sebelum mengganti deployment lama, buat backup terkontrol dan lakukan migrasi yang ditinjau; jangan memindahkan database JSON lama secara langsung karena skema password, secret MFA, dan lokasi data berubah.
- Secret lokal `var/secure-vault/secrets.php` harus dicadangkan dengan aman. Kehilangan `MFA_ENCRYPTION_KEY` membuat secret TOTP yang sudah terenkripsi tidak dapat didekripsi. Pada produksi, simpan kedua secret dalam secret manager atau fasilitas deployment yang sesuai.
- Untuk deployment produksi, atur `JWT_SECRET`, `MFA_ENCRYPTION_KEY` (base64 untuk 32 byte acak), `SECURE_VAULT_DATA_DIR`, `SECURE_VAULT_STORAGE_DIR`, dan `SECURE_VAULT_CORS_ORIGINS` melalui lingkungan deployment. TLS tetap wajib dipasang di reverse proxy/web server.
- Ini baru Tahap 1. Kelemahan kuota/unggahan, transaksi database JSON, dan integritas hash-chain audit yang disebut pada laporan evaluasi masih perlu ditangani pada tahap berikutnya.
