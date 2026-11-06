# Secure Vault – Backend PHP Edition
Implementasi REST API berbasis **PHP 8** untuk Secure Vault dengan arsitektur **3-Layer Envelope Encryption** dan audit hash-chain SHA-256. Dokumen standar merupakan acuan desain, bukan bukti kesesuaian atau sertifikasi Common Criteria. Runtime V9 memakai enam tabel SQLite per entitas dengan foreign key, indeks, constraint unik, dan transaksi UPSERT per-record. Kolom payload JSON masih dipertahankan sementara agar kompatibel dengan service layer array; global process lock dan request snapshot masih membatasi konkurensi multi-worker.

---

## 🛡️ Arsitektur Keamanan
1. **Zero-Knowledge Guarantee**: Backend PHP tidak pernah menerima atau menyimpan kata sandi brankas (*passphrase*), *plaintext*, maupun kunci dekripsi tanpa proteksi. Seluruh enkripsi/dekripsi file (AES-256-GCM + Argon2id) berlangsung di browser klien.
2. **Stateless JWT Authentication**: Menggunakan token JWT HS256 dengan masa berlaku 8 jam bergulir (diperbarui pada setiap aktivitas API terautentikasi) dan tantangan MFA/TOTP 20 menit. Pencabutan sesi administrator tetap berlaku melalui session_version.
3. **Hash-Chain Audit**: Transaksi audit dicatat dengan hash berantai SHA-256; cakupan atribut yang di-hash dan penyimpanan audit independen masih menjadi pekerjaan lanjutan sebelum sistem dapat mengklaim ketahanan manipulasi.
4. **Isolated Storage**: Potongan ciphertext (*chunks*) disimpan secara terisolasi di luar jangkauan eksekusi skrip web. Batas upload PHP disetel 8 MiB per request agar chunk plaintext 5 MiB beserta overhead multipart dapat diterima.

---

## 🚀 Cara Menjalankan

### Cara 1: Menggunakan Script 1-Klik (Windows)
Jalankan `start_all_php.bat` dari root proyek atau `backend_php/run_server.bat`. Launcher membuat secret lokal acak satu kali di `var/secure-vault/secrets.php`, di luar web root, lalu server PHP aktif di `http://127.0.0.1:5000`. Jangan commit file secret itu. Untuk produksi, gunakan secret yang dikelola environment/deployment.

### Cara 2: Melalui Terminal / Command Line
Dari root proyek, inisialisasi secret lokal lalu jalankan server:
```bash
php backend_php/scripts/init_local_secrets.php
php -d upload_max_filesize=8M -d post_max_size=10M -d max_execution_time=120 -d max_input_time=120 -S 127.0.0.1:5000 -t backend_php backend_php/index.php
```

### Cara 3: Melalui XAMPP / Apache
1. Salin atau symlink folder `backend_php` ke dalam `C:\xampp\htdocs\secure-vault-api`.
2. Pada `php.ini` yang digunakan Apache, set `upload_max_filesize=8M`, `post_max_size=10M`, `max_execution_time=120`, dan `max_input_time=120`, lalu restart Apache.
3. Pastikan ekstensi `pdo_sqlite` serta modul `mod_rewrite` dan `mod_headers` diaktifkan.
4. File `.htaccess` yang disertakan akan mengarahkan seluruh rute ke `index.php`.

---

## 🔐 Registrasi, TOTP, dan administrator
- Semua pendaftaran melalui API menetapkan `role=user`; nilai role dari browser diabaikan.
- Login pertama menampilkan QR TOTP lokal di browser (tanpa layanan QR pihak ketiga), dengan secret manual sebagai opsi cadangan. JWT hanya diterbitkan sesudah kode TOTP valid.
- Secret TOTP dienkripsi di database runtime memakai `MFA_ENCRYPTION_KEY`.
- Tidak ada akun demo atau MFA universal.
- Untuk mempromosikan akun yang sudah terdaftar menjadi administrator, jalankan dari root proyek: `php backend_php/scripts/promote_admin.php USERNAME` dan konfirmasi nama pengguna. Script hanya bekerja di CLI.
- Runtime database dan storage disimpan di `var/secure-vault/` di luar web root secara default. Upgrade dari skema generik `vault_records` ke skema relasional V2 berjalan otomatis saat database pertama kali dibuka oleh build ini; sistem membuat backup SQLite pra-migrasi yang terverifikasi di direktori data privat sebelum migrasi.

## 🧪 Pengujian regresi keamanan
Dari root proyek, jalankan:
```bash
node --experimental-default-type=module frontend/diagnostics/crypto-rewrap-test.mjs
php backend_php/tests/mfa_challenge_lock_test.php
python backend_php/tests/security_stage1.py
python backend_php/tests/security_stage2.py
find backend_php -name '*.php' -print0 | xargs -0 -n1 php -l
```
Tes regresi memulai API lokal dengan direktori data sementara dan memvalidasi pendaftaran peran, enrollment/verifikasi TOTP, hashing password, akses admin, klaim JWT, CORS, unggah/kuota, idempotensi, serta audit. Kedua suite melakukan preflight `pdo_sqlite` dan melaporkan status BLOCKED secara eksplisit jika ekstensi tidak aktif. Tes belum menggantikan audit keamanan independen.

---

## 📡 Daftar Endpoint API

| Method | Endpoint | Keterangan |
| :--- | :--- | :--- |
| `GET` | `/api/health` | Healthcheck & spesifikasi standar keamanan |
| `POST` | `/api/auth/register` | Pendaftaran akun baru |
| `POST` | `/api/auth/login` | Autentikasi kredensial & pemicu tantangan MFA |
| `POST` | `/api/auth/mfa/setup` | Memulai enrollment TOTP setelah verifikasi password |
| `POST` | `/api/auth/mfa/verify` | Validasi kode MFA TOTP & penerbitan JWT |
| `GET` | `/api/auth/me` | Profil data pengguna aktif |
| `GET` | `/api/auth/vault-profile` | Mengambil salt & master key ter-wrap |
| `POST` | `/api/auth/setup-vault` | Inisialisasi awal brankas Zero-Knowledge |
| `POST` | `/api/auth/rewrap-master-key`| Update passphrase (re-wrap Master Key) |
| `GET` | `/api/files` | Daftar file terenkripsi milik pengguna |
| `POST` | `/api/files/init` | Inisialisasi metadata unggah berkas |
| `POST` | `/api/files/{id}/chunk/{idx}` | Unggah 5MB ciphertext chunk |
| `POST` | `/api/files/{id}/complete` | Menyelesaikan proses unggah berkas |
| `GET` | `/api/files/{id}/chunk/{idx}/meta` | Mengambil IV dan AAD untuk dekripsi chunk |
| `GET` | `/api/files/{id}/chunk/{idx}/data` | Streaming binary ciphertext chunk |
| `PATCH`| `/api/files/{id}/metadata` | Memperbarui nama/tag terenkripsi |
| `DELETE`| `/api/files/{id}` | Pemusnahan berkas dan seluruh chunk |
| `GET` | `/api/audit` | Riwayat log audit (anti-tamper) |
| `GET` | `/api/audit/verify` | Verifikasi integritas rantai SHA-256 |
| `GET` | `/api/admin/users` | [Admin] Daftar seluruh pengguna |
| `GET` | `/api/admin/stats` | [Admin] Telemetri sistem & integritas rantai |
| `PATCH`| `/api/admin/users/{id}/quota` | [Admin] Alokasi kuota penyimpanan |
| `POST` | `/api/admin/users/{id}/revoke`| [Admin] Pencabutan sesi pengguna |


## Runtime database

Runtime memakai SQLite melalui ekstensi PHP `pdo_sqlite`. Database berada di `var/secure-vault/data/secure-vault.sqlite` di luar web root. Pada pembukaan pertama, koleksi dari `database.json` lama diimpor otomatis jika database SQLite belum berisi data; JSON sumber tetap dipertahankan sebagai backup.


## Iterasi 2 — V6

- API file tidak lagi menyimpan fingerprint SHA-256 plaintext. Field legacy dihapus dari record SQLite aktif saat database dimuat. AES-GCM dan AAD mengautentikasi setiap chunk.
- Mutasi file yang didukung menggabungkan perubahan metadata/kuota dan audit entry dalam satu commit SQLite melalui `Database::transaction()`.
- Penghapusan memasang tombstone `deletion_pending` lebih dahulu. Jika cleanup filesystem gagal atau proses terhenti, ulangi endpoint DELETE untuk melanjutkan; akses file tetap diblokir sampai selesai.
- `scripts/export_audit_anchor.php` dan `scripts/verify_audit_anchor.php` membuat serta memverifikasi checkpoint audit ber-HMAC. Simpan key hanya pada sesi CLI tepercaya dan simpan checkpoint di lokasi eksternal/offline/WORM.
- Model database masih generik JSON-record di SQLite dan `save()` masih menulis ulang koleksi; migrasi relasional dan penghapusan global lock belum termasuk iterasi ini.


## Iterasi 5 / V9 — skema relasional SQLite

Skema SQLite aktif berada di `db/schema_sqlite.sql` dan menggunakan `PRAGMA user_version=2`. Koleksi generik lama dipindahkan ke tabel `users`, `vault_profiles`, `encrypted_files`, `file_chunks`, `audit_logs`, dan `auth_rate_limits`. Migrasi memeriksa keadaan ambigu, mengurutkan insert sesuai foreign key, menghapus fingerprint plaintext legacy, lalu menghapus `vault_records` hanya setelah migrasi berhasil dalam transaksi yang sama.

Sebelum migrasi database V8, adapter membuat snapshot `VACUUM INTO` dan memvalidasi `PRAGMA integrity_check`. Snapshot disimpan dengan permission privat; jangan dihapus sebelum database V9 dan backup storage diverifikasi.

Pengujian tahap ini:

```bash
python backend_php/tests/iteration5_relational_static_test.py
python backend_php/tests/iteration5_sqlite_integration_test.py
php backend_php/tests/relational_migration_integration.php
```

Python test memvalidasi skema pada SQLite engine. PHP integration test memvalidasi adapter/migrasi PDO yang sebenarnya, dan membutuhkan ekstensi `pdo_sqlite`. Payload JSON merupakan lapisan kompatibilitas sementara; penghapusan global lock belum dilakukan.
