# Secure Vault – Backend PHP Edition
Implementasi REST API Backend berbasis **PHP 8** untuk sistem **Secure Vault** dengan arsitektur **Zero-Knowledge 3-Layer Envelope Encryption** dan **Tamper-Resistant SHA-256 Hash-Chain Audit** yang memenuhi standar **ISO/IEC 15408-1:2022** & **ISO/IEC 18045:2026**.

---

## 🛡️ Arsitektur Keamanan
1. **Zero-Knowledge Guarantee**: Backend PHP tidak pernah menerima atau menyimpan kata sandi brankas (*passphrase*), *plaintext*, maupun kunci dekripsi tanpa proteksi. Seluruh enkripsi/dekripsi file (AES-256-GCM + Argon2id) berlangsung di browser klien.
2. **Stateless JWT Authentication**: Menggunakan token JWT HS256 dengan masa kedaluwarsa 15 menit dan multi-factor challenge (TOTP).
3. **Tamper-Resistant Hash Chain**: Setiap transaksi audit dicatat dengan hashing berantai SHA-256 (`current_hash = SHA256(prev_hash + timestamp + user + action + file + status)`) yang diverifikasi secara matematis.
4. **Isolated Storage**: Potongan ciphertext (*chunks*) disimpan secara terisolasi di luar jangkauan eksekusi skrip web.

---

## 🚀 Cara Menjalankan

### Cara 1: Menggunakan Script 1-Klik (Windows)
Cukup jalankan file:
```cmd
run_server.bat
```
Server PHP akan otomatis aktif di `http://127.0.0.1:5000`.

### Cara 2: Melalui Terminal / Command Line
Di dalam folder `backend_php`, jalankan:
```bash
php -S 127.0.0.1:5000 -t . index.php
```

### Cara 3: Melalui XAMPP / Apache
1. Salin atau symlink folder `backend_php` ke dalam `C:\xampp\htdocs\secure-vault-api`.
2. Pastikan modul `mod_rewrite` dan `mod_headers` diaktifkan pada `httpd.conf` Apache.
3. File `.htaccess` yang disertakan akan otomatis mengarahkan seluruh rute ke `index.php`.

---

## 🧪 Pengujian Integritas (Automated Tests)
Jalankan tes otomatis untuk memvalidasi hashing, JWT, dan verifikasi rantai audit:
```bash
php test_api.php
php test_e2e.php
```

---

## 📡 Daftar Endpoint API

| Method | Endpoint | Keterangan |
| :--- | :--- | :--- |
| `GET` | `/api/health` | Healthcheck & spesifikasi standar keamanan |
| `POST` | `/api/auth/register` | Pendaftaran akun baru |
| `POST` | `/api/auth/login` | Autentikasi kredensial & pemicu tantangan MFA |
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
