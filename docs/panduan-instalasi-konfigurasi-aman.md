# Panduan Instalasi dan Konfigurasi Aman Secure Vault

> **Referensi Desain Keamanan:** ISO/IEC 15408 dan ISO/IEC 18045. Dokumen dan referensi standar ini bukan merupakan klaim sertifikasi atau kesesuaian Common Criteria.

---

## 1. Pendahuluan dan Tujuan

**Secure Vault** adalah aplikasi web penyimpanan berkas berarsitektur *Zero-Knowledge Client-Side Encryption* dengan skema *3-Layer Envelope Encryption*:

- **Sisi Klien (Browser):** Penurunan kunci dari *passphrase* menggunakan **Argon2id** (WebAssembly, 64 MiB, 3 iterasi, paralelisme 1, keluaran 32 byte) untuk menghasilkan *Key Encryption Key* (KEK). KEK membungkus *Master Key* (AES-256-KW), *Master Key* membungkus *Data Encryption Key* (DEK) unik tiap berkas, dan setiap potongan berkas (*chunk* 5 MB) dienkripsi menggunakan **AES-256-GCM** dengan *Additional Authenticated Data* (AAD) berupa `fileId + chunkIndex` melalui Web Crypto API dan Web Worker.
- **Sisi Server (Backend):** REST API berbasis **PHP 8** yang menyimpan *ciphertext* dan metadata terenkripsi, menggunakan token sesi JWT (HS256), autentikasi multifaktor (TOTP) terenkripsi AES-256-GCM, basis data relasional **SQLite** (`pdo_sqlite`, skema versi 2), serta pencatatan log audit berantai (*hash-chain* SHA3-512).

**Tujuan dokumen ini** adalah menyediakan panduan resmi instalasi, inisialisasi, konfigurasi aman, operasional, dan verifikasi pasca-instalasi berdasarkan implementasi kode dan konfigurasi aktual pada repository Secure Vault.

---

## 2. Persyaratan Perangkat Keras dan Perangkat Lunak

### 2.1 Persyaratan Perangkat Lunak

Berdasarkan pemeriksaan pada `README.md`, `start_all_php.bat`, `backend_php/config.php`, `backend_php/db/Database.php`, `backend_php/utils/Totp.php`, dan `backend_php/utils/SmtpMailer.php`:

| Komponen | Kebutuhan Aktual | Keterangan |
| :--- | :--- | :--- |
| **PHP CLI & Runtime** | PHP 8.0 atau lebih baru | Wajib tersedia di `PATH` sistem. |
| **Ekstensi PHP Wajib** | `pdo_sqlite`, `openssl` | `pdo_sqlite` wajib untuk SQLite; `openssl` wajib untuk enkripsi/dekripsi secret MFA (`aes-256-gcm`) dan koneksi TLS/SSL SMTP. |
| **Ekstensi/Fitur Standar PHP** | `hash` (SHA3-512), `json`, `pdo`, `filter`, `pcre` | Umumnya aktif secara bawaan pada PHP 8+. |
| **Browser Klien** | Browser modern dengan Web Crypto API (`crypto.subtle`), WebAssembly, dan Web Worker | Disarankan Chrome atau Edge modern (mendukung `webkitdirectory` untuk unggah folder dan `showSaveFilePicker()` untuk *streaming download*). |
| **PowerShell (Windows)** | Windows PowerShell | Diperlukan bila menggunakan skrip `configure_gmail_smtp.bat` / `configure_gmail_smtp.ps1`. |
| **Python 3 & Node.js (Opsional)** | Python 3 dan Node.js | Hanya diperlukan untuk menjalankan suite pengujian regresi keamanan (`backend_php/tests/*.py` dan `frontend/diagnostics/crypto-rewrap-test.mjs`). Tidak diperlukan untuk menjalankan aplikasi. |

> [!NOTE]
> Frontend Secure Vault menggunakan HTML, CSS, dan JavaScript ES Modules native. **Tidak diperlukan** Node.js, `npm`, maupun proses *build* untuk menjalankan aplikasi.

### 2.2 Persyaratan Perangkat Keras

- **Spesifikasi minimum CPU dan RAM:** *Perlu dikonfirmasi* (tidak didefinisikan secara eksplisit di dalam kode maupun dokumentasi repository).
- **Ruang Penyimpanan (Disk):** *Perlu dikonfirmasi* untuk batas minimum sistem operasi; sebagai acuan kapasitas aplikasi, batas ukuran berkas unggahan adalah **500 MiB** per berkas (`chunk` 5 MB) dan kuota penyimpanan bawaan untuk akun administrator pertama pada `backend_php/scripts/init_admin.php` adalah **10 GiB** (`10737418240` byte). Sediakan ruang disk yang memadai di direktori data persisten.

---

## 3. Struktur Direktori Aplikasi

### 3.1 Struktur Repository

```text
secure-vault/
├── start_all_php.bat                # Launcher utama Windows (bootstrap, secret, backend, frontend)
├── configure_gmail_smtp.bat         # Wrapper CMD konfigurasi SMTP Gmail
├── configure_gmail_smtp.ps1         # Skrip interaktif konfigurasi SMTP Gmail (smtp.json)
├── README.md                        # Dokumentasi ringkas proyek
├── .gitignore                       # Pengecualian berkas sensitif/runtime dari Git
├── backend_php/
│   ├── index.php                    # Entry point REST API PHP
│   ├── config.php                   # Konfigurasi runtime, secret, CORS, dan direktori privat
│   ├── .htaccess                    # Aturan proteksi Apache untuk direktori backend
│   ├── .env.example                 # Contoh environment lama (lihat catatan pada Bagian 4)
│   ├── db/
│   │   ├── Database.php             # Adapter SQLite relasional, locking, transaksi, seed genesis
│   │   └── schema_sqlite.sql        # Skema relasional SQLite v2 (6 tabel)
│   ├── middleware/                  # Middleware autentikasi/otorisasi API
│   ├── routes/
│   │   ├── AdminRoutes.php          # Endpoint manajemen pengguna & statistik admin
│   │   ├── AuditRoutes.php          # Endpoint daftar & verifikasi rantai audit
│   │   ├── AuthRoutes.php           # Endpoint login, aktivasi, MFA, profil brankas
│   │   └── FileRoutes.php           # Endpoint folder, init upload, chunk, download, hapus
│   ├── scripts/
│   │   ├── bootstrap_data.php       # Inisialisasi direktori persisten & pemulihan instalasi lama
│   │   ├── init_local_secrets.php   # Pembuat secret lokal (JWT_SECRET & MFA_ENCRYPTION_KEY)
│   │   ├── init_admin.php           # Pembuat akun administrator pertama (hanya saat 0 user)
│   │   ├── promote_admin.php        # Promosi akun aktif menjadi administrator via CLI
│   │   ├── production_readiness.php # Pemeriksaan kesiapan & validasi konfigurasi (CLI)
│   │   ├── test_smtp.php            # Pengujian pengiriman email SMTP
│   │   ├── backup_sqlite.php        # Backup konsisten SQLite via VACUUM INTO
│   │   ├── verify_sqlite_backup.php # Verifikasi integritas & foreign key backup SQLite
│   │   ├── reconcile_storage.php    # Audit/karantina chunk atau direktori yatim
│   │   ├── export_audit_anchor.php  # Ekspor checkpoint HMAC rantai audit
│   │   ├── verify_audit_anchor.php  # Verifikasi checkpoint HMAC rantai audit
│   │   ├── migrate_relational.php   # Migrasi skema relasional v2
│   │   ├── migrate_json_to_sqlite.php
│   │   └── migrate_audit_v2.php
│   ├── tests/                       # Suite pengujian keamanan dan migrasi
│   └── utils/
│       ├── Activation.php           # Pembuatan & pengiriman tautan aktivasi akun
│       ├── Audit.php                # Pencatatan audit log SHA3-512
│       ├── Env.php                  # Pembaca variabel lingkungan (digunakan oleh RateLimiter)
│       ├── Jwt.php                  # Penandatanganan & verifikasi JWT HS256
│       ├── PersistentStorage.php    # Resolusi direktori persisten & pemulihan otomatis
│       ├── RateLimiter.php          # Pembatasan laju autentikasi
│       ├── Response.php             # Header keamanan HTTP, CORS, HSTS, dan output JSON/biner
│       ├── SmtpMailer.php           # Klien SMTP (TLS/SSL)
│       └── Totp.php                 # Generator & verifikator TOTP + enkripsi AES-256-GCM
├── frontend/
│   ├── index.html                   # Dokumen utama UI
│   ├── router.php                   # Server statis PHP + header CSP & keamanan browser
│   ├── run_frontend.bat             # Launcher frontend mandiri (port 5173)
│   ├── styles.css                   # Stylesheet aplikasi
│   ├── logo.png                     # Logo aplikasi
│   ├── argon2-bundled.min.js        # Runtime Argon2id WebAssembly
│   ├── js/
│   │   ├── api.js                   # Klien REST API & manajemen sesi JWT
│   │   ├── app.js                   # Logika antarmuka & alur fitur
│   │   ├── crypto.js                # Utilitas enkripsi envelope sisi klien
│   │   ├── crypto-worker.js         # Web Worker enkripsi/dekripsi AES-256-GCM
│   │   ├── crypto-worker-client.js  # Pembungkus komunikasi Web Worker
│   │   └── qr.js                    # Generator kode QR TOTP offline
│   ├── fonts/                       # Aset font lokal
│   ├── diagnostics/                 # Halaman & skrip uji mandiri Argon2 & Crypto Worker
│   └── src/                         # Berkas sumber React/TypeScript lama (tidak dipakai runtime aktif)
└── docs/                            # Dokumentasi proyek
```

### 3.2 Struktur Direktori Data Persisten (Di Luar Web Root)

Sesuai `backend_php/utils/PersistentStorage.php` dan `backend_php/config.php`, data runtime **wajib berada di luar web root** (`backend_php/`). Lokasi default `PRIVATE_DIR` ditentukan otomatis berdasarkan sistem operasi:

- **Windows:** `%LOCALAPPDATA%\SecureVault`
- **macOS:** `~/Library/Application Support/SecureVault`
- **Linux:** `$XDG_DATA_HOME/secure-vault` (atau `~/.local/share/secure-vault`)
- **Fallback:** `<root-proyek>/var/secure-vault`

Di dalam direktori persisten tersebut tersimpan:
- `secrets.php` — secret lokal pengembangan (`JWT_SECRET` dan `MFA_ENCRYPTION_KEY`) bila tidak disetel via environment variable.
- `smtp.json` — konfigurasi SMTP lokal (bila dikonfigurasi melalui `configure_gmail_smtp.ps1`).
- `data/secure-vault.sqlite` — basis data SQLite aktif (bersama berkas `-wal`, `-shm`, dan `database.lock`).
- `storage/` — direktori penyimpanan potongan berkas terenkripsi (*ciphertext chunks*).
- `backups/` — direktori cadangan saat proses bootstrap/pemulihan.

---

## 4. Persiapan Lingkungan Instalasi

1. **Verifikasi PHP CLI dan Ekstensi:**
   Jalankan perintah berikut di terminal untuk memastikan PHP 8+ serta ekstensi `pdo_sqlite` dan `openssl` aktif:
   ```bash
   php -v
   php -m
   ```
   Jika `pdo_sqlite` atau `openssl` belum muncul pada daftar modul, aktifkan pada berkas `php.ini` (`extension=pdo_sqlite` dan `extension=openssl`).

2. **Pastikan Lokasi Runtime di Luar Web Root:**
   `backend_php/config.php` memeriksa secara ketat bahwa `PRIVATE_DIR`, `DATA_DIR`, dan `STORAGE_DIR` tidak berada di dalam `backend_php/`. Jika variabel lingkungan kustom (`SECURE_VAULT_PERSISTENT_DIR`, `SECURE_VAULT_HOME`, `SECURE_VAULT_DATA_DIR`, atau `SECURE_VAULT_STORAGE_DIR`) diarahkan ke dalam `backend_php/`, aplikasi akan melempar eksepsi dan menolak berjalan.

3. **Catatan Penting Mengenai Berkas `.env`:**
   - Pada implementasi aktual, `backend_php/config.php` dan `backend_php/index.php` **tidak memanggil** `Env::load()` untuk membaca berkas `.env` secara otomatis. Variabel konfigurasi dibaca langsung dari *environment variable* sistem operasi atau konfigurasi web server melalui `getenv()`.
   - Berkas `backend_php/.env.example` memuat beberapa nama variabel lama (seperti `SV_DATA_DIR`, `DEMO_MODE`, `ALLOW_REGISTRATION`, `ADMIN_PASSWORD`) yang **tidak digunakan** oleh `backend_php/config.php`. Gunakan daftar variabel aktual pada **Bagian 7** dan **Bagian 8**.

---

## 5. Langkah Instalasi Secure Vault

### Opsi A: Instalasi Lokal pada Windows (Satu Klik)

1. Ekstrak atau clone repository Secure Vault ke direktori kerja (misalnya di luar folder sementara).
2. Jalankan `start_all_php.bat` dari root proyek (klik dua kali atau melalui Command Prompt):
   ```cmd
   start_all_php.bat
   ```
3. Skrip tersebut akan secara otomatis:
   - Memeriksa keberadaan PHP CLI dan ekstensi `pdo_sqlite`.
   - Menjalankan `php backend_php\scripts\bootstrap_data.php` untuk menyiapkan direktori persisten di `%LOCALAPPDATA%\SecureVault` (atau memulihkan instalasi lama secara otomatis bila ditemukan satu kandidat valid).
   - Menjalankan `php backend_php\scripts\init_local_secrets.php` untuk membuat `secrets.php` bila `JWT_SECRET` dan `MFA_ENCRYPTION_KEY` belum disetel di environment.
   - Menjalankan backend PHP di `http://127.0.0.1:5000` dan frontend statis di `http://127.0.0.1:5173`.

> [!WARNING]
> Bila `bootstrap_data.php` berhenti dengan status `AMBIGUOUS_CANDIDATES` (ditemukan lebih dari satu kandidat database lama), tetapkan variabel `SECURE_VAULT_SOURCE_DIR` ke folder data sumber yang benar sebelum menjalankan ulang launcher:
> ```cmd
> set SECURE_VAULT_SOURCE_DIR=C:\path\ke\folder_data_terpilih
> ```

### Opsi B: Instalasi Manual / Lintas Platform (Linux, macOS, atau Windows CLI)

Dari direktori root proyek:

1. **Siapkan direktori data persisten:**
   ```bash
   php backend_php/scripts/bootstrap_data.php
   ```
2. **Siapkan secret aplikasi:**
   - Untuk lingkungan **pengembangan lokal**:
     ```bash
     php backend_php/scripts/init_local_secrets.php
     ```
   - Untuk lingkungan **produksi / deployment**, tetapkan `JWT_SECRET` dan `MFA_ENCRYPTION_KEY` langsung pada environment variable sistem/web server (lihat Bagian 7) tanpa bergantung pada `init_local_secrets.php`.

### Catatan untuk Deployment Produksi (Non-Localhost)

- Skrip `start_production.bat` di root proyek merujuk pada `frontend\dist\index.html` dan `npm run build` (struktur React/Vite terdahulu). Penggunaan `start_production.bat` pada build native saat ini **Perlu dikonfirmasi**.
- Pada deployment server produksi di balik Nginx, Apache, atau reverse proxy HTTPS:
  - Sajikan direktori `frontend/` sebagai situs statis dengan header keamanan HTTP yang setara dengan `frontend/router.php` (termasuk `Content-Security-Policy`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`).
  - Arahkan permintaan `/api/*` ke `backend_php/index.php` atau atur `window.SECURE_VAULT_API_URL` sebelum `js/app.js` dimuat di `frontend/index.html`, serta sesuaikan `SECURE_VAULT_CORS_ORIGINS`.
  - Pastikan berkas sensitif (`config.php`, `.htaccess`, `README.md`, berkas `.json`/`.sql`/`.env`/`.log`) diblokir dari akses web (`backend_php/.htaccess` menyediakan aturan dasar untuk Apache).
  - Contoh konfigurasi lengkap Nginx/Apache VirtualHost produksi **Perlu dikonfirmasi** (tidak tersedia di repository).

---

## 6. Inisialisasi Database dan Administrator Pertama

Secure Vault **tidak menyediakan** akun bawaan, akun demo, maupun kata sandi default.

### 6.1 Inisialisasi Skema Database

Database SQLite (`data/secure-vault.sqlite`) diinisialisasi otomatis oleh `Database.php` saat pertama kali diakses melalui aplikasi atau skrip CLI. Sistem menerapkan:
- `PRAGMA journal_mode=WAL`
- `PRAGMA synchronous=FULL`
- `PRAGMA foreign_keys=ON`
- Skema relasional v2 (`backend_php/db/schema_sqlite.sql`, `PRAGMA user_version = 2`) dengan tabel `users`, `vault_profiles`, `encrypted_files`, `file_chunks`, `audit_logs`, dan `auth_rate_limits`.
- Entri awal log audit `SYSTEM_GENESIS` dengan hash SHA3-512.

Jika meng-upgrade dari database JSON lama (`database.json`) atau skema SQLite `vault_records` v1, migrasi berjalan otomatis atau dapat dijalankan eksplisit melalui:
```bash
php backend_php/scripts/migrate_relational.php
```
*(Selalu buat cadangan terlebih dahulu sebelum migrasi).*

### 6.2 Membuat Administrator Pertama

Jalankan perintah berikut dari root proyek (secara interaktif):

```bash
php backend_php/scripts/init_admin.php
```

Atau dengan argumen CLI:

```bash
php backend_php/scripts/init_admin.php <username> <password> <email>
```

**Ketentuan & mekanisme keamanan `init_admin.php`:**
- Hanya dapat dijalankan melalui PHP CLI (`PHP_SAPI === 'cli'`).
- **Hanya berjalan jika database memiliki 0 pengguna.** Begitu satu akun administrator dibuat, mekanisme inisialisasi admin ini **dinonaktifkan secara permanen** dan akan menolak eksekusi berikutnya.
- Validasi input:
  - Username: 3–32 karakter (`a-z`, `A-Z`, `0-9`, `_`, `-`, `.`).
  - Email: format email valid.
  - Password: **minimal 12 karakter** dan tidak boleh termasuk daftar password umum/bawaan yang dilarang.
- Password di-hash dengan `PASSWORD_ARGON2ID` (atau `PASSWORD_DEFAULT` bila Argon2id tidak tersedia pada build PHP).

### 6.3 Mempromosikan Akun Lain Menjadi Administrator (Opsional)

Untuk memberikan hak administrator kepada pengguna yang sudah aktif:
1. Hentikan proses backend PHP terlebih dahulu.
2. Jalankan perintah berikut dari root proyek dan ketik ulang username saat diminta konfirmasi:
   ```bash
   php backend_php/scripts/promote_admin.php <USERNAME>
   ```
3. Jalankan kembali backend PHP.

---

## 7. Konfigurasi Secret dan Keamanan Aplikasi

Berikut perbedaan antara konfigurasi yang sudah otomatis tersedia untuk pengembangan lokal dan konfigurasi yang **wajib** diatur oleh administrator untuk lingkungan produksi.

### 7.1 Ringkasan Status Konfigurasi

| Variabel / Berkas | Pengembangan Lokal (Default) | Produksi / Deployment (Wajib oleh Admin) |
| :--- | :--- | :--- |
| `JWT_SECRET` | Dibuat otomatis ke `secrets.php` oleh `init_local_secrets.php` atau `config.php`. | **Wajib** disetel via environment variable: string acak kriptografis minimal **32 byte**. Jangan gunakan `secrets.php` lokal. |
| `MFA_ENCRYPTION_KEY` | Dibuat otomatis ke `secrets.php` oleh `init_local_secrets.php` atau `config.php`. | **Wajib** disetel via environment variable: **base64 dari 32 byte acak** (kunci AES-256-GCM untuk secret TOTP). |
| `JWT_TTL_SECONDS` | Default `28800` (8 jam, *sliding session*). | Opsional; rentang yang diizinkan `900` hingga `86400` detik. |
| `SECURE_VAULT_CORS_ORIGINS` | Default: `http://localhost:5173`, `http://127.0.0.1:5173`, `http://localhost:3000`, `http://127.0.0.1:3000`. | **Wajib** disetel ke origin HTTPS frontend produksi (dipisahkan koma). |
| `SECURE_VAULT_APP_URL` | Default: `http://127.0.0.1:5173`. | **Wajib** disetel ke URL **HTTPS** publik aplikasi sebelum admin membuat akun pengguna (dipakai pada tautan aktivasi email). |
| `SECURE_VAULT_ENABLE_HSTS` | Tidak aktif (default). | Setel `1` **hanya** jika aplikasi berjalan di belakang HTTPS/TLS yang tervalidasi. |
| `TRUST_PROXY` | Default `false`. | Setel `true` **hanya** jika berada di belakang reverse proxy tepercaya (agar pembacaan `HTTP_X_FORWARDED_FOR` untuk *rate limit* akurat). |
| `SECURE_VAULT_PERSISTENT_DIR` / `SECURE_VAULT_HOME` | Otomatis ke `%LOCALAPPDATA%\SecureVault` (Windows) atau direktori data user OS. | Opsional; atur ke direktori privat khusus di luar web root jika ingin lokasi tetap. |
| `SECURE_VAULT_DATA_DIR` & `SECURE_VAULT_STORAGE_DIR` | Otomatis di bawah `PRIVATE_DIR`. | Opsional; jika disetel, **wajib** berada di luar web root (`backend_php/`). |
| `AUDIT_ANCHOR_HMAC_KEY` | Tidak disetel. | Opsional (CLI-only); base64 dari 32 byte acak untuk `export_audit_anchor.php` & `verify_audit_anchor.php`. Jangan berikan ke proses web/PHP-FPM. |

### 7.2 Contoh Pembuatan Nilai Secret (Jangan Simpan Nilai Asli di Repository)

Untuk menghasilkan secret acak yang memenuhi syarat melalui PHP CLI:

```bash
# Menghasilkan JWT_SECRET (64 karakter hex / 32 byte acak)
php -r "echo bin2hex(random_bytes(32)) . PHP_EOL;"

# Menghasilkan MFA_ENCRYPTION_KEY atau AUDIT_ANCHOR_HMAC_KEY (base64 dari 32 byte acak)
php -r "echo base64_encode(random_bytes(32)) . PHP_EOL;"
```

Simpan nilai hasil generator tersebut pada pengelola secret atau environment variable sistem, **bukan** di dalam repository Git maupun file yang dapat diakses publik.

---

## 8. Konfigurasi Email SMTP

Konfigurasi SMTP **wajib dilakukan sebelum administrator membuat akun pengguna baru**. Tanpa konfigurasi SMTP yang valid, pembuatan akun melalui Konsol Admin akan ditolak karena sistem tidak dapat mengirim tautan aktivasi sekali pakai (berlaku 24 jam).

### 8.1 Opsi 1: Menggunakan Skrip Gmail SMTP (Windows)

Jika menggunakan akun Gmail:
1. Aktifkan **Verifikasi 2 Langkah** pada akun Google Anda.
2. Buat **App Password** (16 karakter) di pengaturan keamanan akun Google (jangan gunakan kata sandi login Gmail biasa).
3. Jalankan skrip dari root proyek:
   ```cmd
   configure_gmail_smtp.bat
   ```
4. Masukkan alamat Gmail pengirim dan App Password 16 karakter saat diminta.
5. Skrip `configure_gmail_smtp.ps1` akan menyimpan konfigurasi ke `smtp.json` di direktori persisten (`%LOCALAPPDATA%\SecureVault\smtp.json`, atau `$env:SECURE_VAULT_PERSISTENT_DIR\smtp.json`, atau `var\secure-vault\smtp.json`) dengan port `465` dan enkripsi `ssl`, lalu otomatis menjalankan `backend_php/scripts/test_smtp.php` untuk mengirim email uji ke alamat pengirim.

### 8.2 Opsi 2: Menggunakan Environment Variable (Semua Platform / Penyedia SMTP)

Tetapkan variabel lingkungan berikut pada lingkungan backend sebelum menjalankan aplikasi:

```powershell
# Contoh PowerShell (ganti seluruh nilai dengan konfigurasi penyedia SMTP Anda)
$env:SECURE_VAULT_SMTP_HOST = 'smtp.example.com'
$env:SECURE_VAULT_SMTP_PORT = '587'
$env:SECURE_VAULT_SMTP_ENCRYPTION = 'tls'
$env:SECURE_VAULT_SMTP_FROM = 'vault@example.com'
$env:SECURE_VAULT_SMTP_USER = 'vault@example.com'
$env:SECURE_VAULT_SMTP_PASSWORD = '<kata-sandi-atau-app-password-smtp>'
```

Aturan penting pada `backend_php/utils/SmtpMailer.php`:
- Nilai `SECURE_VAULT_SMTP_ENCRYPTION` yang valid adalah `tls` (STARTTLS, umumnya port 587), `ssl` (SMTPS, umumnya port 465), atau `none` (**hanya diizinkan** jika host adalah `localhost`, `127.0.0.1`, atau `::1`).
- Jika `SECURE_VAULT_SMTP_HOST` didefinisikan di environment variable, seluruh parameter SMTP diambil dari environment (tidak dicampur dengan `smtp.json`).
- Untuk menguji konfigurasi SMTP kapan saja melalui CLI:
  ```bash
  php backend_php/scripts/test_smtp.php
  ```

---

## 9. Menjalankan dan Menghentikan Aplikasi

### 9.1 Menjalankan Aplikasi

- **Windows (satu perintah):**
  ```cmd
  start_all_php.bat
  ```
- **Manual / Lintas Platform (2 terminal terpisah):**
  - **Terminal 1 (Backend PHP, dari root proyek):**
    ```bash
    php -d upload_max_filesize=8M -d post_max_size=10M -d max_execution_time=120 -d max_input_time=120 -S 127.0.0.1:5000 -t backend_php backend_php/index.php
    ```
  - **Terminal 2 (Frontend statis, dari direktori `frontend/`):**
    ```bash
    php -S 127.0.0.1:5173 router.php
    ```

### 9.2 Menghentikan Aplikasi

- Pada mode pengembangan (`start_all_php.bat` atau terminal manual): tekan `Ctrl + C` pada masing-masing terminal backend dan frontend, atau tutup kedua jendela Command Prompt server yang terbuka.
- Pada mode layanan server produksi (misalnya `systemd` atau PHP-FPM/Nginx): *Perlu dikonfirmasi* sesuai manajer proses yang digunakan administrator di server tujuan.

---

## 10. Verifikasi Instalasi Berhasil

Lakukan langkah-langkah berikut setelah instalasi dan konfigurasi selesai:

1. **Jalankan Pemeriksaan Kesiapan Sistem (CLI):**
   ```bash
   php backend_php/scripts/production_readiness.php
   ```
   Pastikan keluaran JSON menunjukkan `"status": "PASS"` (atau cek bagian `blockers`/`checks` bila ada yang masih `BLOCKED`/`FAIL`).

2. **Verifikasi Endpoint Healthcheck API:**
   Buka `http://127.0.0.1:5000/api/health` melalui browser atau `curl` / `Invoke-RestMethod`. Respons harus mengembalikan HTTP 200 dengan JSON berisi `"status": "OK"`.

3. **Verifikasi Uji Pengiriman SMTP:**
   ```bash
   php backend_php/scripts/test_smtp.php
   ```
   Pastikan muncul pesan sukses dan email uji diterima di kotak masuk (atau folder Spam) alamat pengirim.

4. **Verifikasi Login Administrator dan Penyiapan MFA:**
   - Buka `http://127.0.0.1:5173` di browser.
   - Masuk menggunakan akun administrator yang dibuat melalui `init_admin.php`.
   - Siapkan autentikasi TOTP (pindai kode QR pada aplikasi authenticator) serta buat *passphrase* brankas untuk menguji pembukaan brankas dan akses Konsol Admin.

5. **Verifikasi Modul Kriptografi Browser (Opsional):**
   - Buka `http://127.0.0.1:5173/diagnostics/argon2-self-test.html` untuk menguji derivasi Argon2id WebAssembly.
   - Buka `http://127.0.0.1:5173/diagnostics/crypto-worker-self-test.html` untuk menguji Web Worker enkripsi/dekripsi.

---

## 11. Pemeriksaan Keamanan Setelah Instalasi

Setelah sistem berjalan, pastikan daftar periksa keamanan berikut terpenuhi:

- [ ] **Status `production_readiness.php` adalah `PASS`:** Memastikan `private_data_outside_webroot`, `private_storage_outside_webroot`, `data_dir_not_world_writable`, `storage_dir_not_world_writable`, `jwt_secret_minimum_length`, `mfa_key_32_bytes`, `database_wal_mode`, `relational_schema_version` (`2`), `foreign_key_violations` (`0`), dan `legacy_generic_table_absent` semuanya `true`.
- [ ] **Inisialisasi admin terkunci:** Menjalankan `php backend_php/scripts/init_admin.php` ulang harus ditolak dengan pesan `SETUP DITOLAK`.
- [ ] **Tidak ada berkas sensitif di web root:** Pastikan `secrets.php`, `smtp.json`, `secure-vault.sqlite`, dan folder `storage/` tidak berada di dalam `backend_php/` atau `frontend/` serta tidak dapat diakses melalui HTTP.
- [ ] **Header keamanan aktif:** Verifikasi respons HTTP API dan frontend menyertakan `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Permissions-Policy`, dan `Content-Security-Policy`.
- [ ] **HTTPS & HSTS (Produksi):** Pastikan seluruh akses produksi menggunakan HTTPS yang valid, `SECURE_VAULT_APP_URL` diawali `https://`, `SECURE_VAULT_CORS_ORIGINS` hanya mencantumkan origin produksi resmi, dan `SECURE_VAULT_ENABLE_HSTS=1` hanya diaktifkan di belakang TLS.
- [ ] **Cadangan awal & verifikasi database:** Buat dan uji cadangan SQLite pertama:
  ```bash
  php backend_php/scripts/backup_sqlite.php /path/ke/backup-awal.sqlite
  php backend_php/scripts/verify_sqlite_backup.php /path/ke/backup-awal.sqlite
  ```
- [ ] **Pengujian regresi keamanan (untuk audit/pengujian sebelum rilis):**
  ```bash
  node --experimental-default-type=module frontend/diagnostics/crypto-rewrap-test.mjs
  php backend_php/tests/mfa_challenge_lock_test.php
  python backend_php/tests/security_stage1.py
  python backend_php/tests/security_stage2.py
  python backend_php/tests/frontend_security_static.py
  ```

---

## 12. Troubleshooting Instalasi

| Gejala / Pesan Error | Penyebab Umum | Solusi |
| :--- | :--- | :--- |
| `PHP CLI tidak ditemukan` atau `Ekstensi pdo_sqlite belum aktif` | PHP 8+ belum terpasang di `PATH` atau ekstensi `pdo_sqlite` mati di `php.ini`. | Pasang PHP 8+ dan aktifkan `extension=pdo_sqlite` serta `extension=openssl` pada `php.ini`. |
| `JWT_SECRET is not configured` atau `MFA_ENCRYPTION_KEY is not configured or invalid` | Secret belum disetel di environment dan `secrets.php` belum dibuat atau rusak. | Jalankan `php backend_php/scripts/init_local_secrets.php` (lokal) atau setel `JWT_SECRET` (min. 32 byte) dan `MFA_ENCRYPTION_KEY` (base64 dari 32 byte) di environment. |
| `Secure Vault runtime data and secrets must be stored outside the web root` | `SECURE_VAULT_PERSISTENT_DIR`, `SECURE_VAULT_DATA_DIR`, atau `SECURE_VAULT_STORAGE_DIR` mengarah ke dalam `backend_php/`. | Pindahkan direktori data/storage ke lokasi di luar `backend_php/`. |
| `Ditemukan lebih dari satu kandidat database lama` (`STATUS_AMBIGUOUS_CANDIDATES`) | Ada beberapa file `secure-vault.sqlite` dari instalasi terdahulu yang terdeteksi saat bootstrap. | Tetapkan `SECURE_VAULT_SOURCE_DIR` ke direktori data yang ingin dipulihkan sebelum menjalankan aplikasi. |
| `SETUP DITOLAK: Sistem sudah memiliki akun terdaftar` | `init_admin.php` dijalankan saat database sudah memiliki minimal satu user. | Gunakan akun admin yang sudah ada, atau promosikan user terdaftar dengan `php backend_php/scripts/promote_admin.php <USERNAME>`. |
| `SMTP belum diatur` atau `Gmail menolak login SMTP` | `smtp.json` / `SECURE_VAULT_SMTP_*` belum diatur, atau memakai kata sandi akun Gmail biasa alih-alih App Password 16 karakter. | Jalankan ulang `configure_gmail_smtp.bat` dengan App Password 16 karakter, atau periksa variabel `SECURE_VAULT_SMTP_*`. Uji jaringan port 465 (`Test-NetConnection smtp.gmail.com -Port 465`) dan jalankan `test_smtp.php`. |
| `Tidak dapat terhubung ke server Secure Vault` atau error CORS di browser | Backend PHP port `5000` belum berjalan, alamat API berbeda, atau origin frontend belum terdaftar di `SECURE_VAULT_CORS_ORIGINS`. | Pastikan backend berjalan di `127.0.0.1:5000`, periksa `window.SECURE_VAULT_API_URL`, dan tambahkan origin frontend ke `SECURE_VAULT_CORS_ORIGINS`. |
| Fitur enkripsi/Argon2id gagal di browser | Aplikasi diakses melalui alamat HTTP non-localhost (Web Crypto API diblokir oleh browser pada *insecure origin*). | Akses melalui `http://127.0.0.1:5173` / `http://localhost:5173` secara lokal, atau gunakan **HTTPS** pada deployment. |
