# 🛡️ Secure Vault

> **Zero-Knowledge 3-Layer Envelope Encryption Web Application**  
> Referensi desain keamanan: **ISO/IEC 15408** dan **ISO/IEC 18045**. Proyek ini tidak menyatakan sertifikasi atau kesesuaian Common Criteria.

## Fitur utama

- **Zero-Knowledge Architecture**: enkripsi dan dekripsi berkas dilakukan di sisi klien menggunakan Web Crypto API (`crypto.subtle`) dan Argon2id WebAssembly.
- **3-Layer Envelope Encryption**: passphrase diturunkan menjadi KEK memakai Argon2id; KEK membungkus Master Key (AES-256-KW); Master Key membungkus DEK unik setiap berkas; potongan berkas 5 MB dienkripsi dengan AES-256-GCM dan AAD (`fileId + chunkIndex`).
- **SHA-256 Hash-Chain Audit**: jejak audit berantai mendeteksi perubahan yang tidak menghitung ulang rantai. Runtime JSON/SQLite bukan jaminan penyimpanan audit immutable atau anti-manipulasi terhadap operator server.
- **Backend**: REST API berbasis PHP 8, OpenSSL, HS256 JWT, chunk streaming, dan SQLite melalui PDO_SQLite.
- **Frontend native**: HTML, CSS, dan JavaScript ES Modules tanpa React, TypeScript, Vite, Node.js, npm, atau proses build.
- **Pratinjau lokal**: PDF, gambar, TXT, CSV, JSON, dan Markdown setelah berkas didekripsi di browser.
- **Folder terenkripsi**: buat folder dan subfolder, unggah folder dari perangkat, lalu buka isinya di dashboard. Nama folder dienkripsi di browser; server hanya menyimpan hubungan antar-ID folder.

## Folder dan unggah folder

Di dashboard, pilih **+ Baru → Folder baru** untuk membuat folder pada lokasi saat ini. Pilih **+ Baru → Upload folder** untuk mengunggah struktur folder beserta berkasnya. Setiap berkas tetap melewati validasi dan enkripsi chunk yang sama dengan unggah berkas biasa. Folder hanya dapat dihapus setelah isinya kosong.

Pemilihan folder menggunakan dukungan `webkitdirectory` pada browser seperti Chrome atau Edge. Pemilih tersebut tidak mengembalikan direktori kosong, sehingga subfolder kosong perlu dibuat melalui **Folder baru**. Batas satu pemilihan adalah 1.000 berkas, dan batas tiap berkas tetap 500 MiB.

## Memulai aplikasi

### Prasyarat

- PHP 8.0 atau lebih baru.
- Ekstensi PHP `pdo_sqlite` aktif.
- Browser modern yang mendukung Web Crypto API. Untuk penggunaan lokal, akses lewat `localhost` agar fitur kriptografi browser tersedia.

### Windows: jalankan dengan satu klik

Klik dua kali:

```cmd
start_all_php.bat
```

Launcher akan membuat secret lokal, menjalankan backend PHP pada `127.0.0.1:5000`, menjalankan frontend statis pada `127.0.0.1:5173`, lalu membuka browser. Tidak diperlukan `npm install`.

### Jalankan secara terpisah

**Terminal 1, dari root proyek (backend):**

```bash
php backend_php/scripts/init_local_secrets.php
php -d upload_max_filesize=8M -d post_max_size=10M -d max_execution_time=120 -d max_input_time=120 -S 127.0.0.1:5000 -t backend_php backend_php/index.php
```

**Terminal 2, dari folder `frontend` (frontend):**

```bash
php -S 127.0.0.1:5173 router.php
```

Buka `http://127.0.0.1:5173`.

Frontend mengirim request API ke `http://127.0.0.1:5000/api`. Alamat ini dapat diganti sebelum `app.js` berjalan dengan menetapkan `window.SECURE_VAULT_API_URL` pada halaman `frontend/index.html`. Untuk origin selain `localhost:5173` atau `127.0.0.1:5173`, atur `SECURE_VAULT_CORS_ORIGINS` pada lingkungan backend agar origin frontend diizinkan.

## Penyiapan akun dan MFA

Tidak ada akun demo, password bawaan, atau kode MFA universal.

1. Administrator membuka **Konsol Admin → Buat Akun Pengguna** dan mengisi username serta email. Sistem mengirim tautan aktivasi sekali pakai ke email tersebut. Admin tidak menerima atau mengirim kata sandi sementara.
2. Pengguna membuka tautan aktivasi dan membuat kata sandi sendiri (minimal 12 karakter). Tautan berlaku 24 jam; admin dapat mengirim ulang tautan dari daftar pengguna jika kedaluwarsa. Tautan lama tidak berlaku setelah dikirim ulang.
3. Akun aktif setelah kata sandi dibuat. Pengguna masuk dengan kata sandi baru, lalu menyiapkan TOTP melalui QR di browser.
4. Untuk memberikan hak administrator pada akun yang sudah aktif, hentikan backend dan jalankan perintah CLI dari root proyek, lalu konfirmasi nama akun:

   ```cmd
   php backend_php/scripts/promote_admin.php USERNAME
   ```

5. Jalankan kembali backend. Pendaftaran publik ditolak oleh API; akun baru hanya dapat dibuat dari sesi administrator.

### Konfigurasi email SMTP

Untuk akun Gmail, aktifkan [Verifikasi 2 Langkah](https://support.google.com/accounts/answer/185839), buat **App Password** di pengaturan Akun Google, lalu jalankan `configure_gmail_smtp.bat` dari root proyek. Masukkan alamat Gmail pengirim dan App Password 16 karakter saat diminta. Skrip menyimpan konfigurasi di `var/secure-vault/smtp.json` (di luar web root dan diabaikan Git), memakai port 465 dengan SSL, kemudian mengirim email tes ke Gmail pengirim. Password Gmail biasa tidak digunakan. Setelah tes berhasil, buka aplikasi dan buat akun pengguna; tautan aktivasi akan dikirim ke email pengguna.

Tautan aktivasi memakai `SECURE_VAULT_APP_URL` sebagai alamat aplikasi yang dapat dibuka user. Untuk pengembangan lokal, nilai bawaan `http://127.0.0.1:5173` hanya dapat dibuka pada komputer yang menjalankan frontend. Untuk deployment, atur `SECURE_VAULT_APP_URL` ke URL HTTPS publik aplikasi sebelum membuat akun.

Jika tes gagal, pesan skrip menjelaskan apakah masalahnya konfigurasi, koneksi, atau penolakan login Gmail. Jalankan `Test-NetConnection smtp.gmail.com -Port 465` untuk memeriksa jalur jaringan dan periksa folder Spam untuk email tes. Konfigurasi file dibaca langsung pada setiap pengiriman, jadi backend tidak perlu dimulai ulang setelah menjalankan skrip.

Sebelum administrator membuat akun, atur environment backend: `SECURE_VAULT_SMTP_HOST`, `SECURE_VAULT_SMTP_PORT`, `SECURE_VAULT_SMTP_ENCRYPTION` (`tls` untuk STARTTLS atau `ssl` untuk SMTPS), `SECURE_VAULT_SMTP_FROM`, `SECURE_VAULT_SMTP_USER`, dan `SECURE_VAULT_SMTP_PASSWORD`. Nilai host, pengguna, dan kata sandi diperoleh dari penyedia email Anda. Jangan menaruh kata sandi SMTP di repository. Tanpa konfigurasi ini, pembuatan akun baru ditolak karena kode verifikasi tidak dapat dikirim.

Contoh di PowerShell sebelum menjalankan launcher (isi dengan nilai milik penyedia email):

```powershell
$env:SECURE_VAULT_SMTP_HOST = 'smtp.example.com'
$env:SECURE_VAULT_SMTP_PORT = '587'
$env:SECURE_VAULT_SMTP_ENCRYPTION = 'tls'
$env:SECURE_VAULT_SMTP_FROM = 'vault@example.com'
$env:SECURE_VAULT_SMTP_USER = 'vault@example.com'
$env:SECURE_VAULT_SMTP_PASSWORD = '<kata sandi aplikasi SMTP>'
.\start_all_php.bat
```

Mode `none` hanya diizinkan untuk server SMTP pada `localhost` saat pengujian.

Tantangan aktivasi/verifikasi MFA berlaku 20 menit. JWT sesi berlaku 8 jam sejak aktivitas API terautentikasi terakhir dan diputar ulang otomatis pada setiap request API. Saat administrator mencabut sesi, akun juga dinonaktifkan sehingga login dan aktivitas API ditolak; akun serta berkas tetap tersimpan sampai administrator mengaktifkannya kembali. Token sesi lama tetap tidak berlaku setelah akun diaktifkan kembali. Brankas yang sudah terbuka tetap mengunci kunci di RAM setelah 15 menit tanpa aktivitas; ini tidak mengeluarkan pengguna dari sesi akun.

Untuk menghapus akun secara permanen, administrator menonaktifkannya terlebih dahulu lalu memilih **Hapus Akun** dan mengetik username sebagai konfirmasi. Seluruh berkas, folder, chunk, dan profil brankas milik akun ikut dihapus; jejak audit tetap disimpan. Akun dengan peran admin selalu tampil di urutan atas dan tidak dapat diubah melalui konsol admin. Halaman dan API jejak audit hanya dapat diakses admin; aktivitas pengguna tetap dicatat.

Untuk deployment, atur `JWT_SECRET` (acak, minimal 32 byte), `MFA_ENCRYPTION_KEY` (base64 dari 32 byte acak), dan `SECURE_VAULT_CORS_ORIGINS` sebagai environment variable yang dikelola deployment. Aktifkan `SECURE_VAULT_ENABLE_HSTS=1` **hanya** di belakang TLS yang tervalidasi. Jangan gunakan secret lokal pengembangan sebagai secret produksi. Data runtime berada di `var/secure-vault/` secara default.

## Pengujian regresi keamanan

Jalankan dari root proyek:

```bash
node --experimental-default-type=module frontend/diagnostics/crypto-rewrap-test.mjs
php backend_php/tests/mfa_challenge_lock_test.php
python backend_php/tests/security_stage1.py
python backend_php/tests/security_stage2.py
find backend_php -name '*.php' -print0 | xargs -0 -n1 php -l
```

Suite API melakukan preflight `pdo_sqlite`; jika ekstensi belum aktif, hasilnya dilaporkan sebagai `BLOCKED` agar tidak disalahartikan sebagai kegagalan assertion keamanan. Lihat `REMEDIATION_LOG.md` untuk perubahan dan pekerjaan tersisa.

## Database, pratinjau, dan pemeriksaan unggahan

- Database aktif: `var/secure-vault/data/secure-vault.sqlite` (di luar web root, direktori privat). Mulai build V9, tabel aktif dipisahkan per entitas (`users`, `vault_profiles`, `encrypted_files`, `file_chunks`, `audit_logs`, dan `auth_rate_limits`) dengan foreign key, indeks, dan constraint unik. Pastikan `pdo_sqlite` aktif (`php -m`).
- Migrasi JSON berjalan otomatis saat SQLite kosong dan `database.json` lama ditemukan. Untuk menjalankan secara eksplisit: `php backend_php/scripts/migrate_json_to_sqlite.php`. Simpan backup terpisah sebelum upgrade; JSON sumber tidak dihapus otomatis.
- Pratinjau file dilakukan setelah setiap chunk berhasil didekripsi dan tag AES-GCM diverifikasi di browser; AAD mengikat setiap chunk ke ID file dan indeksnya. Seluruh plaintext sementara tetap perlu disusun menjadi Blob di memori browser. Format yang didukung: PDF, PNG/JPEG/GIF/WebP/BMP/AVIF, TXT, CSV, JSON, dan Markdown. Format lain tetap dapat diunduh.
- Pratinjau PDF dan gambar memakai URL `blob:` lokal di browser; teks/CSV/JSON/Markdown ditampilkan sebagai teks ter-escape, bukan HTML. Jangan mengaktifkan preview HTML/SVG secara langsung.
- Setelah endpoint `/files/{id}/complete` sukses, daftar berkas diperbarui otomatis.
- Upload memeriksa ekstensi berisiko, nama file, dan signature beberapa format umum sebelum enkripsi. Pemeriksaan ini heuristik, **bukan antivirus**.
- Karena arsitektur Zero-Knowledge, server hanya menerima ciphertext dan tidak dapat memindai malware pada plaintext.

## Struktur frontend hasil konversi

```text
frontend/
├── index.html              # Dokumen utama
├── styles.css              # Seluruh styling
├── logo.png                # Logo aplikasi
├── argon2-bundled.min.js    # Runtime Argon2id WASM
└── js/
    ├── api.js              # Klien REST API PHP dan pembaruan token sesi
    ├── app.js              # UI, state, navigasi history, event, dan seluruh alur fitur
    ├── qr.js               # Generator QR TOTP lokal/offline
    └── crypto.js           # Envelope encryption dan utilitas kriptografi
```

## Acuan keamanan

- **ISO/IEC 15408**: keluarga standar Common Criteria untuk evaluasi keamanan TI.
- **ISO/IEC 18045**: metodologi evaluasi keamanan TI.

Referensi standar bukan bukti bahwa aplikasi telah dievaluasi atau disertifikasi.

## Perbaikan passphrase dan pesan error (versi terbaru)

Perubahan passphrase menggunakan salinan Master Key sementara yang extractable hanya selama proses re-wrap, lalu mengimpor kembali Master Key sesi sebagai non-extractable. Regresi ini diuji dengan `frontend/diagnostics/crypto-rewrap-test.mjs`. Pengaturan upload PHP diseragamkan: `upload_max_filesize=8M`, `post_max_size=10M`, dan batas waktu 120 detik.


Alur derivasi passphrase diselaraskan kembali dengan implementasi React awal: `window.argon2.hash()` dipanggil langsung dengan Argon2id 64 MiB, 3 iterasi, paralelisme 1, dan keluaran 32 byte. Proses tidak dipindahkan ke Worker dan tidak menggunakan KDF alternatif. Selama derivasi, JavaScript hanya memperbarui indikator progres dan tombol modal secara langsung, tidak me-render ulang seluruh aplikasi.

API client sekarang mempertahankan pesan error dari backend. Login dengan username tidak ditemukan maupun password salah akan menampilkan pesan kredensial umum (keduanya sengaja disamakan untuk mencegah enumerasi akun); password registrasi yang kurang dari 12 karakter, kode MFA salah/kedaluwarsa, akun nonaktif, serta sesi yang dicabut/kedaluwarsa menampilkan pesan sesuai penyebab.

Untuk menguji kompatibilitas browser secara terpisah, jalankan aplikasi lalu buka `http://127.0.0.1:5173/diagnostics/argon2-self-test.html`. Tes ini memakai passphrase diagnostik sementara, tidak menyentuh brankas, dan tidak menghubungi backend.


## Build V6 — privasi metadata dan transaksi file

Build ini menggunakan identitas `NATIVE-V6-2026.11.02` serta query cache `v=6`. Fingerprint SHA-256 plaintext tidak lagi dikirim atau disimpan oleh API. Saat database dibuka, field `plaintext_sha256` legacy dihapus dari record aktif; autentikasi konten mengandalkan tag AES-GCM per chunk dan AAD yang mengikat ID file serta indeks chunk. Catatan: file backup JSON lama yang disimpan terpisah tidak diubah otomatis dan perlu ditangani sesuai kebijakan retensi/backup.

Operasi inisialisasi file, penyimpanan metadata chunk, penyelesaian upload, perubahan metadata, dan penghapusan final kini dapat menggabungkan mutasi bisnis dengan audit entry dalam satu commit SQLite. Penghapusan menggunakan tombstone `deletion_pending`; bila cleanup filesystem terhenti, objek menjadi tidak dapat diakses dan permintaan DELETE ulang melanjutkan pembersihan. Ini adalah retry/recovery yang dapat dilanjutkan, bukan transaksi atomik lintas SQLite dan filesystem.

Jika halaman tidak menampilkan penanda `NATIVE-V6-2026.11.02`, browser/server masih menyajikan folder atau cache versi sebelumnya pada build V6. Halaman diagnosis: `/diagnostics/argon2-self-test.html`.

### Checkpoint audit eksternal

Rantai hash yang hanya berada di database lokal masih dapat dibangun ulang oleh administrator host yang memiliki akses penuh. Untuk menyimpan bukti pembanding di luar host:

1. Buat secret khusus 32 byte acak dan simpan sebagai Base64 pada environment variable CLI `AUDIT_ANCHOR_HMAC_KEY`. Contoh untuk shell Bash: `export AUDIT_ANCHOR_HMAC_KEY="$(php -r 'echo base64_encode(random_bytes(32));')"`. Simpan secret ini di pengelola secret terpisah dan jangan berikan kepada proses web/PHP-FPM.
2. Setelah menyiapkan secret, jalankan dari root proyek:

   ```bash
   php backend_php/scripts/export_audit_anchor.php /path/ke/penyimpanan-eksternal/audit-anchor.json
   ```

3. Salin file checkpoint tersebut ke media offline, WORM, atau penyimpanan terpisah dengan kontrol akses independen.
4. Untuk verifikasi terhadap database lokal:

   ```bash
   php backend_php/scripts/verify_audit_anchor.php /path/ke/audit-anchor.json
   ```

Checkpoint memverifikasi HMAC dan kecocokan prefix rantai audit hingga sequence yang ditambatkan. Perlindungannya bergantung pada penyimpanan checkpoint dan secret HMAC di luar kendali administrator host aplikasi.


## Build V7 — streaming download, crypto worker, dan CSP hardening

Build V9 memakai identitas `NATIVE-V9-2026.11.04` serta cache query `v=9`. Operasi AES-GCM untuk enkripsi/dekripsi per chunk dipindahkan ke ES Module Web Worker; Argon2id tetap dijalankan pada jalur browser yang sebelumnya terbukti stabil dan belum diklaim berjalan di Worker. Buffer plaintext/ciphertext sementara dibersihkan setelah pekerjaan chunk selesai.

Unduhan memakai `showSaveFilePicker()` dan `FileSystemWritableFileStream` ketika tersedia, sehingga plaintext ditulis per chunk dan tidak dibangun menjadi Blob penuh di RAM JavaScript. Browser tanpa dukungan API tersebut memakai fallback Blob; file di atas 100 MiB memerlukan konfirmasi karena pemakaian memori dapat meningkat. Pratinjau tetap dibatasi 50 MiB. Seluruh chunk diverifikasi dengan AES-GCM + AAD, panjang per chunk, dan ukuran total file.

Frontend menghapus atribut style inline, menghapus ketergantungan font Google, dan memperketat CSP menjadi `style-src 'self'` serta `worker-src 'self'`. Pengecualian `wasm-unsafe-eval` masih digunakan khusus untuk runtime Argon2id WASM. Tes statis tersedia melalui `python backend_php/tests/frontend_security_static.py`; tes browser worker tersedia di `/diagnostics/crypto-worker-self-test.html`.

**Batasan yang belum selesai:** pengujian Chromium headless pada lingkungan build tidak dapat diselesaikan karena proses browser tidak berhenti/timeout. Pengujian worker dan File System Access API tetap harus dijalankan pada browser desktop aktual. API Stage 1/2 masih memerlukan PHP `pdo_sqlite`, dan Argon2id belum dipindahkan ke Worker.

## Iteration 4 / Stage 8: database write efficiency and operational recovery

This iteration retains the current SQLite JSON-record compatibility model but changes persistence from full-table replacement to record-level diff/upsert/delete. The existing process lock is intentionally retained because the application still loads a request-level in-memory snapshot; removing that lock before moving to transactional repositories would introduce lost-update risks.

New operator tools (CLI only):

- `php backend_php/scripts/production_readiness.php` — non-destructive preflight; reports `BLOCKED` when required PHP extensions are absent.
- `php backend_php/scripts/backup_sqlite.php /path/to/existing/backup.sqlite` — consistent SQLite backup using `VACUUM INTO`; destination directory must already exist and the destination must not exist.
- `php backend_php/scripts/verify_sqlite_backup.php /path/to/backup.sqlite` — read-only integrity and foreign-key validation.
- `php backend_php/scripts/reconcile_storage.php` — dry-run report of unreferenced storage directories, abandoned temporary files, and missing referenced chunks.
- `php backend_php/scripts/reconcile_storage.php --apply` — moves only unreferenced directories and abandoned `.tmp` files into a private quarantine; it does not permanently delete them. Review the report and make a backup first.

The reconciliation tool does not automatically delete incomplete uploads that still have database records. Missing referenced chunks are reported and require operator review. This is deliberately conservative.

### Iteration 4 limitations

- The database is still a generic `vault_records` JSON payload table, not a normalized relational schema.
- The global process lock remains; multi-worker concurrency and high throughput are not production-ready.
- API suites requiring `pdo_sqlite` must still be run in a PHP environment with that extension enabled.
- Backup/restore drills, browser E2E, TLS deployment review, and independent penetration testing remain release gates.


## Iteration 5 / Stage 9 — relational SQLite migration and reliability

Build V9 uses SQLite schema version `2` (`PRAGMA user_version=2`). The former generic `vault_records` table is migrated transactionally into six dedicated entity tables: `users`, `vault_profiles`, `encrypted_files`, `file_chunks`, `audit_logs`, and `auth_rate_limits`. The schema adds foreign keys, unique account identifiers, unique file/chunk identity, unique audit sequence numbers, indexes for common owner/status/time lookups, and non-negative quota/size checks.

For compatibility with the existing PHP service layer, each entity table temporarily retains a JSON `payload` column alongside typed relational columns. The service API still loads a request snapshot into memory; this iteration does **not** yet remove the process-wide lock or establish multi-worker scalability. The next refactor should move reads/writes into repository methods and retire the compatibility payload only after route-by-route tests pass.

On first open of a V8 database with legacy `vault_records`, Secure Vault creates a consistent pre-migration SQLite snapshot in the private data directory (`secure-vault.pre-relational-v2.*.sqlite`), verifies its integrity, then migrates the rows in one transaction. The duplicate generic table is dropped only after all rows have migrated successfully. A failed migration rolls back and leaves the pre-migration snapshot for operator recovery. Do not delete these snapshots until the upgraded database and a separate storage backup have been verified.

Migration and regression commands (from the project root):

```bash
php backend_php/scripts/migrate_relational.php
python backend_php/tests/iteration5_relational_static_test.py
python backend_php/tests/iteration5_sqlite_integration_test.py
php backend_php/tests/relational_migration_integration.php
```

The Python SQLite integration test exercises the shipped SQL schema against the SQLite engine, including FK enforcement, unique constraints, cascades, atomic rollback, and `integrity_check`. The PHP migration integration test exercises the actual PDO adapter and is reported as `BLOCKED` (exit code 77) when `pdo_sqlite` is unavailable. Neither static tests nor the Python schema test replace the PHP API integration suite or browser tests.

The production readiness preflight now checks relational schema version, required tables, and foreign-key violations in addition to existing environment checks:

```bash
php backend_php/scripts/production_readiness.php
```

### Iteration 5 limitations

- Relational columns and constraints are in place, but complete normalization is not finished because JSON compatibility payloads remain.
- The PHP service layer still loads collections into an in-memory snapshot and holds a global process lock for the request lifetime. Do not claim high-concurrency or horizontal multi-worker readiness.
- PHP PDO migration, backup/restore drills, and Stage 1/2 API suites still require a PHP runtime with `pdo_sqlite` enabled.
- Storage objects are not moved during schema migration. Back up the storage directory separately before deployment.
- Full browser E2E, concurrent multi-user load testing, disaster-recovery exercise, TLS deployment review, and independent penetration testing remain release gates.
