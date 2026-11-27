# Standar Operasional Prosedur (SOP) Penanganan Insiden Keamanan Secure Vault

---

## 1. Identitas dan Tujuan Dokumen

| Atribut Dokumen | Keterangan |
| :--- | :--- |
| **Nama Dokumen** | Standar Operasional Prosedur (SOP) Penanganan Insiden Keamanan Secure Vault |
| **Kode / Lokasi** | `docs/sop-penanganan-insiden-keamanan.md` |
| **Acuan Sistem** | Secure Vault (PHP 8 REST API + SQLite `pdo_sqlite` + Frontend ES Modules *Zero-Knowledge*) |
| **Referensi Desain** | ISO/IEC 15408 dan ISO/IEC 18045 (referensi desain keamanan; bukan klaim sertifikasi) |

**Tujuan dokumen ini** adalah menyediakan prosedur operasional yang terstruktur, aman, dan berbasis bukti kode aktual bagi administrator dan operator dalam mendeteksi, membatasi dampak (*containment*), mengumpulkan serta menjaga bukti digital, memulihkan layanan, dan mengevaluasi insiden keamanan maupun gangguan layanan pada **Secure Vault**.

---

## 2. Ruang Lingkup

SOP ini berlaku untuk:
- Seluruh komponen aplikasi Secure Vault: backend REST API (`backend_php/`), antarmuka web (`frontend/`), direktori data persisten di luar web root (`PRIVATE_DIR`: `data/secure-vault.sqlite`, `storage/`, `secrets.php`, `smtp.json`, `mfa_tokens.json`), serta skrip CLI operasional (`backend_php/scripts/`).
- Tujuh skenario insiden utama: pengambilalihan akun pengguna, kebocoran secret/kunci, akses tidak sah terhadap berkas, kerusakan/kehilangan *ciphertext*, kerusakan/kehilangan database, indikasi manipulasi *audit hash-chain*, dan gangguan layanan aplikasi.

> [!NOTE]
> Secure Vault **tidak memiliki** sistem SIEM, SOC terintegrasi, deteksi insiden otomatis, rotasi kunci otomatis, maupun pengiriman *backup* audit eksternal otomatis. Deteksi awal dan eksekusi langkah penanganan dilakukan **secara manual** oleh administrator/operator berdasarkan pemantauan **Jejak Audit**, **Konsol Admin**, log server, dan alat CLI yang tersedia.

---

## 3. Definisi dan Istilah

- **Insiden Keamanan:** Peristiwa atau rangkaian peristiwa yang mengancam kerahasiaan, integritas, atau ketersediaan data dan layanan Secure Vault.
- **Containment (Pembatasan Dampak):** Tindakan segera untuk menghentikan atau membatasi penyebaran insiden tanpa merusak bukti digital.
- **Preservasi Bukti:** Penyimpanan salinan identik (*read-only* / terisolasi) dari database, berkas `-wal`/`-shm`, `storage/`, log, dan checkpoint *Audit Anchor* sebelum tindakan perbaikan dilakukan.
- **Zero-Knowledge:** Arsitektur di mana *passphrase*, KEK, Master Key, DEK, dan *plaintext* berkas hanya diproses di browser pengguna; server hanya menyimpan *ciphertext* dan *wrapped keys*.
- **Hash-Chain & Audit Anchor:** Rantai hash berurutan pada `audit_logs` (V3 menggunakan SHA3-512; V1/V2 menggunakan SHA-256) serta checkpoint JSON bertanda tangan `HMAC-SHA256` yang diekspor manual lewat `export_audit_anchor.php`.

---

## 4. Peran dan Tanggung Jawab

| Peran | Tanggung Jawab Utama dalam Penanganan Insiden |
| :--- | :--- |
| **Administrator Secure Vault** | Memantau **Jejak Audit** dan **Konsol Admin**, menonaktifkan akun/mencabut sesi (`Cabut Sesi & Nonaktifkan`), memverifikasi rantai audit (`/api/audit/verify`), dan berkoordinasi dengan operator server. |
| **Operator Server / Infrastruktur** | Mengakses host/CLI, menghentikan atau menyalakan layanan PHP/web server, membuat salinan preservasi bukti, menjalankan skrip CLI (`production_readiness.php`, `verify_sqlite_backup.php`, `reconcile_storage.php`, `verify_audit_anchor.php`), serta memulihkan backup/secret. |
| **Penanggung Jawab Keamanan / Pimpinan** | Menetapkan tingkat keparahan insiden, menyetujui *maintenance window* atau penghentian layanan darurat, menentukan eskalasi eksternal/hukum, serta memimpin evaluasi pascainsiden. |
| **Pengguna Terdampak** | Melaporkan aktivitas mencurigakan, mengganti kata sandi/passphrase brankas (**Re-Wrap**), dan memverifikasi keutuhan berkas setelah pemulihan. |

---

## 5. Klasifikasi dan Tingkat Keparahan Insiden

| Tingkat | Kriteria pada Secure Vault | Contoh Skenario | Target Waktu Respons (*SLA*) |
| :--- | :--- | :--- | :--- |
| **Kritis (P1)** | Kebocoran secret sistem (`JWT_SECRET`, `MFA_ENCRYPTION_KEY`), manipulasi `audit_logs`, atau pengambilalihan akun `admin` / seluruh layanan mati total. | Skenario 2, 5, 6, 7 (total) | `[Diisi oleh Organisasi]` |
| **Tinggi (P2)** | Pengambilalihan akun `user`, akses tidak sah terhadap berkas, atau kerusakan/kehilangan *ciphertext* / database parsial. | Skenario 1, 3, 4, 5 (parsial) | `[Diisi oleh Organisasi]` |
| **Sedang (P3)** | Kegagalan komponen non-kritis (mis. gangguan SMTP sementara atau *orphan `.tmp`* di `storage/`) tanpa indikasi kompromi data. | Skenario 7 (parsial) | `[Diisi oleh Organisasi]` |
| **Rendah (P4)** | Percobaan login/MFA gagal yang berhasil ditahan oleh *rate limiter* (`AUTH_LOGIN_FAILED` / `AUTH_MFA_FAILED`) tanpa akses berhasil. | Pemantauan rutin | `[Diisi oleh Organisasi]` |

---

## 6. Alur Umum Penanganan Insiden

Setiap insiden ditangani melalui 6 fase berurutan:

1. **Identifikasi & Triase:** Verifikasi laporan atau anomali melalui **Jejak Audit** (`GET /api/audit`), **Konsol Admin**, *error log* PHP/web server, dan pemeriksaan CLI (`production_readiness.php`). Tentukan tingkat keparahan.
2. **Preservasi Bukti Awal:** Sebelum mengubah atau menghapus apa pun, amankan salinan bukti (*read-only*) sesuai Bagian 8. **Jangan pernah menghapus database, *ciphertext*, secret, atau audit log sebagai langkah awal.**
3. **Pembatasan Dampak (*Containment*):** Cabut sesi dan nonaktifkan akun terdampak, hentikan layanan jika diperlukan, atau isolasi host/jaringan.
4. **Eradikasi & Pemulihan (*Recovery*):** Perbaiki akar masalah, rotasi kredensial/secret sesuai ketergantungannya, pulihkan database/storage dari backup terverifikasi (merujuk [SOP Backup dan Restore](prosedur-backup-restore.md)), lalu jalankan pemeriksaan pascapemulihan.
5. **Verifikasi Keamanan:** Pastikan `production_readiness.php` berstatus `PASS`, `reconcile_storage.php` (*dry-run*) bebas `missing_chunk_files`, rantai audit valid, dan layanan normal.
6. **Evaluasi Pascainsiden:** Lengkapi formulir insiden (Bagian 13), lakukan rapat evaluasi, dan catat tindakan pencegahan.

---

## 7. Prosedur Penanganan Berdasarkan Jenis Insiden

### 7.1 Skenario 1: Dugaan Pengambilalihan Akun Pengguna

- **Indikasi & Verifikasi:**
  - Tinjau **Jejak Audit** (filter aktivitas `AUTH_CREDENTIALS_VERIFIED`, `AUTH_MFA_SUCCESS`, `AUTH_LOGIN_FAILED`, `AUTH_MFA_FAILED`, `FILE_DOWNLOAD`, `FILE_DELETE`, `VAULT_REWRAP_MK`) beserta kolom **Alamat IP** dan waktu kejadian.
  - Periksa status akun di **Konsol Admin**.
- **Pembatasan Akses & Penanganan Sesi/Token:**
  - **Jika akun berperan `user`:** Masuk ke **Konsol Admin → Daftar akun pengguna**, klik **Cabut Sesi & Nonaktifkan** pada akun tersebut (`POST /api/admin/users/{id}/revoke`). Tindakan ini menyetel `is_active = false` dan menaikkan `session_version`, sehingga seluruh JWT aktif langsung ditolak oleh `AuthMiddleware::authenticate()`.
  - **Jika akun berperan `admin`:** Konsol Admin melindungi akun `admin` (*Akun terlindungi*), sehingga pencabutan melalui UI tidak tersedia. Operator harus menghentikan layanan atau menangani akun di tingkat server/database secara hati-hati (*Prosedur manual — belum ada endpoint API untuk menonaktifkan admin lain*).
- **Pemeriksaan MFA & Perubahan Kredensial:**
  - Catatan implementasi: Secure Vault **belum menyediakan** fitur *reset password* mandiri maupun tombol *reset MFA* di UI/Konsol Admin bagi akun yang sudah aktif.
  - Jika kata sandi akun `user` diduga bocor sementara *passphrase* brankas tidak bocor, dan akun masih perlu diganti kredensialnya, organisasi harus melakukan prosedur administratif manual (atau menonaktifkan akun lama dan membuat akun pengganti setelah data dipindahkan oleh pemiliknya).
  - Jika *passphrase* brankas ikut dicurigai diketahui pihak lain, pemilik akun harus membuka brankas dan segera mengganti *passphrase* melalui tombol **Re-Wrap** (`AuthRoutes::rewrapMasterKey()`).
- **Pemulihan Akun & Evaluasi Audit:**
  - Aktifkan kembali akun hanya setelah pemilik terverifikasi melalui **Aktifkan Akun** (`POST /api/admin/users/{id}/reactivate`), lalu tinjau apakah ada berkas yang diunduh (`FILE_DOWNLOAD`) atau dihapus (`FILE_DELETE`) selama periode kompromi.

### 7.2 Skenario 2: Kebocoran Secret atau Kunci

Ketergantungan masing-masing secret di kode (`backend_php/config.php`, `Totp.php`, `Activation.php`, `SmtpMailer.php`, `export_audit_anchor.php`):

| Secret / Kunci | Dampak Jika Bocor | Prosedur Rotasi & Ketergantungan |
| :--- | :--- | :--- |
| **`JWT_SECRET`** | Penyerang dapat memalsukan JWT sesi (`Jwt::sign()`), token aktivasi (`Activation::tokenHash()`), dan kode verifikasi email onboarding (`hash_hmac`). **Tidak memengaruhi** *ciphertext* berkas maupun secret MFA. | **Manual:** Buat nilai acak baru min. 32 byte (`php -r "echo bin2hex(random_bytes(32));"`), perbarui `PRIVATE_DIR/secrets.php` atau env `JWT_SECRET`, lalu restart backend. Seluruh pengguna otomatis keluar dan harus login ulang; tautan aktivasi yang belum dipakai harus dikirim ulang oleh admin. |
| **`MFA_ENCRYPTION_KEY`** | Penyerang yang juga memiliki akses ke tabel `users` dapat mendekripsi `mfa_secret_encrypted` (`Totp::decryptSecret()` AES-256-GCM). **Tidak memengaruhi** *ciphertext* berkas di `storage/`. | **Perhatian Kritis:** **Belum tersedia skrip rotasi otomatis.** Mengganti `MFA_ENCRYPTION_KEY` secara langsung tanpa migrasi akan membuat **seluruh pengguna gagal login MFA** karena secret TOTP lama tidak dapat didekripsi. Rotasi memerlukan skrip pemeliharaan khusus untuk mendekripsi seluruh `mfa_secret_encrypted` memakai kunci lama dan mengenkripsinya ulang memakai kunci baru (base64 dari 32 byte acak) dalam kondisi layanan berhenti, lalu memperbarui `secrets.php`/env. |
| **Kredensial SMTP (`smtp.json` / `SECURE_VAULT_SMTP_PASSWORD`)** | Penyerang dapat menyalahgunakan akun email pengirim. **Tidak memengaruhi** data brankas. | **Manual:** Segera cabut *App Password* / kredensial pada penyedia email, buat kredensial baru, jalankan ulang `configure_gmail_smtp.bat` atau perbarui env `SECURE_VAULT_SMTP_*`, lalu uji dengan `php backend_php/scripts/test_smtp.php`. |
| **`AUDIT_ANCHOR_HMAC_KEY`** | Penyerang dapat memalsukan tanda tangan `hmac_sha256` pada berkas checkpoint *Audit Anchor* baru. **Tidak memengaruhi** rantai SHA3-512 di SQLite. | **Manual:** Buat base64 32 byte acak baru untuk env CLI `AUDIT_ANCHOR_HMAC_KEY`, verifikasi rantai lokal (`GET /api/audit/verify`), lalu ekspor checkpoint baru (`export_audit_anchor.php`). |
| **Kunci Enkripsi Berkas (*Passphrase* / KEK / Master Key / DEK)** | Berada di sisi klien (*Zero-Knowledge*). Server tidak menyimpannya. | Pemilik akun mengganti *passphrase* via **Re-Wrap** (`AuthRoutes::rewrapMasterKey()`). Jika berkas pernah didekripsi oleh pihak tak berwenang, anggap *plaintext* berkas tersebut telah terekspos. |

### 7.3 Skenario 3: Dugaan Akses Tidak Sah Terhadap Berkas

- **Identifikasi:** Catat UUID berkas (`file_id`), akun pemilik (`owner_id`), rentang waktu, dan IP dari **Jejak Audit** (`FILE_DOWNLOAD`, `FILE_METADATA_UPDATE`, `FILE_DELETE_PENDING`, `FILE_DELETE`).
  - *Catatan implementasi:* `FILE_DOWNLOAD` hanya dicatat saat `$chunkIndex === 0` (`FileRoutes::streamChunkData()`), sedangkan `GET /api/files` (melihat daftar) tidak dicatat di `audit_logs`.
- **Preservasi & Pembatasan:** Salin `secure-vault.sqlite` (read-only) dan log akses web server/PHP, lalu cabut sesi akun terkait melalui **Konsol Admin → Cabut Sesi & Nonaktifkan**.
- **Penilaian Kebocoran (*Ciphertext* vs *Plaintext*):**
  - Jika akses terjadi hanya di level server/storage tanpa *passphrase* pengguna (atau hanya berupa unduhan *ciphertext* tanpa *Master Key*), data yang terekspos adalah **ciphertext** AES-256-GCM.
  - Jika akses terjadi melalui sesi pengguna dengan brankas terbuka (atau *passphrase* diketahui penyerang), anggap **plaintext** berkas telah bocor.
- **Pemulihan & Pencegahan:** Ganti *passphrase* via **Re-Wrap** (bila kunci klien dicurigai bocor), aktifkan kembali akun hanya setelah aman, dan tinjau izin akses OS pada `PRIVATE_DIR`.

### 7.4 Skenario 4: Kerusakan atau Kehilangan Ciphertext

- **Identifikasi Berkas Terdampak:**
  Jalankan pemeriksaan *read-only* dalam mode *dry-run*:
  ```bash
  php backend_php/scripts/reconcile_storage.php
  ```
  Periksa daftar `missing_chunk_files`, `orphan_directories`, dan `orphan_temp_files` pada keluaran JSON. Periksa juga `FILE_UPLOAD_INTEGRITY_FAILURE` atau `FILE_DOWNLOAD_INTEGRITY_FAILURE` di **Jejak Audit**.
- **Preservasi Bukti:** **Jangan langsung menjalankan `--apply` atau menghapus isi `STORAGE_DIR`.** Buat salinan utuh `STORAGE_DIR` dan `DATA_DIR` saat ini sebagai bukti insiden.
- **Pemeriksaan Backup & Pemulihan:**
  Periksa ketersediaan cadangan `STORAGE_DIR` dan SQLite (`verify_sqlite_backup.php`). Ikuti **Bagian 10 (Prosedur Restore Secara Manual)** pada [SOP Backup dan Restore](prosedur-backup-restore.md) untuk memulihkan chunk yang rusak/hilang secara konsisten dengan metadata database.
- **Verifikasi:** Jalankan ulang `reconcile_storage.php` (*dry-run*) hingga `missing_chunk_files` kosong, lalu uji unduh berkas terdampak untuk memastikan tag AES-GCM dan AAD (`{file_id}-{chunk_index}`) valid.

### 7.5 Skenario 5: Kerusakan atau Kehilangan Database

- **Identifikasi & Penghentian Operasi:**
  Gejala dapat berupa HTTP 500 dari API, kegagalan `production_readiness.php`, atau error `PRAGMA integrity_check` / `database is locked`. **Segera hentikan layanan backend PHP** agar tidak ada penulisan tambahan yang memperburuk korupsi SQLite.
- **Preservasi Bukti:**
  Salin seluruh isi `DATA_DIR` **termasuk `secure-vault.sqlite`, `secure-vault.sqlite-wal`, `secure-vault.sqlite-shm`, `database.lock`, dan `mfa_tokens.json`** ke direktori isolasi bukti sebelum menyentuh file aktif.
- **Pemeriksaan Integritas:**
  Jalankan `php backend_php/scripts/verify_sqlite_backup.php <salinan-db-rusak.sqlite>` (membuka dalam mode `?mode=ro`) untuk memastikan apakah kerusakan terjadi pada file utama atau transaksi WAL.
- **Pemulihan:**
  - **Jangan mengandalkan `bootstrap_data.php`** untuk menimpa database rusak (karena bila `secure-vault.sqlite` masih terbaca valid sebagian, bootstrap menganggapnya `STATUS_ALREADY_EXISTS`).
  - Pulihkan dari cadangan SQLite terverifikasi bersama `STORAGE_DIR`, `secrets.php` (`MFA_ENCRYPTION_KEY`), dan `smtp.json` yang berpasangan sesuai **Bagian 10** [SOP Backup dan Restore](prosedur-backup-restore.md).
- **Verifikasi Pascapemulihan:** Jalankan `production_readiness.php` (`PASS`), `reconcile_storage.php` (*dry-run*), verifikasi `GET /api/audit/verify`, serta uji login, MFA, dan pembukaan brankas.

### 7.6 Skenario 6: Indikasi Manipulasi Audit Hash-Chain

- **Verifikasi Rantai & Audit Anchor:**
  1. Jalankan verifikasi rantai via API administrator: `GET /api/audit/verify` (memanggil `Audit::verifyChain()`).
  2. Jika menggunakan *Audit Anchor*, jalankan:
     ```bash
     php backend_php/scripts/verify_audit_anchor.php /path/ke/anchor.json
     ```
- **Preservasi Bukti & Larangan Mutlak:**
  - Segera salin `DATA_DIR` (`secure-vault.sqlite`, `-wal`, `-shm`) dan berkas checkpoint *Audit Anchor* ke media *read-only* terpisah.
  - **DILARANG keras menghapus, mengatur ulang, mengedit `payload`, atau menghitung ulang hash-chain** pada database bukti agar terlihat valid.
- **Dokumentasi & Eskalasi:**
  Catat nilai `brokenSequence`, pesan kegagalan (`Rantai audit terputus`, `Manipulasi data terdeteksi`, `Nomor urut audit tidak kontinu`, atau `CHECKPOINT TIDAK COCOK`), serta bandingkan dengan checkpoint *Audit Anchor* dan backup SQLite historis. Eskalasi ke penanggung jawab keamanan organisasi.
- **Konteks Keterbatasan:** Hash-chain lokal pada SQLite **tidak melindungi bukti dari pihak yang memiliki kendali penuh atas host/database** (yang dapat menghitung ulang seluruh rantai). Keaslian historis hanya dapat dibuktikan jika *Audit Anchor* dan `AUDIT_ANCHOR_HMAC_KEY` disimpan terpisah di luar kendali operator host (proses ekspor & verifikasi saat ini manual via CLI).

### 7.7 Skenario 7: Gangguan Layanan Aplikasi

- **Identifikasi Cakupan:**
  Periksa apakah gangguan terjadi pada backend PHP (port `5000`), frontend statis (port `5173`), web server/reverse proxy, atau transport SMTP (`test_smtp.php`).
- **Pemeriksaan Proses, Konfigurasi, & Log:**
  - Cek endpoint `GET http://127.0.0.1:5000/api/health`.
  - Periksa *error log* PHP/web server (karena `backend_php/index.php` mencatat detail eksepsi melalui `error_log('[Secure Vault] ...')` dan hanya mengirim pesan umum ke klien).
  - Jalankan `php backend_php/scripts/production_readiness.php` untuk memeriksa ekstensi `pdo_sqlite`, isolasi web root, izin direktori, dan integritas SQLite.
  - Jika `bootstrap_data.php` berhenti dengan `STATUS_AMBIGUOUS_CANDIDATES`, **jangan menghapus kandidat mana pun**; tetapkan `SECURE_VAULT_SOURCE_DIR` ke sumber yang benar sesuai [Panduan Instalasi](panduan-instalasi-konfigurasi-aman.md).
- **Pemulihan & Pengujian:**
  Pulihkan layanan sesuai [Panduan Instalasi](panduan-instalasi-konfigurasi-aman.md) (`start_all_php.bat` atau perintah manual backend + frontend), lalu verifikasi `/api/health`, login + MFA, brankas, dan `test_smtp.php`.

---

## 8. Pengumpulan dan Preservasi Bukti Digital

Sebelum melakukan tindakan pemulihan yang mengubah state sistem:
1. **Catat waktu insiden** (UTC dan lokal) serta akun/IP yang dicurigai.
2. **Salin artefak secara utuh (tanpa memodifikasi sumber):**
   - `DATA_DIR/secure-vault.sqlite` beserta `-wal` dan `-shm` (jika ada).
   - `STORAGE_DIR` (atau direktori `<file-uuid>` terdampak).
   - `DATA_DIR/mfa_tokens.json` dan `PRIVATE_DIR/recovery_receipt.json` (bila ada).
   - Checkpoint *Audit Anchor* (jika ada) dan *error log* PHP / web server.
   - **Jangan** menyertakan isi plaintext `secrets.php` atau `smtp.json` ke dalam laporan insiden yang dibagikan luas.
3. **Hitung hash integritas bukti** (mis. SHA-256) atas salinan bukti dan simpan di media terpisah dengan akses terbatas.

---

## 9. Pemulihan Layanan dan Verifikasi Keamanan

Setelah fase eradikasi dan pemulihan selesai:
1. Jalankan `php backend_php/scripts/production_readiness.php` dan pastikan status `PASS`.
2. Jalankan `php backend_php/scripts/reconcile_storage.php` (*dry-run*) dan pastikan `missing_chunk_files` kosong.
3. Verifikasi rantai audit melalui `GET /api/audit/verify` (dan `verify_audit_anchor.php` bila digunakan).
4. Uji fungsionalitas utama: `GET /api/health`, login + MFA, pembukaan brankas, unggah/unduh berkas uji, dan `php backend_php/scripts/test_smtp.php`.

---

## 10. Komunikasi, Eskalasi, dan Pencatatan Insiden

Setiap organisasi pengguna Secure Vault wajib melengkapi tabel kontak dan jalur eskalasi di bawah ini sebelum operasional produksi:

| Peran / Tujuan Eskalasi | Nama / Jabatan | Kontak Resmi | Batas Waktu Eskalasi |
| :--- | :--- | :--- | :--- |
| Administrator Utama Secure Vault | `[Diisi oleh Organisasi]` | `[Diisi oleh Organisasi]` | `[Diisi oleh Organisasi]` |
| Operator Server / Infrastruktur | `[Diisi oleh Organisasi]` | `[Diisi oleh Organisasi]` | `[Diisi oleh Organisasi]` |
| Penanggung Jawab Keamanan / CSIRT | `[Diisi oleh Organisasi]` | `[Diisi oleh Organisasi]` | `[Diisi oleh Organisasi]` |
| Pimpinan / Pemilik Sistem | `[Diisi oleh Organisasi]` | `[Diisi oleh Organisasi]` | `[Diisi oleh Organisasi]` |

---

## 11. Evaluasi Pascainsiden

Maksimal dalam batas waktu yang ditetapkan organisasi setelah insiden ditutup:
1. Tinjau kronologi insiden berdasarkan catatan **Jejak Audit** dan formulir insiden.
2. Identifikasi celah yang menyebabkan insiden (konfigurasi, prosedur operasional, atau keterbatasan aplikasi).
3. Tetapkan tindakan perbaikan (misalnya pembaruan jadwal backup, ekspor *Audit Anchor* rutin, atau pengetatan akses host) dan perbarui SOP bila diperlukan.

---

## 12. Checklist Penanganan Insiden

- [ ] Insiden diverifikasi dan diklasifikasikan tingkat keparahannya (P1–P4).
- [ ] Bukti digital (`DATA_DIR`, `-wal`/`-shm`, `STORAGE_DIR`, log) telah disalin sebelum perubahan apa pun.
- [ ] Tidak ada penghapusan database, *ciphertext*, secret, atau `audit_logs` pada fase awal.
- [ ] Pembatasan dampak (*containment*) telah dilakukan (cabut sesi / nonaktifkan akun / hentikan layanan).
- [ ] Akar masalah ditangani dan pemulihan dilakukan sesuai prosedur terverifikasi.
- [ ] `production_readiness.php` berstatus `PASS` dan `reconcile_storage.php` (*dry-run*) bebas `missing_chunk_files`.
- [ ] Rantai audit terverifikasi (`GET /api/audit/verify` dan/atau `verify_audit_anchor.php`).
- [ ] Layanan diuji normal (`/api/health`, login + MFA, brankas, unduh berkas, SMTP).
- [ ] Formulir pencatatan insiden diisi lengkap (tanpa secret/password/token).

---

## 13. Formulir Pencatatan Insiden

| Kolom | Isian |
| :--- | :--- |
| **ID Insiden** | `[Diisi oleh Organisasi]` |
| **Tanggal & Waktu Terdeteksi** | `[YYYY-MM-DD HH:MM TZ]` |
| **Pelapor & Penanggung Jawab** | `[Nama / Peran]` |
| **Jenis Insiden (Skenario 1–7)** | `[Pilih skenario]` |
| **Tingkat Keparahan (P1–P4)** | `[P1 / P2 / P3 / P4]` |
| **Ringkasan Gejala & Bukti Awal** | `[Ringkasan, nomor sequence audit, ID berkas — tanpa secret/data pribadi]` |
| **Tindakan Containment** | `[Tindakan & waktu eksekusi]` |
| **Tindakan Pemulihan** | `[Langkah restore / rotasi / perbaikan]` |
| **Hasil Verifikasi Pascapemulihan** | `[Hasil production_readiness, reconcile_storage, verifyChain]` |
| **Status & Waktu Penutupan** | `[Terbuka / Ditutup — YYYY-MM-DD HH:MM TZ]` |

---

## 14. Referensi Teknis yang Relevan

- **Dokumentasi Resmi Secure Vault:**
  - [Panduan Instalasi dan Konfigurasi Aman](panduan-instalasi-konfigurasi-aman.md)
  - [Panduan Operasional](panduan-operasional.md)
  - [SOP Backup dan Restore](prosedur-backup-restore.md)
  - [Panduan Audit Log](panduan-audit-log.md)
  - [Dokumentasi Perbaikan Sistem](perbaikan/README.md)
- **Kode Sumber Terkait:**
  - `backend_php/config.php`, `backend_php/index.php`
  - `backend_php/middleware/AuthMiddleware.php`, `backend_php/utils/Jwt.php`
  - `backend_php/routes/AuthRoutes.php`, `AdminRoutes.php`, `FileRoutes.php`, `AuditRoutes.php`
  - `backend_php/utils/Audit.php`, `Totp.php`, `SmtpMailer.php`, `Activation.php`, `PersistentStorage.php`
  - `backend_php/db/Database.php`
  - `backend_php/scripts/production_readiness.php`, `backup_sqlite.php`, `verify_sqlite_backup.php`, `reconcile_storage.php`, `export_audit_anchor.php`, `verify_audit_anchor.php`, `test_smtp.php`, `bootstrap_data.php`
