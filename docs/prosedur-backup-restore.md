# Standar Operasional Prosedur (SOP) Backup dan Restore Secure Vault

---

## 1. Pendahuluan dan Tujuan

Dokumen ini merupakan **Standar Operasional Prosedur (SOP)** resmi untuk pelaksanaan pencadangan (*backup*), verifikasi cadangan, dan pemulihan (*restore*) data aplikasi **Secure Vault** berdasarkan implementasi aktual pada repository.

**Tujuan SOP ini** adalah:
- Menjamin ketersediaan dan konsistensi data operasional Secure Vault (basis data relasional SQLite, potongan berkas terenkripsi, secret aplikasi, dan konfigurasi layanan).
- Mencegah kehilangan akses permanen akibat ketidaksesuaian antara database, *ciphertext chunks*, dan kunci enkripsi (`MFA_ENCRYPTION_KEY`).
- Memisahkan secara tegas fitur otomatis yang sudah tersedia (`backup_sqlite.php`, `verify_sqlite_backup.php`, `reconcile_storage.php`) dari prosedur yang masih harus dijalankan **secara manual**.

---

## 2. Ruang Lingkup

SOP ini berlaku untuk:
- Lingkungan **lokal/pengembangan** maupun **deployment produksi** Secure Vault berbasis PHP 8 + SQLite (`pdo_sqlite`).
- Seluruh data runtime persisten di luar web root (`PRIVATE_DIR`), meliputi basis data SQLite, direktori *storage* berisi *ciphertext chunks*, secret aplikasi, konfigurasi SMTP, serta *audit anchor* eksternal (bila digunakan).
- Prosedur **backup**, **verifikasi**, dan **restore manual** dari arsip cadangan.

> [!IMPORTANT]
> **Pembedaan Penting:** Mekanisme `PersistentStorage::bootstrap()` dan `PersistentStorage::recover()` (dipicu oleh `backend_php/scripts/bootstrap_data.php`) merupakan fitur **pemulihan otomatis instalasi lama** (*automatic recovery* saat direktori target belum memiliki `secure-vault.sqlite`, misalnya setelah ekstraksi rilis baru), **bukan** skrip *restore* dari file backup untuk menimpa database aktif.

---

## 3. Peran dan Tanggung Jawab Administrator

Seluruh prosedur *backup* dan *restore* hanya boleh dilakukan oleh **Administrator Sistem / Operator Server** yang memiliki akses CLI tepercaya ke host tempat Secure Vault berjalan:

- **Menjadwalkan *Maintenance Window*** sebelum pencadangan penuh atau pemulihan manual agar tidak ada operasi unggah/hapus berkas yang berjalan bersamaan.
- **Menjalankan pencadangan** database SQLite (`backup_sqlite.php`) serta pencadangan manual *storage*, secret, dan konfigurasi SMTP.
- **Memverifikasi integritas** berkas cadangan (`verify_sqlite_backup.php`) sebelum arsip disimpan atau dipindahkan.
- **Menjaga kerahasiaan** `secrets.php` / `JWT_SECRET` / `MFA_ENCRYPTION_KEY`, `smtp.json`, dan arsip *backup* dengan izin akses terbatas (`0700`/`0600`).
- **Melakukan uji pemulihan (*restore drill*)** pada lingkungan terisolasi sebelum menerapkannya ke lingkungan produksi.

---

## 4. Inventaris Komponen Wajib Backup

Berdasarkan `backend_php/config.php`, `backend_php/db/Database.php`, dan `backend_php/utils/PersistentStorage.php`, lokasi default `PRIVATE_DIR` berada di `%LOCALAPPDATA%\SecureVault` (Windows), `~/Library/Application Support/SecureVault` (macOS), `~/.local/share/secure-vault` (Linux), atau `var/secure-vault` (fallback), kecuali diarahkan lain oleh `SECURE_VAULT_PERSISTENT_DIR` / `SECURE_VAULT_HOME` / `SECURE_VAULT_DATA_DIR`.

| Komponen | Lokasi Aktual | Keterangan & Kepentingan |
| :--- | :--- | :--- |
| **Database SQLite (`DB_FILE`)** | `DATA_DIR/secure-vault.sqlite` | Menyimpan tabel `users` (termasuk `mfa_secret_encrypted`), `vault_profiles` (salt & wrapped Master Key), `encrypted_files`, `file_chunks`, `audit_logs`, dan `auth_rate_limits`. |
| **Direktori Storage (`STORAGE_DIR`)** | `PRIVATE_DIR/storage/<file-uuid>/chunk_<n>.bin` | Menyimpan seluruh potongan berkas terenkripsi (*ciphertext* AES-256-GCM). **Tidak ikut dicadangkan** oleh `backup_sqlite.php`. |
| **Secret Aplikasi** | `PRIVATE_DIR/secrets.php` (lokal) atau environment variable (`JWT_SECRET`, `MFA_ENCRYPTION_KEY`) | **Kritis:** `MFA_ENCRYPTION_KEY` digunakan oleh `Totp.php` untuk mendekripsi secret TOTP pengguna. Tanpa kunci yang sama, pengguna gagal verifikasi MFA. |
| **Konfigurasi SMTP** | `PRIVATE_DIR/smtp.json` atau environment variable `SECURE_VAULT_SMTP_*` | Diperlukan agar pengiriman tautan aktivasi akun baru tetap berfungsi setelah pemulihan. |
| **Data MFA Pendukung** | `DATA_DIR/mfa_tokens.json` | Menyimpan token tantangan MFA sementara (TTL 20 menit). Opsional untuk dicadangkan karena bersifat jangka pendek. |
| **Audit Anchor Eksternal (Opsional)** | Lokasi eksternal terpisah + `AUDIT_ANCHOR_HMAC_KEY` | Berkas checkpoint JSON hasil `export_audit_anchor.php` untuk memverifikasi keaslian prefix rantai audit pasca-insiden. |

---

## 5. Persiapan Sebelum Backup

1. **Verifikasi Kesiapan Sistem:**
   Pastikan `pdo_sqlite` aktif dan database sehat sebelum mencadangkan:
   ```bash
   php backend_php/scripts/production_readiness.php
   ```
2. **Siapkan Direktori Tujuan Backup:**
   Buat direktori penyimpanan backup di luar web root (`backend_php/` dan `frontend/`) dengan hak akses privat (`0700` pada Linux/macOS atau ACL terbatas pada Windows). `backup_sqlite.php` mewajibkan direktori induk sudah ada, dapat ditulis, dan file tujuan belum ada.
3. **Terapkan *Maintenance Window* untuk Pencadangan Lengkap:**
   - `backup_sqlite.php` menggunakan `VACUUM INTO` yang aman untuk snapshot *online* SQLite, **namun tidak ada mekanisme *atomic snapshot* lintas SQLite dan filesystem `STORAGE_DIR`**.
   - Untuk menjamin konsistensi antara metadata `file_chunks` di database dan berkas fisik di `STORAGE_DIR`, **hentikan layanan backend** (atau pastikan tidak ada pengguna yang mengunggah/menghapus berkas) selama jendela *maintenance window* saat mencadangkan kedua komponen secara bersamaan.

---

## 6. Prosedur Backup Database SQLite

> [!NOTE]
> Skrip `backend_php/scripts/backup_sqlite.php` **HANYA mencadangkan database SQLite (`DB_FILE`)**. Skrip ini tidak mencadangkan `STORAGE_DIR`, `secrets.php`, maupun `smtp.json`.

Jalankan perintah berikut dari direktori root proyek:

```bash
php backend_php/scripts/backup_sqlite.php /path/ke/backup/secure-vault-YYYYMMDD-HHMMSS.sqlite
```

**Mekanisme internal `backup_sqlite.php`:**
1. Memvalidasi eksekusi CLI (`PHP_SAPI === 'cli'`), ekstensi `pdo_sqlite`, dan keberadaan `DB_FILE`.
2. Menolak apabila file tujuan sudah ada atau menunjuk ke `DB_FILE` aktif.
3. Mengeksekusi `VACUUM INTO` untuk menghasilkan salinan konsisten, terdefragmentasi, dan menggabungkan transaksi WAL yang tertunda ke dalam satu berkas SQLite dengan izin `0600`.
4. Memvalidasi hasil backup secara otomatis (`PRAGMA integrity_check`, `PRAGMA user_version = 2`, `PRAGMA foreign_key_check`, dan 6 tabel wajib). Bila gagal, berkas backup langsung dihapus otomatis.
5. Output berhasil diawali baris `BACKUP_OK`.

---

## 7. Prosedur Backup Storage dan Komponen Non-SQLite *(Manual)*

Karena **belum tersedia skrip backup lengkap otomatis** di repository, komponen non-SQLite berikut **wajib dicadangkan secara manual** pada *maintenance window* yang sama dengan backup SQLite:

1. **Pencadangan `STORAGE_DIR` (Ciphertext Chunks):**
   Salin seluruh isi `PRIVATE_DIR/storage/` beserta struktur subdirektori `<file-uuid>/` ke lokasi cadangan terpisah (mempertahankan nama folder UUID dan file `chunk_<n>.bin`).
   - *Contoh di Windows PowerShell:*
     ```powershell
     Copy-Item -Path "$env:LOCALAPPDATA\SecureVault\storage" -Destination "D:\SecureVaultBackup\YYYYMMDD-HHMMSS\storage" -Recurse
     ```
   - *Contoh di Linux/macOS:*
     ```bash
     cp -a ~/.local/share/secure-vault/storage /path/ke/backup/YYYYMMDD-HHMMSS/storage
     ```
2. **Pencadangan Secret Aplikasi (`secrets.php` atau Env Vars):**
   - Jika menggunakan secret lokal: salin `PRIVATE_DIR/secrets.php` ke brankas cadangan terenkripsi dengan izin `0600`.
   - Jika menggunakan environment variable produksi (`JWT_SECRET`, `MFA_ENCRYPTION_KEY`): dokumentasikan dan cadangkan nilai tersebut di pengelola secret terpisah (**jangan pernah** menyimpannya dalam teks biasa di repository Git).
   - Pastikan `MFA_ENCRYPTION_KEY` selalu berpasangan dengan backup SQLite yang bersangkutan.
3. **Pencadangan Konfigurasi SMTP:**
   - Salin `PRIVATE_DIR/smtp.json` (bila ada) atau catat konfigurasi `SECURE_VAULT_SMTP_*` di pengelola secret/konfigurasi aman.
4. **Pencadangan Audit Anchor (Opsional):**
   Jika menggunakan fitur *audit anchor* eksternal, jalankan `export_audit_anchor.php` (dengan `AUDIT_ANCHOR_HMAC_KEY` di lingkungan CLI terpisah) dan simpan berkas JSON hasilnya di media terpisah.

---

## 8. Pengamanan dan Penyimpanan Hasil Backup

- **Isolasi Lokasi:** Simpan hasil backup di luar direktori proyek, di luar web root (`backend_php/` dan `frontend/`), serta idealnya pada media/host terpisah dari server utama.
- **Izin Akses File:** Pastikan direktori backup berizin `0700` dan berkas backup (`*.sqlite`, `secrets.php`, `smtp.json`) berizin `0600` (atau ACL Windows yang hanya mengizinkan akun operator/administrator yang berwenang).
- **Kerahasiaan:** Meskipun isi berkas pengguna di `storage/` sudah terenkripsi (*Zero-Knowledge*), paket backup tetap mengandung `secrets.php` (`JWT_SECRET`, `MFA_ENCRYPTION_KEY`), `smtp.json` (kredensial SMTP), dan metadata akun di SQLite. Enkripsi arsip backup (misalnya BitLocker/LUKS/arsip terenkripsi) sangat disarankan saat dipindahkan ke penyimpanan eksternal.
- **Retensi:** Simpan minimal satu salinan cadangan sebelum setiap pembaruan sistem atau migrasi skema.

---

## 9. Verifikasi Backup

Setiap paket backup yang selesai dibuat **wajib diverifikasi** sebelum dianggap valid:

1. **Verifikasi Database SQLite (Otomatis via CLI):**
   Jalankan [verify_sqlite_backup.php](file:///c:/Users/AXIOO/Documents/PKL/secure-vault-main/secure-vault-main/backend_php/scripts/verify_sqlite_backup.php) (mode *read-only*):
   ```bash
   php backend_php/scripts/verify_sqlite_backup.php /path/ke/backup/secure-vault-YYYYMMDD-HHMMSS.sqlite
   ```
   Pastikan output menampilkan `BACKUP_VALID`, `Schema version: 2`, `Integrity: ok`, `Foreign key violations: 0`, dan keenam tabel relasional tercantum.

2. **Verifikasi Kelengkapan Komponen Non-SQLite (Manual):**
   Pastikan dalam paket backup tanggal/waktu yang sama tersedia:
   - Direktori `storage/` beserta seluruh subdirektori `<file-uuid>/chunk_*.bin`.
   - Berkas `secrets.php` (atau pasangan `JWT_SECRET` dan `MFA_ENCRYPTION_KEY` di pengelola secret).
   - Berkas `smtp.json` (atau konfigurasi `SECURE_VAULT_SMTP_*`).

3. **Uji Pemulihan Berkala (*Restore Drill*):**
   Secara berkala, uji pemulihan paket backup ke direktori terisolasi sementara (dengan mengarahkan `SECURE_VAULT_PERSISTENT_DIR` ke folder uji) lalu jalankan `production_readiness.php` dan `reconcile_storage.php` (*dry-run*) tanpa menyentuh database produksi.

---

## 10. Prosedur Restore Secara Manual

> [!WARNING]
> **Belum tersedia skrip *restore* otomatis khusus** di repository. Pemulihan dari file backup ke sistem aktif **harus dilakukan secara manual** dengan urutan berikut. Jangan menjalankan langkah ini saat layanan masih aktif.

1. **Hentikan Layanan Aplikasi:**
   Hentikan seluruh proses server PHP backend (port `5000` atau PHP-FPM) dan frontend (port `5173` atau web server) agar tidak ada koneksi aktif ke SQLite maupun `STORAGE_DIR`.
2. **Verifikasi Backup Sumber Terlebih Dahulu:**
   Jalankan `php backend_php/scripts/verify_sqlite_backup.php <path-backup.sqlite>` dan pastikan hasilnya `BACKUP_VALID`.
3. **Amankan Kondisi Saat Ini (Opsional / Pra-Timpa):**
   Pindahkan atau salin `DATA_DIR` dan `STORAGE_DIR` yang rusak/saat ini ke folder arsip sementara di luar `PRIVATE_DIR` sebagai cadangan darurat.
4. **Bersihkan Berkas SQLite WAL/SHM Lama:**
   Pastikan tidak ada berkas sisa `secure-vault.sqlite-wal` atau `secure-vault.sqlite-shm` dari database sebelumnya di dalam `DATA_DIR` agar tidak merusak database hasil restore.
5. **Pulihkan Database SQLite:**
   Salin berkas backup `*.sqlite` yang sudah terverifikasi ke `DATA_DIR/secure-vault.sqlite` dengan izin `0600`.
6. **Pulihkan Direktori Storage (`STORAGE_DIR`):**
   Salin direktori `storage/` dari paket backup yang sama ke `PRIVATE_DIR/storage/` dengan izin direktori `0700` dan berkas `0600`.
7. **Pulihkan Secret Aplikasi (`MFA_ENCRYPTION_KEY` dan `JWT_SECRET`):**
   Salin `secrets.php` dari paket backup ke `PRIVATE_DIR/secrets.php` (izin `0600`), atau pastikan environment variable `JWT_SECRET` dan `MFA_ENCRYPTION_KEY` pada host tujuan bernilai **identik** dengan saat backup dibuat.
8. **Pulihkan Konfigurasi SMTP:**
   Salin `smtp.json` ke `PRIVATE_DIR/smtp.json` (izin `0600`) atau pastikan variabel `SECURE_VAULT_SMTP_*` terpasang di environment.
9. **Jalankan Kembali Layanan** setelah pemeriksaan CLI pada Bagian 11 lulus.

---

## 11. Pemeriksaan Pasca-Restore

Sebelum membuka akses pengguna setelah proses *restore* manual (dan sebelum menyalakan ulang server web, lakukan pemeriksaan CLI terlebih dahulu):

1. **Pemeriksaan Kesiapan Sistem & Database:**
   ```bash
   php backend_php/scripts/production_readiness.php
   ```
   Pastikan status akhir adalah `"status": "PASS"` (integritas SQLite `ok`, mode `wal`, `relational_schema_version = 2`, `foreign_key_violations = 0`, direktori di luar web root).
2. **Pemeriksaan Konsistensi Database vs Storage (Mode Dry-Run):**
   ```bash
   php backend_php/scripts/reconcile_storage.php
   ```
   *(Jalankan tanpa flag `--apply` untuk mode `dry-run`)*. Pastikan `missing_chunk_files` bernilai kosong (`[]`) dan *exit code* `0`. Jika ada `orphan_directories` atau `orphan_temp_files`, tinjau laporan sebelum memutuskan karantina.
3. **Pemeriksaan Rantai Audit (Jika Menggunakan Audit Anchor):**
   ```bash
   php backend_php/scripts/verify_audit_anchor.php /path/ke/audit-anchor.json
   ```
   Atau setelah layanan menyala, verifikasi rantai audit melalui endpoint administrator `GET /api/audit/verify`.
4. **Verifikasi Operasional di Aplikasi (Setelah Layanan Dinyalakan):**
   - Uji `GET /api/health` (`"status": "OK"`).
   - Uji login administrator dan verifikasi kode **MFA TOTP** (memastikan `MFA_ENCRYPTION_KEY` cocok).
   - Uji **membuka brankas** dengan *passphrase* dan uji **unduh/pratinjau** satu berkas sampel untuk memastikan dekripsi *ciphertext chunk* berjalan normal.
   - Uji `php backend_php/scripts/test_smtp.php` untuk memastikan pengiriman email berfungsi.

---

## 12. Troubleshooting

| Gejala / Masalah | Penyebab Umum | Tindakan Penanganan |
| :--- | :--- | :--- |
| `Destination already exists or points to the active database` pada `backup_sqlite.php` | Nama file tujuan sudah ada atau mengarah ke `DB_FILE` aktif. | Gunakan nama file tujuan baru dengan stempel waktu unik pada direktori backup yang sudah ada. |
| `BACKUP_FAILED: Backup failed relational schema, integrity, or foreign-key validation` | Database sumber mengalami korupsi atau inkonsistensi relasional. | Jangan pakai hasil backup tersebut; periksa kondisi disk dan jalankan `PRAGMA integrity_check` secara *read-only* pada sumber. |
| Pengguna gagal verifikasi MFA setelah *restore* (`Kode autentikator tidak valid` atau error dekripsi MFA) | `secrets.php` / `MFA_ENCRYPTION_KEY` tidak dipulihkan atau berbeda dari saat backup dibuat. | Pulihkan `secrets.php` (atau env `MFA_ENCRYPTION_KEY`) yang asli dari paket backup yang sama. |
| `reconcile_storage.php` melaporkan `missing_chunk_files` (*exit code* `10`) | Backup SQLite dan `STORAGE_DIR` diambil pada waktu berbeda, atau ada folder chunk yang terlewat saat penyalinan. | Periksa kembali salinan `STORAGE_DIR` pada paket backup dan lengkapi direktori `<file-uuid>` yang hilang. |
| `bootstrap_data.php` tidak memulihkan dari backup yang ditaruh di folder lain | `PRIVATE_DIR/data/secure-vault.sqlite` sudah ada (`STATUS_ALREADY_EXISTS`), atau terdapat lebih dari satu kandidat (`STATUS_AMBIGUOUS_CANDIDATES`). | Ingat bahwa `bootstrap_data.php` hanya untuk pemulihan instalasi lama saat target kosong. Untuk restore dari file backup, ikuti **Prosedur Restore Manual (Bagian 10)**. |

---

## 13. Risiko dan Keterbatasan

1. **Backup Parsial pada Skrip Bawaan:** `backup_sqlite.php` hanya mencadangkan database SQLite. Pencadangan lengkap (*database + storage + secrets + smtp*) masih bergantung pada prosedur manual administrator.
2. **Tidak Ada *Atomic Snapshot* Lintas SQLite dan Filesystem:** Tanpa *maintenance window* (menghentikan layanan saat pencadangan `STORAGE_DIR`), unggahan atau penghapusan yang berlangsung di tengah proses dapat menyebabkan ketidaksinkronan sementara antara tabel `file_chunks` dan isi direktori `storage/`.
3. **Ketiadaan Skrip Restore Otomatis:** Proses *restore* dilakukan secara manual sehingga kesalahan seperti lupa menghapus `-wal`/`-shm` lama atau salah menyetel izin file dapat menggagalkan pemulihan.
4. **Ketergantungan Mutlak pada `MFA_ENCRYPTION_KEY` dan *Passphrase* Pengguna:** Jika `MFA_ENCRYPTION_KEY` hilang permanen, seluruh user tidak dapat melewati MFA; sementara jika pengguna lupa *passphrase* brankas, data terenkripsi tetap tidak dapat didekripsi oleh siapa pun (*Zero-Knowledge*).

---

## 14. Checklist Backup dan Restore

### Checklist Backup Lengkap
- [ ] Jalankan `php backend_php/scripts/production_readiness.php` (`PASS`).
- [ ] Terapkan *maintenance window* (hentikan layanan bila diperlukan untuk konsistensi penuh dengan `STORAGE_DIR`).
- [ ] Jalankan `php backend_php/scripts/backup_sqlite.php <tujuan.sqlite>` (`BACKUP_OK`).
- [ ] Jalankan `php backend_php/scripts/verify_sqlite_backup.php <tujuan.sqlite>` (`BACKUP_VALID`).
- [ ] Salin direktori `STORAGE_DIR` (`storage/`) ke paket backup yang sama *(Manual)*.
- [ ] Salin/amankan `secrets.php` (atau `JWT_SECRET` & `MFA_ENCRYPTION_KEY`) dan `smtp.json` *(Manual)*.
- [ ] Simpan *audit anchor* eksternal jika digunakan (`export_audit_anchor.php`).
- [ ] Verifikasi izin akses direktori (`0700`) dan file (`0600`) pada penyimpanan backup.

### Checklist Restore Manual
- [ ] Hentikan proses backend dan frontend Secure Vault.
- [ ] Verifikasi berkas SQLite backup dengan `verify_sqlite_backup.php` (`BACKUP_VALID`).
- [ ] Amankan kondisi data aktif saat ini ke folder arsip sementara.
- [ ] Hapus sisa `secure-vault.sqlite-wal` dan `secure-vault.sqlite-shm` lama di `DATA_DIR`.
- [ ] Pulihkan `secure-vault.sqlite` ke `DATA_DIR`, `storage/` ke `STORAGE_DIR`, `secrets.php`, dan `smtp.json`.
- [ ] Jalankan `php backend_php/scripts/production_readiness.php` (`PASS`).
- [ ] Jalankan `php backend_php/scripts/reconcile_storage.php` mode *dry-run* (`missing_chunk_files` kosong, *exit code* `0`).
- [ ] Nyalakan kembali layanan dan uji `/api/health`, login + MFA, pembukaan brankas, unduh berkas sampel, dan `test_smtp.php`.

---

## 15. Referensi Kode dan Dokumentasi

- **Skrip Backup, Verifikasi, dan Rekonsiliasi:**
  - `backend_php/scripts/backup_sqlite.php`
  - `backend_php/scripts/verify_sqlite_backup.php`
  - `backend_php/scripts/reconcile_storage.php`
  - `backend_php/scripts/production_readiness.php`
  - `backend_php/scripts/bootstrap_data.php`
  - `backend_php/scripts/export_audit_anchor.php` & `backend_php/scripts/verify_audit_anchor.php`
- **Modul Inti Backend:**
  - `backend_php/config.php`
  - `backend_php/db/Database.php`
  - `backend_php/utils/PersistentStorage.php`
  - `backend_php/utils/Totp.php`
  - `backend_php/utils/SmtpMailer.php`
- **Dokumentasi Terkait:**
  - [Panduan Instalasi dan Konfigurasi Aman](panduan-instalasi-konfigurasi-aman.md)
  - [Panduan Operasional](panduan-operasional.md)
  - [Dokumentasi Perbaikan 04: Penyimpanan Data Persisten](perbaikan/04-persistent-local-database.md)
