# Panduan Audit Log Secure Vault

---

## 1. Pendahuluan dan Tujuan

Dokumen ini merupakan panduan resmi mengenai sistem **Audit Log (Jejak Audit)** pada aplikasi **Secure Vault** berdasarkan implementasi kode sumber aktual pada repository resmi.

**Tujuan dokumen ini** adalah menjelaskan:
- Arsitektur dan mekanisme pencatatan event keamanan serta operasional.
- Struktur data, atribut, dan katalog lengkap event yang benar-benar dicatat (beserta event yang **belum** dicatat).
- Hak akses, tampilan antarmuka **Jejak Audit**, dan endpoint API terkait.
- Mekanisme integritas *hash-chain* (V1, V2, dan V3 SHA3-512), *Audit Anchor*, prosedur verifikasi, penanganan anomali, serta keterbatasan sistem.

---

## 2. Ruang Lingkup Audit Log

Sistem audit log Secure Vault mencakup:
- **Pencatatan sinkron sisi backend** melalui `Audit::logEvent()` (`backend_php/utils/Audit.php`) untuk aktivitas autentikasi, aktivasi/onboarding, MFA, manajemen brankas, operasi folder/berkas, administrasi akun, dan skrip CLI tertentu.
- **Penyimpanan relasional** pada tabel `audit_logs` dalam basis data SQLite (`DATA_DIR/secure-vault.sqlite`).
- **Verifikasi rantai hash** secara internal melalui `Audit::verifyChain()`, API administrator (`GET /api/audit/verify`), serta verifikasi *checkpoint* eksternal opsional melalui skrip CLI `export_audit_anchor.php` dan `verify_audit_anchor.php`.

---

## 3. Arsitektur dan Mekanisme Pencatatan

### 3.1 Mekanisme Pencatatan (`Audit::logEvent()`)
Setiap event dicatat secara **sinkron** melalui fungsi `Audit::logEvent()` pada `backend_php/utils/Audit.php`:
1. Membaca seluruh catatan `audit_logs` yang ada di memori/snapshot `Database::getInstance()->getAuditLogs()` untuk mengambil entri terakhir (`$lastLog`).
2. Menentukan `sequence_number` berikutnya (`$lastLog['sequence_number'] + 1`, atau `1` jika kosong) dan `previous_hash` (`$lastLog['current_hash']`, atau 128 karakter `'0'` jika kosong).
3. Membentuk entri baru dengan `hash_version = 3`, menghitung `current_hash` menggunakan `Audit::computeEntryHashV3($entry)` (**SHA3-512**), lalu menyimpannya melalui `$db->addAuditLog($entry)`.

### 3.2 Lokasi Penyimpanan dan Keterkaitan Transaksi
- **Lokasi penyimpanan:** Tabel `audit_logs` pada `DATA_DIR/secure-vault.sqlite` (di luar web root) sesuai skema `backend_php/db/schema_sqlite.sql`.
- **Serialisasi & konkurensi:** `Database::__construct()` mengunci `DB_LOCK_FILE` (`flock(..., LOCK_EX)`) selama siklus permintaan sehingga penulisan `sequence_number` dan `previous_hash` antarentri tetap berurutan.
- **Transaksi atomik mutasi + audit:** Pada beberapa operasi (seperti `AdminRoutes::resendVerificationCode()`, `AdminRoutes::deleteUser()`, `AuthRoutes::activateAccount()`, dan `FileRoutes::createFolder()`, `deleteFolder()`, `init()`, `uploadChunk()`, `complete()`, `updateMetadata()`, `delete()`), pemanggilan `Audit::logEvent()` dibungkus di dalam `$db->transaction(...)` sehingga mutasi data dan entri audit di-commit bersama dalam satu transaksi SQLite.
- **Penanganan kegagalan pencatatan:** Jika serialisasi JSON gagal, `Audit::computeEntryHashV3()` melempar `RuntimeException`. Jika terjadi kegagalan commit transaksi SQLite (`Database::persist()`), transaksi di-*rollback* dan eksepsi ditangkap oleh *global exception handler* di `backend_php/index.php` (log error server via `error_log()`, respons HTTP 500 ke klien).

### 3.3 Genesis Entry
Pada instalasi baru yang kosong, `Database::seed()` (`backend_php/db/Database.php`) otomatis membuat entri genesis (`sequence_number = 1`, `action_type = 'SYSTEM_GENESIS'`, `user_id = 'SYSTEM_BOOTSTRAP'`, `status = 'SUCCESS'`, `hash_version = 3`, `previous_hash = str_repeat('0', 128)`, dan `current_hash` SHA3-512).

---

## 4. Struktur Data dan Atribut Audit Log

### 4.1 Skema Tabel `audit_logs` (`backend_php/db/schema_sqlite.sql`)
Tabel `audit_logs` menyimpan kolom relasional terindeks (`id`, `record_key`, `sequence_number` UNIQUE, `timestamp`, `user_id`, `action_type`, `file_id`, `status`, `previous_hash`, `current_hash`) serta kolom `payload` (JSON lengkap entri audit).

### 4.2 Atribut pada Entri Audit (`Audit::logEvent()`)

| Atribut | Tipe / Format | Keterangan & Nilai Fallback |
| :--- | :--- | :--- |
| `id` | String (UUID v4) | Dihasilkan oleh `Database::generateUuid()`. |
| `sequence_number` | Integer (unik, berurutan) | Dimulai dari `1`, bertambah `1` per entri. |
| `timestamp` | String ISO-8601 UTC | Format `gmdate('Y-m-d\TH:i:s.000\Z')`. |
| `user_id` | String | UUID pengguna, `'UNKNOWN_USER'` (login gagal untuk username tak dikenal), `'SYSTEM_BOOTSTRAP'` (genesis), `'SYSTEM_CLI_OPERATOR'` (`promote_admin.php`), atau `'SYSTEM_OPERATOR'` (`migrate_audit_v2.php`). |
| `action_type` | String | Kode jenis aktivitas (lihat Bagian 5). |
| `file_id` | String (UUID) / `null` | Opsional; terisi UUID berkas/folder pada event `FileRoutes`, `null` pada event akun/auth/admin. |
| `ip_address` | String | Diambil dari argumen `$ipAddress`, atau fallback `$_SERVER['REMOTE_ADDR'] ?? '127.0.0.1'`. |
| `user_agent` | String | Diambil dari argumen `$userAgent`, atau fallback `$_SERVER['HTTP_USER_AGENT'] ?? 'SecureVault/PHP'`. |
| `status` | String | Default `'SUCCESS'`; bernilai `'FAILED'` pada event kegagalan. |
| `details` | String / `null` | Opsional; berisi pasangan `key=value;` (mis. `size_bytes=...;total_chunks=...`, `chunk_index=...`, `target_user_id=...`) atau `null` bila tidak disuplai. |
| `hash_version` | Integer | `3` untuk seluruh entri baru (`1` atau `2` pada entri historis). |
| `previous_hash` | String (hex) | `current_hash` entri sebelumnya (`128` nol pada genesis V3; `64` nol pada genesis V1/V2). |
| `current_hash` | String (hex) | Digest SHA3-512 (`128` hex) untuk V3, atau SHA-256 (`64` hex) untuk V1/V2. |

> [!NOTE]
> **Perbedaan Database vs API vs UI:**
> - **Database & API (`GET /api/audit`):** Menyimpan dan mengembalikan seluruh objek entri lengkap (termasuk `user_id`, `user_agent`, `previous_hash`, `current_hash`, `hash_version`).
> - **Tampilan UI (`frontend/js/app.js`):** Tabel **Jejak Audit** hanya merender 5 kolom: **No.** (`#sequence_number`), **Waktu** (`timestamp`), **Aktivitas** (terjemahan `action_type` + ringkasan `details` yang dikenali), **Alamat IP** (`ip_address` dengan fallback `'Tidak tersedia'`), dan **Status** (`Berhasil`/`Gagal`). Kolom `user_id` dan rantai hash sengaja tidak ditampilkan di UI (sesuai Perbaikan 02 & 03).

---

## 5. Katalog Event yang Dicatat

Berdasarkan pencarian seluruh pemanggilan `Audit::logEvent()` dan `Database::seed()` di `backend_php/`, terdapat **34 jenis `action_type`** yang benar-benar dicatat:

### 5.1 Autentikasi, Sesi, dan Kegagalan Login (`AuthRoutes.php`)
| `action_type` | Pemicu Aktual | Status | Sumber |
| :--- | :--- | :--- | :--- |
| `AUTH_CREDENTIALS_VERIFIED` | Username dan kata sandi cocok saat login (lanjut ke tahap MFA). | `SUCCESS` | `AuthRoutes::login()` |
| `AUTH_LOGIN_FAILED` | Username tidak ditemukan atau kata sandi salah (`user_id` = ID user atau `'UNKNOWN_USER'`). | `FAILED` | `AuthRoutes::login()` |
| `AUTH_LOGOUT` | Pengguna melakukan logout (`POST /api/auth/logout`). | `SUCCESS` | `AuthRoutes::logout()` |

### 5.2 MFA dan Verifikasi Email / Onboarding (`AuthRoutes.php`, `AdminRoutes.php`)
| `action_type` | Pemicu Aktual | Status | Sumber |
| :--- | :--- | :--- | :--- |
| `AUTH_MFA_ENROLLED` | Pengguna menyelesaikan aktivasi TOTP pertama kali. | `SUCCESS` | `AuthRoutes::verifyMfa()` |
| `AUTH_MFA_SUCCESS` | Verifikasi TOTP berhasil dan token sesi JWT diterbitkan. | `SUCCESS` | `AuthRoutes::issueSession()` |
| `AUTH_MFA_FAILED` | Kode TOTP salah atau terdeteksi *replay* counter. | `FAILED` | `AuthRoutes::verifyMfa()` |
| `AUTH_ACTIVATION_LINK_SENT` | Tautan aktivasi akun dikirim saat admin membuat user baru. | `SUCCESS` | `AdminRoutes::createUser()` |
| `AUTH_EMAIL_CODE_SENT` | Kode verifikasi email 8 digit dikirim saat *onboarding* login. | `SUCCESS` | `AuthRoutes::startOnboarding()` |
| `AUTH_EMAIL_VERIFY_FAILED` | Kode verifikasi email 8 digit salah. | `FAILED` | `AuthRoutes::verifyOnboardingEmail()` |
| `AUTH_EMAIL_VERIFIED` | Verifikasi email berhasil (via kode onboarding atau tautan aktivasi). | `SUCCESS` | `AuthRoutes::verifyOnboardingEmail()`, `activateAccount()` |
| `AUTH_ONBOARDING_COMPLETE` | Kata sandi baru ditetapkan dan akun diaktifkan. | `SUCCESS` | `AuthRoutes::activateAccount()`, `completeOnboarding()` |

### 5.3 Manajemen Brankas (`AuthRoutes.php`)
| `action_type` | Pemicu Aktual | Status | Sumber |
| :--- | :--- | :--- | :--- |
| `VAULT_SETUP` | Profil brankas Zero-Knowledge pertama kali dibuat. | `SUCCESS` | `AuthRoutes::setupVault()` |
| `VAULT_REWRAP_MK` | *Passphrase* brankas diganti dan *Master Key* di-*wrap* ulang. | `SUCCESS` | `AuthRoutes::rewrapMasterKey()` |

### 5.4 Aktivitas Folder, Berkas, Upload, Download, dan Integritas (`FileRoutes.php`)
| `action_type` | Pemicu Aktual | Status | Sumber |
| :--- | :--- | :--- | :--- |
| `FOLDER_CREATE` | Folder terenkripsi baru dibuat (`file_id` terisi UUID folder). | `SUCCESS` | `FileRoutes::createFolder()` |
| `FOLDER_DELETE` | Folder kosong dihapus (`file_id` terisi UUID folder). | `SUCCESS` | `FileRoutes::deleteFolder()` |
| `FILE_INIT` | Inisialisasi unggahan berkas dan reservasi kuota (`details`: `size_bytes`, `total_chunks`). | `SUCCESS` | `FileRoutes::init()` |
| `FILE_CHUNK_UPLOAD` | Setiap potongan (*chunk*) baru berhasil disimpan (`details`: `chunk_index`, `ciphertext_bytes`). | `SUCCESS` | `FileRoutes::uploadChunk()` |
| `FILE_UPLOAD_COMPLETE` | Seluruh chunk terverifikasi dan unggahan difinalisasi (`details`: `total_chunks`, `file_size_bytes`). | `SUCCESS` | `FileRoutes::complete()` |
| `FILE_UPLOAD_INTEGRITY_FAILURE` | Hash SHA-256 *ciphertext* chunk di disk tidak cocok saat finalisasi (`details`: `chunk_index`). | `FAILED` | `FileRoutes::complete()` |
| `FILE_DOWNLOAD` | Pengunduhan berkas dimulai — **hanya dicatat pada `$chunkIndex === 0`**. | `SUCCESS` | `FileRoutes::streamChunkData()` |
| `FILE_DOWNLOAD_INTEGRITY_FAILURE` | Hash SHA-256 *ciphertext* chunk gagal diverifikasi saat unduh (`details`: `chunk_index`). | `FAILED` | `FileRoutes::streamChunkData()` |
| `FILE_METADATA_UPDATE` | Nama atau tag terenkripsi berkas diperbarui (`details`: `fields`). | `SUCCESS` | `FileRoutes::updateMetadata()` |
| `FILE_DELETE_PENDING` | Berkas ditandai `deletion_pending` sebelum pembersihan filesystem (`details`: `file_size_bytes`). | `SUCCESS` | `FileRoutes::delete()` |
| `FILE_DELETE` | Berkas dan metadata chunk selesai dihapus (`details`: `file_size_bytes`, `upload_status`). | `SUCCESS` | `FileRoutes::delete()` |

### 5.5 Aktivitas Administrator dan Sistem (`AdminRoutes.php`, `Database.php`, Skrip CLI)
| `action_type` | Pemicu Aktual | Status | Sumber |
| :--- | :--- | :--- | :--- |
| `ADMIN_CREATE_USER` | Administrator membuat akun pengguna baru. | `SUCCESS` | `AdminRoutes::createUser()` |
| `ADMIN_RESEND_ACTIVATION_LINK` | Administrator mengirim ulang tautan aktivasi (`details`: `target_user_id`). | `SUCCESS` | `AdminRoutes::resendVerificationCode()` |
| `ADMIN_UPDATE_QUOTA` | Administrator mengubah kuota pengguna (`details`: `target_user_id`, `quota_bytes`). | `SUCCESS` | `AdminRoutes::updateQuota()` |
| `ADMIN_ACCOUNT_DEACTIVATED` | Administrator menonaktifkan akun & mencabut sesi (`details`: `target_user_id`). | `SUCCESS` | `AdminRoutes::revokeUser()` |
| `ADMIN_ACCOUNT_REACTIVATED` | Administrator mengaktifkan kembali akun (`details`: `target_user_id`). | `SUCCESS` | `AdminRoutes::reactivateUser()` |
| `ADMIN_DELETE_USER` | Administrator menghapus akun permanen (`details`: `target_user_id`, `deleted_files`). | `SUCCESS` | `AdminRoutes::deleteUser()` |
| `ADMIN_INITIAL_SETUP` | Akun administrator pertama dibuat via CLI (`details`: `username`, `email`). | `SUCCESS` | `backend_php/scripts/init_admin.php` |
| `ADMIN_ROLE_PROMOTION` | Akun dipromosikan menjadi admin via CLI. | `SUCCESS` | `backend_php/scripts/promote_admin.php` |
| `AUDIT_CHAIN_MIGRATED_V2` | Migrasi rantai audit ke V2 dijalankan via CLI (`details`: `records`). | `SUCCESS` | `backend_php/scripts/migrate_audit_v2.php` |
| `SYSTEM_GENESIS` | Inisialisasi otomatis entri pertama pada database baru. | `SUCCESS` | `Database::seed()` |

---

## 6. Event yang Belum Dicatat atau Belum Terverifikasi

Berdasarkan pemeriksaan seluruh `index.php`, `AuthMiddleware.php`, `AuthRoutes.php`, `AdminRoutes.php`, `FileRoutes.php`, dan `AuditRoutes.php`, kondisi berikut **TIDAK dicatat** ke tabel `audit_logs` (hanya mengembalikan respons HTTP kepada klien):

- **Penolakan Akses / HTTP 403:** Upaya pendaftaran publik (`POST /api/auth/register`), akses pengguna biasa ke endpoint admin/audit (`AuthMiddleware::requireAdmin()`), percobaan login pada akun nonaktif, maupun penolakan akses berkas milik pengguna lain hanya mengembalikan HTTP 403 tanpa memanggil `Audit::logEvent()`.
- **Kegagalan Token JWT / HTTP 401 pada `AuthMiddleware::authenticate()`:** Token tidak ada, kedaluwarsa, tidak valid, atau `session_version` telah dicabut hanya mengembalikan HTTP 401 tanpa pencatatan audit.
- **Endpoint atau Objek Tidak Ditemukan (HTTP 404):** Permintaan ke rute yang tidak terdaftar di `index.php` atau ID berkas/folder/pengguna yang tidak ditemukan tidak dicatat ke `audit_logs`.
- **Pemblokiran *Rate Limit* (HTTP 429):** Saat batas 5 percobaan per 15 menit terlampaui pada login, aktivasi, atau MFA (atau jeda 1 menit pengiriman ulang email), respons HTTP 429 dikirim tanpa entri audit baru *(kegagalan percobaan sebelumnya tetap tercatat sebagai `AUTH_LOGIN_FAILED` / `AUTH_MFA_FAILED`, sedangkan counter pembatasan disimpan di tabel `auth_rate_limits`)*.
- **Pembacaan Daftar / Pratinjau tanpa Unduh Chunk 0:** `GET /api/files`, `GET /api/folders`, `GET /api/audit`, `GET /api/admin/users`, serta `GET /api/files/{id}/chunk/{idx}/meta` tidak mencatat entri audit. Untuk `streamChunkData()`, chunk dengan indeks `> 0` tidak mencatat `FILE_DOWNLOAD` ulang (hanya chunk `0`).
- **Catatan UI `frontend/js/app.js`:** `AUDIT_ACTION_LABELS` memiliki pemetaan label `USER_REGISTER` dan `ADMIN_REVOKE_USER_SESSION`, namun backend aktual tidak lagi memancarkan kedua kode tersebut (menggunakan `ADMIN_CREATE_USER` dan `ADMIN_ACCOUNT_DEACTIVATED`).

---

## 7. Hak Akses dan Penggunaan Jejak Audit

- **Otorisasi API:** Endpoint `GET /api/audit` (`AuditRoutes::list()`) dan `GET /api/audit/verify` (`AuditRoutes::verify()`) mewajibkan `AuthMiddleware::authenticate()` dan `AuthMiddleware::requireAdmin($user)`. Pengguna biasa menerima HTTP 403.
- **Antarmuka Web (UI):** Menu **Jejak Audit** di sidebar hanya dirender apabila `state.user.role === 'admin'`.
  - **Ringkasan audit:** Menampilkan **Total aktivitas**, **Berhasil**, dan **Gagal**.
  - **Filter:** Dropdown **Aktivitas** (berdasarkan daftar `action_type` yang ada) dan **Status** (**Semua status**, **Berhasil**, **Gagal**), serta tombol **Perbarui data**.
  - **Kolom tabel:** `No.`, `Waktu`, `Aktivitas`, `Alamat IP`, `Status` (diurutkan menurun dari `sequence_number` terbesar).

---

## 8. Mekanisme Hash-Chain dan SHA3-512

Setiap entri baru yang dibuat oleh `Audit::logEvent()` menggunakan **V3 (`hash_version = 3`)**:

1. **Algoritma:** `hash('sha3-512', $encoded)` menghasilkan digest **128 karakter heksadesimal** (512 bit).
2. **Payload Kanonikal V3 (`Audit::computeEntryHashV3()`):**
   Payload disusun dengan urutan key tetap (`version` = `3`, `id`, `sequence_number`, `timestamp`, `user_id`, `action_type`, `file_id`, `status`, `ip_address`, `user_agent`, `details`, `previous_hash`), lalu di-encode dengan `json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)`.
3. **Keterkaitan Rantai:** `previous_hash` pada entri ke-$N$ wajib sama persis (`hash_equals`) dengan `current_hash` pada entri ke-$(N-1)$. Entri genesis V3 menggunakan `str_repeat('0', 128)`.
4. **Kondisi Kegagalan Integritas (`Audit::verifyChain()`):**
   - Nomor urut (`sequence_number`) tidak kontinu (`$sequence !== $i + 1`).
   - `previous_hash` genesis tidak cocok dengan format versinya (`64` nol untuk V1/V2, `128` nol untuk V3).
   - `previous_hash` entri berikutnya tidak sama dengan `current_hash` entri sebelumnya (*"Rantai audit terputus"*).
   - Atribut wajib hilang pada entri V2/V3.
   - `current_hash` tidak cocok dengan hasil perhitungan ulang (*"Manipulasi data terdeteksi"*).

---

## 9. Kompatibilitas Audit Versi Lama

`Audit::verifyChain()` mendukung verifikasi **multi-versi (V1, V2, dan V3)** dalam satu rantai tanpa mewajibkan perhitungan ulang entri historis:

- **Versi 1 (`hash_version = 1` atau tidak ada field `hash_version`):** Menggunakan `Audit::computeLogHash()` dengan **SHA-256** (`64` hex) atas string `"{$prevHash}:{$timestamp}:{$userId}:{$actionType}:{$fileIdStr}:{$status}"`. Atribut `id`, `sequence_number`, `ip_address`, `user_agent`, dan `details` **belum** dilindungi oleh hash V1. Genesis V1 memakai `64` karakter `'0'`.
- **Versi 2 (`hash_version = 2`):** Menggunakan `Audit::computeEntryHashV2()` dengan **SHA-256** (`64` hex) atas JSON berurutan 12 field (`version = 2` + `id`, `sequence_number`, `timestamp`, `user_id`, `action_type`, `file_id`, `status`, `ip_address`, `user_agent`, `details`, `previous_hash`). Genesis V2 memakai `64` karakter `'0'`.
- **Transisi V1/V2 ke V3:** Entri V3 pertama setelah entri V2/V1 tetap menggunakan `previous_hash` 64-karakter dari entri sebelumnya dan menghasilkan `current_hash` 128-karakter (SHA3-512). Hasil `Audit::verifyChain()` melaporkan jumlah `legacyRecords` (V1), `v2Records`, dan `v3Records`.

---

## 10. Prosedur Verifikasi Integritas Audit

- **Melalui API Administrator:**
  Kirim permintaan `GET /api/audit/verify` dengan header `Authorization: Bearer <token-admin>`. Endpoint mengembalikan JSON berisi `isValid` (`true`/`false`), `totalRecords`, `legacyRecords`, `v2Records`, `v3Records`, `brokenSequence` (jika gagal), dan `message`.
- **Ringkasan Otomatis di Konsol Admin:**
  `GET /api/admin/stats` juga memanggil `Audit::verifyChain()` dan mengembalikan `chainIntegrity` (`true`/`false`), meskipun indikator tersebut saat ini tidak dirender sebagai elemen terpisah pada UI Konsol Admin (`frontend/js/app.js`).
- **Pada Antarmuka Web:**
  Tidak terdapat tombol "Verifikasi Rantai" pada halaman **Jejak Audit** di UI; verifikasi eksplisit dilakukan melalui endpoint `/api/audit/verify` atau skrip CLI Audit Anchor.

---

## 11. Audit Anchor: Ekspor dan Verifikasi Checkpoint

Repository menyediakan mekanisme **Audit Anchor** berbasis CLI (**bukan proses otomatis**; dijalankan manual oleh operator):

1. **Prasyarat:**
   Siapkan secret khusus **32 byte acak** dalam format Base64 pada environment variable CLI `AUDIT_ANCHOR_HMAC_KEY`. Secret ini **tidak boleh** diberikan ke proses web/PHP-FPM.
2. **Ekspor Checkpoint (`backend_php/scripts/export_audit_anchor.php`):**
   - Memverifikasi rantai audit via `Audit::verifyChain()` terlebih dahulu.
   - Membentuk payload `secure-vault-audit-anchor-v1` (`created_at`, `record_count`, `latest_sequence`, `head_hash`) dan menandatanganinya dengan `hash_hmac('sha256', $canonical, $key)`.
   - Menulis file JSON secara atomik ke path argumen CLI atau default `PRIVATE_DIR/audit-anchors/anchor-YYYYmmdd-His.json` (izin `0600`).
   - **Penting:** Secara bawaan tidak ada penyimpanan eksternal terpisah yang otomatis terkonfigurasi; operator **harus menyalin secara manual** file checkpoint ke media *offline*, WORM, atau host terpisah.
3. **Verifikasi Checkpoint (`backend_php/scripts/verify_audit_anchor.php`):**
   ```bash
   php backend_php/scripts/verify_audit_anchor.php /path/ke/anchor.json
   ```
   Memvalidasi tanda tangan `hmac_sha256`, menjalankan `Audit::verifyChain()`, dan memastikan entri pada `latest_sequence` di database lokal masih memiliki `current_hash` yang identik dengan `head_hash` di checkpoint.

---

## 12. Prosedur Pemeriksaan dan Penanganan Anomali Audit

1. **Deteksi via UI Jejak Audit:** Filter status **Gagal** untuk memeriksa lonjakan `AUTH_LOGIN_FAILED`, `AUTH_MFA_FAILED`, `FILE_UPLOAD_INTEGRITY_FAILURE`, atau `FILE_DOWNLOAD_INTEGRITY_FAILURE`.
2. **Verifikasi Integritas Rantai:** Jalankan permintaan ke `GET /api/audit/verify` (sebagai admin) dan/atau `php backend_php/scripts/verify_audit_anchor.php <checkpoint.json>`.
3. **Jika Terjadi Kegagalan Rantai atau Ketidakcocokan Anchor:**
   - Hentikan sementara layanan jika diduga terjadi manipulasi basis data.
   - Catat nomor urut `brokenSequence` dan pesan error dari `Audit::verifyChain()`.
   - Bandingkan basis data aktif dengan salinan cadangan SQLite terverifikasi dan checkpoint *Audit Anchor* eksternal.
   - *SOP penanganan insiden keamanan menyeluruh belum tersedia di repository — Perlu verifikasi / dokumentasi terpisah.*

---

## 13. Keterbatasan dan Risiko Residual

1. **Hash-Chain Lokal Bukan Penyimpanan Immutable Penuh:** Seperti dijelaskan pada `README.md`, penyimpanan SQLite lokal tetap dapat dimodifikasi dan dihitung ulang seluruh rantainya oleh pihak/administrator yang menguasai penuh sistem host (kecuali ada pembanding *Audit Anchor* eksternal yang disimpan terpisah bersama `AUDIT_ANCHOR_HMAC_KEY`).
2. **Audit Anchor Bersifat Manual:** Tidak ada penjadwalan atau pengiriman otomatis checkpoint ke penyimpanan eksternal di dalam kode aplikasi.
3. **Tidak Ada Pencatatan Penolakan Akses (401/403/404/429):** Upaya akses tidak sah ke endpoint admin/audit atau token kedaluwarsa tidak tercatat di `audit_logs` (hanya tercatat di log akses web server jika diaktifkan).
4. **Keterbatasan Atribut V1:** Entri historis berformat `hash_version = 1` tidak mengikat `ip_address`, `user_agent`, `details`, dan `sequence_number` ke dalam hash.
5. **Skalabilitas Pembacaan:** `Audit::logEvent()` dan `Audit::verifyChain()` memuat seluruh `audit_logs` ke memori melalui `Database::getAuditLogs()` pada setiap operasi.

---

## 14. Bukti Pengujian

Berdasarkan berkas pengujian pada `backend_php/tests/` dan laporan hasil pengujian yang terdokumentasi di [docs/perbaikan/README.md](perbaikan/README.md) serta [docs/perbaikan/01-perubahan-sha3-512-audit.md](perbaikan/01-perubahan-sha3-512-audit.md) *(tidak dijalankan ulang dalam sesi penyusunan dokumen ini)*:

- `backend_php/tests/audit_sha3_compat_test.php`: **PASS (29/29 assertions)** — menguji genesis V3, kompatibilitas V1/V2/V3, transisi rantai, deteksi manipulasi, dan kompatibilitas `export_audit_anchor.php` / `verify_audit_anchor.php`.
- `backend_php/tests/audit_ip_column_test.mjs`: **PASS (16/16 assertions)** — menguji tampilan kolom `Alamat IP`, penghapusan `user_id` di UI, fallback `'Tidak tersedia'`, dan proteksi XSS.
- `backend_php/tests/audit_table_columns_test.mjs`: **PASS (15/15 assertions)** — menguji 5 kolom tabel UI Jejak Audit dan ketiadaan kolom rantai hash di tampilan.
- `backend_php/tests/security_stage2.py`: **PASS (Exit Code 0)** — mencakup pengujian otorisasi audit admin vs user dan rantai hash.

---

## 15. Referensi File Kode dan Dokumentasi

- **Kode Sumber Backend:**
  - `backend_php/utils/Audit.php`
  - `backend_php/routes/AuditRoutes.php`
  - `backend_php/routes/AuthRoutes.php`
  - `backend_php/routes/AdminRoutes.php`
  - `backend_php/routes/FileRoutes.php`
  - `backend_php/middleware/AuthMiddleware.php`
  - `backend_php/db/Database.php` & `backend_php/db/schema_sqlite.sql`
  - `backend_php/scripts/export_audit_anchor.php` & `backend_php/scripts/verify_audit_anchor.php`
  - `backend_php/scripts/init_admin.php`, `promote_admin.php`, `migrate_audit_v2.php`
  - `backend_php/utils/RateLimiter.php`
- **Kode Sumber Frontend:**
  - `frontend/js/app.js` (`AUDIT_ACTION_LABELS`, `auditTemplate()`, `fetchAudit()`)
- **Dokumentasi Terkait:**
  - [Panduan Instalasi dan Konfigurasi Aman](panduan-instalasi-konfigurasi-aman.md)
  - [Panduan Operasional](panduan-operasional.md)
  - [SOP Backup dan Restore](prosedur-backup-restore.md)
  - [Perbaikan 01: Implementasi SHA3-512 Audit](perbaikan/01-perubahan-sha3-512-audit.md)
  - [Perbaikan 02: Kolom Alamat IP pada Jejak Audit](perbaikan/02-perbaikan-kolom-pengguna-ip.md)
  - [Perbaikan 03: Penghapusan Kolom Rantai Hash UI](perbaikan/03-penghapusan-kolom-rantai-hash.md)
