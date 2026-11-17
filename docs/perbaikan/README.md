# DOKUMENTASI PERBAIKAN SECURE VAULT

Dokumen ini merupakan indeks dan pelacak progres pengerjaan perbaikan sistem Secure Vault yang dilakukan secara bertahap, modular, dan terdokumentasi.

---

## Daftar Status Perbaikan

| No | Modul Perbaikan | Ruang Lingkup | Status | Dokumen Teknis |
| :--- | :--- | :--- | :--- | :--- |
| **01** | **SHA3-512 pada Hash-Chain Jejak Audit** | Penggantian algoritma audit hash-chain ke SHA3-512 (128 hex, `hash_version = 3`), multi-version verification (V1/V2/V3), genesis enforcement, dan audit anchor compatibility. | **SELESAI (PASS)** | [01-perubahan-sha3-512-audit.md](01-perubahan-sha3-512-audit.md) |
| **02** | **Kolom Pengguna & IP pada Jejak Audit** | Perbaikan tampilan kolom menjadi hanya menampilkan Alamat IP, penghapusan tampilan username dari tabel, penambahan fallback 'Tidak tersedia', dan penyesuaian label header menjadi 'Alamat IP'. | **SELESAI (PASS)** | [02-perbaikan-kolom-pengguna-ip.md](02-perbaikan-kolom-pengguna-ip.md) |
| **03** | **Penghilangan Kolom Rantai Hash UI** | Penyesuaian antarmuka konsol audit untuk menyederhanakan tampilan dengan menghilangkan kolom teknis rantai hash, menghasilkan tabel tepat 5 kolom, penyesuaian colspan, dan optimasi lebar CSS. | **SELESAI (PASS)** | [03-penghapusan-kolom-rantai-hash.md](03-penghapusan-kolom-rantai-hash.md) |

---

## Ringkasan Perbaikan 1: SHA3-512 Audit Hash-Chain

- **File Utama yang Dimodifikasi**:
  - `backend_php/utils/Audit.php` (Implementasi hashing V3, multi-version verification, backward compatibility V1/V2).
  - `backend_php/db/Database.php` (Genesis seeding V3 untuk instalasi baru).
  - `backend_php/tests/security_stage2.py` (Penyesuaian wewenang role test suite & strict genesis fixture).
- **File Test Baru**:
  - `backend_php/tests/audit_sha3_compat_test.php` (12 skenario pengujian komprehensif, 29 assertions termasuk skrip CLI aktual audit anchor).
- **Hasil Pengujian**:
  - `audit_sha3_compat_test.php`: **PASS (29/29 assertions)**
  - `security_stage2.py`: **PASS (Exit Code 0)**
  - `onboarding_integration.mjs`: **PASS (Exit Code 0)**
  - `iteration5_sqlite_integration_test.py`: **PASS (Exit Code 0)**
  - `mfa_challenge_lock_test.php`: **PASS (Exit Code 0)**
  - `security_stage1.py`: **PASS (Exit Code 0)** (Seluruh 7 asersi keamanan lulus dan koneksi SQLite ditutup deterministik via `contextlib.closing()` tanpa `WinError 32`).
- **Integritas Database**:
  - Database operasional tidak tersentuh (zero mutation). Pengujian sepenuhnya berjalan pada isolated temporary runtime.
- **Kriptografi Non-Audit**:
  - Seluruh algoritma kriptografi di luar audit (Zero-Knowledge AES-256-GCM, AES-KW, PBKDF2/Argon2id, chunk SHA-256, activation HMAC-SHA256, JWT HS256, password Argon2id) dipertahankan utuh tanpa perubahan.

---

## Ringkasan Perbaikan 2: Kolom Alamat IP pada Jejak Audit

- **File Utama yang Dimodifikasi**:
  - `frontend/js/app.js` (Fungsi `auditTemplate()` baris 460: Mengubah header tabel menjadi `Alamat IP`, menghilangkan rendering `log.user_id`, menyematkan `log.ip_address` dalam class `audit-user-id mono` dengan fallback `Tidak tersedia`).
- **File yang Tidak Dimodifikasi (Divalidasi)**:
  - `frontend/src/components/AuditLogViewer.tsx` (Dikonfirmasi sebagai artefak React pengujian lama yang tidak dipakai runtime aktif).
  - Seluruh backend PHP, database SQLite, API endpoint, dan kriptografi audit (100% utuh tanpa modifikasi).
- **File Test Baru**:
  - `backend_php/tests/audit_ip_column_test.mjs` (16 skenario pengujian rendering IP IPv4/IPv6, penghilangan username, fallback null/kosong, styling monospace, dan proteksi XSS).
- **Hasil Pengujian**:
  - `audit_ip_column_test.mjs`: **PASS (16/16 assertions)**
  - `audit_sha3_compat_test.php`: **PASS (29/29 assertions)**
  - `frontend_security_static.py`: **PASS (Exit Code 0)**
  - `security_stage1.py`: **PASS (Exit Code 0)**
  - `security_stage2.py`: **PASS (Exit Code 0)**
  - `onboarding_integration.mjs`: **PASS (Exit Code 0)**
  - `iteration5_sqlite_integration_test.py`: **PASS (Exit Code 0)**
  - `mfa_challenge_lock_test.php`: **PASS (Exit Code 0)**
- **Integritas Database**:
  - Field `user_id` dan `ip_address` tetap tersimpan secara terpisah di basis data SQLite. Zero mutation pada data operasional.

---

## Ringkasan Perbaikan 3: Penghapusan Kolom Rantai Hash UI

- **File Utama yang Dimodifikasi**:
  - `frontend/js/app.js` (Fungsi `auditTemplate()` baris 460: Menghapus header `<th scope="col">Rantai hash</th>`, menghapus sel `<td>` potongan hash `previous_hash` & `current_hash`, mengubah kedua `colspan="6"` menjadi `colspan="5"`, memastikan setiap baris data merender tepat 5 sel).
  - `frontend/styles.css` (Baris 884–897: Menyesuaikan `min-width: 800px`, menghapus selektor `.audit-console .audit-table th:nth-child(6){width:245px}`, menghapus styling spesifik yang tidak terpakai `.audit-console .hash-line` dan `.audit-console .current-hash`).
- **File yang Tidak Dimodifikasi (Divalidasi)**:
  - `frontend/src/components/AuditLogViewer.tsx` (Artefak React lama yang tidak digunakan runtime aktif).
  - `backend_php/utils/Audit.php`, `backend_php/db/Database.php`, `backend_php/routes/AuditRoutes.php`, `backend_php/db/schema_sqlite.sql`, dan basis data SQLite (100% utuh tanpa modifikasi apa pun).
  - Skrip CLI `export_audit_anchor.php` dan `verify_audit_anchor.php` (100% utuh dan tetap kompatibel).
- **File Test Baru**:
  - `backend_php/tests/audit_table_columns_test.mjs` (15 skenario pengujian: 5 header berurutan, ketiadaan hash visual, ketiadaan string hash dan teks "Sebelumnya:"/"Saat ini:", 5 sel per baris data, colspan=5 pada loading & empty state, kelulusan IP, status, dan aktivitas, serta validasi CSS).
- **Hasil Pengujian**:
  - `audit_table_columns_test.mjs`: **PASS (15/15 assertions, Exit Code 0)**
  - `audit_ip_column_test.mjs`: **PASS (16/16 assertions, Exit Code 0)**
  - `frontend_security_static.py`: **PASS (Exit Code 0)**
  - `audit_sha3_compat_test.php`: **PASS (29/29 assertions, Exit Code 0)**
  - `security_stage1.py`: **PASS (Exit Code 0)**
  - `security_stage2.py`: **PASS (Exit Code 0)**
  - `onboarding_integration.mjs`: **PASS (Exit Code 0)**
  - `iteration5_sqlite_integration_test.py`: **PASS (Exit Code 0)**
  - `mfa_challenge_lock_test.php`: **PASS (Exit Code 0)**
- **Integritas Hash-Chain**:
  - Algoritma hashing SHA3-512 V3, transisi multi-versi V1/V2/V3, anchor verification, dan deteksi tampering audit di backend tetap beroperasi penuh tanpa ada dampak negatif dari perubahan UI ini.
