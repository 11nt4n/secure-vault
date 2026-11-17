# DOKUMENTASI TEKNIS PERBAIKAN 1: IMPLEMENTASI SHA3-512 PADA HASH-CHAIN JEJAK AUDIT SECURE VAULT

---

## 1. Latar Belakang Perubahan

Sistem Jejak Audit (*Audit Trail*) pada Secure Vault bertugas merekam seluruh kejadian penting (seperti otentikasi pengguna, manajemen akun, perubahan kuota, inisialisasi file, hingga penghapusan berkas) ke dalam sebuah struktur data berantai anti-manipulasi (*cryptographic tamper-evident hash-chain*).

Pada implementasi awal (Versi 1 dan Versi 2), Secure Vault menggunakan algoritma **SHA-256** dari keluarga SHA-2 untuk menghasilkan digest rantai audit. Meskipun SHA-256 saat ini masih tergolong aman, arsitektur keamanan tingkat tinggi Secure Vault menuntut ketahanan jangka panjang (*future-proofing*), resistensi terhadap serangan tabrakan tingkat lanjut (*collision resistance*), serta divergensi arsitektural dari fungsi kompresi berbasis struktur Merkle–Damgård.

Untuk mencapai standar tersebut, algoritma hashing rantai audit ditingkatkan menjadi **SHA3-512** (keluarga SHA-3 yang berbasis konstruksi *sponge* dan permutasi Keccak). Perubahan ini meningkatkan ukuran digest dari 256-bit (64 karakter heksadesimal) menjadi 512-bit (128 karakter heksadesimal) dengan tingkat keamanan kriptografis yang jauh lebih tinggi.

---

## 2. Kondisi Sebelum Implementasi

Sebelum dilakukan perbaikan, Secure Vault memiliki dua generasi implementasi audit log:

### A. Versi 1 (Legacy)
- **Fungsi Hashing**: `Audit::computeLogHash($prevHash, $ts, $uid, $act, $fid, $stat)`.
- **Format Input**: Penggabungan string sederhana dipisahkan pipa (`|`):
  ```text
  previous_hash|timestamp|user_id|action_type|file_id|status
  ```
- **Algoritma**: SHA-256 (`hash('sha256', ...)`).
- **Genesis Hash**: String historis 64 karakter heksadesimal nol (`str_repeat('0', 64)`).
- **Kelemahan V1**: Metadata penting seperti alamat IP (`ip_address`), User Agent (`user_agent`), dan rincian aktivitas (`details`) belum diikat ke dalam perhitungan hash.

### B. Versi 2 (Canonical Payload)
- **Fungsi Hashing**: `Audit::computeEntryHash(array $entry)`.
- **Format Input**: Serialisasi JSON kanonikal (`Audit::canonicalEntryJson($entry)`), mengurutkan key secara alfabetis (`ksort`) dengan flag `JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE`.
- **Field yang Diikat**: `sequence_number`, `timestamp`, `user_id`, `action_type`, `file_id`, `status`, `ip_address`, `user_agent`, `details`, `previous_hash`, dan `version = 2`.
- **Algoritma**: SHA-256 (`hash('sha256', ...)`), menghasilkan digest 64 karakter heksadesimal.
- **Genesis Hash**: 64 karakter heksadesimal nol (`str_repeat('0', 64)`).
- **Penanda Versi**: `hash_version = 2` disimpan di dalam payload JSON.

### C. Keterbatasan Kondisi Awal
- Metode `Audit::logEvent()` secara default selalu menghasilkan entri baru dengan format V2 dan algoritma SHA-256.
- Database seeder `Database::seed()` menginisialisasi catatan genesis menggunakan hash SHA-256 64 karakter nol.
- Verifikasi rantai (`verifyChain()`) belum mengenal format digest 128 karakter heksadesimal (SHA3-512).

---

## 3. Tujuan Perubahan

1. **Implementasi Hashing V3 (SHA3-512)**:
   - Seluruh entri log audit baru yang dibuat melalui `Audit::logEvent()` wajib menggunakan `hash_version = 3` dan algoritma `sha3-512` dengan panjang digest 128 karakter heksadesimal.
2. **Backward Compatibility Tanpa Migrasi Paksa**:
   - Data historis yang berformat V1 (SHA-256 legacy) dan V2 (SHA-256 canonical) harus tetap valid dan dapat diverifikasi tanpa perlu melakukan kalkulasi ulang atau merusak rekaman historis.
3. **Penanganan Rantai Transisi Mulus**:
   - Mendukung transisi rantai dari V2 ke V3: record V3 pertama yang menyambung record V2 terakhir menggunakan `previous_hash` 64 karakter heksadesimal (dari record V2 terakhir) dan menghasilkan `current_hash` 128 karakter heksadesimal (SHA3-512).
4. **Aturan Genesis Ketat**:
   - Instalasi baru (fresh database) dengan V3 menggunakan genesis 128 karakter nol (`str_repeat('0', 128)`).
   - Menolak keras anomali genesis (misalnya genesis V3 yang memakai 64 nol, atau genesis V2 yang memakai 128 nol).
5. **Kompatibilitas Audit Anchor**:
   - Skrip `export_audit_anchor.php` dan `verify_audit_anchor.php` dapat mengekspor dan memverifikasi jangkar audit baik saat kepala rantai (*head*) masih 64 hex (V2) maupun setelah berganti menjadi 128 hex (V3).
6. **Isolasi Perubahan**:
   - Tidak ada perubahan pada algoritma kriptografi non-audit: enkripsi client-side (Zero-Knowledge, Master Passphrase, Argon2id, AES-KW, AES-256-GCM), integrity hash chunk file (SHA-256), token aktivasi (HMAC-SHA256), token JWT (HS256), password backend (Argon2id), dan enkripsi MFA secret (`MFA_ENCRYPTION_KEY`).

---

## 4. Desain dan Mekanisme SHA3-512 V3

### A. Karakteristik Algoritma
- **Identifier**: `sha3-512` (didukung secara bawaan oleh PHP 8.x via ekstensi OpenSSL/Hash internal).
- **Panjang Output**: 512 bit (64 bytes) = 128 karakter heksadesimal lowercase.
- **Konstruksi**: Sponge construction berbasis permutasi Keccak dengan kapasitas tinggi (1024-bit capacity, rate 576-bit).

### B. Payload dan Serialisasi Kanonikal
Entri log audit V3 mengikat 11 field yang diurutkan secara deterministik sebelum di-hash:

```php
$payload = [
    'action_type'     => $entry['action_type'],
    'details'         => $entry['details'] ?? null,
    'file_id'         => $entry['file_id'] ?? null,
    'ip_address'      => $entry['ip_address'] ?? null,
    'previous_hash'   => $entry['previous_hash'],
    'sequence_number' => (int)$entry['sequence_number'],
    'status'          => $entry['status'],
    'timestamp'       => $entry['timestamp'],
    'user_agent'      => $entry['user_agent'] ?? null,
    'user_id'         => $entry['user_id'] ?? null,
    'version'         => 3,
];
```

Serialisasi string kanonikal dilakukan dengan:
```php
ksort($payload, SORT_STRING);
$encoded = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
$currentHash = hash('sha3-512', $encoded);
```

---

## 5. Strategi Kompatibilitas V1/V2/V3 (Multi-Version Verification)

Untuk menjamin catatan audit historis tetap absah selamanya, `backend_php/utils/Audit.php` menerapkan pemisahan fungsi dan logika verifikasi multi-versi:

```
+-------------------------------------------------------------------------+
|                           Audit::verifyChain()                          |
+-------------------------------------------------------------------------+
                                     |
              +----------------------+----------------------+
              |                      |                      |
      [hash_version == 1]    [hash_version == 2]    [hash_version == 3]
              |                      |                      |
              v                      v                      v
     computeLogHash()       computeEntryHashV2()   computeEntryHashV3()
         (SHA-256)              (SHA-256)              (SHA3-512)
        64-char hex            64-char hex            128-char hex
```

### Logika Algoritma Verifikasi:
1. **Identifikasi Versi**:
   - Jika field `hash_version == 3` (atau `$entry['payload']['version'] == 3`) $\rightarrow$ Versi 3.
   - Jika field `hash_version == 2` $\rightarrow$ Versi 2.
   - Jika tidak terdapat field versi $\rightarrow$ Versi 1 (Legacy).
2. **Validasi Panjang dan Format Hash**:
   - Versi 1 & Versi 2: Format `current_hash` harus cocok dengan `/^[0-9a-f]{64}$/`.
   - Versi 3: Format `current_hash` harus cocok dengan `/^[0-9a-f]{128}$/`.
3. **Rekalkulasi dan Pemeriksaan Integritas**:
   - Menggunakan `hash_equals($entry['current_hash'], $recomputedHash)` untuk menghindari serangan berbasis *timing attack*.
   - Jika terjadi ketidakcocokan, verifikasi langsung mengembalikan status gagal (`isValid = false`) dan mencatat indeks baris yang tidak cocok.

---

## 6. Aturan Genesis dan Transisi Rantai

| Tipe Skenario | Format `previous_hash` | Format `current_hash` | Aturan Validasi |
| :--- | :--- | :--- | :--- |
| **Genesis V1 / V2 (Historis)** | 64 karakter `'0'` | 64 karakter heksadesimal | Wajib persis `str_repeat('0', 64)`. |
| **Genesis V3 (Instalasi Baru)** | 128 karakter `'0'` | 128 karakter heksadesimal | Wajib persis `str_repeat('0', 128)`. |
| **Transisi V2 $\rightarrow$ V3** | 64 karakter heksadesimal | 128 karakter heksadesimal | `previous_hash` wajib identik dengan `current_hash` entri V2 sebelumnya. |
| **Rantai Berkelanjutan V3** | 128 karakter heksadesimal | 128 karakter heksadesimal | `previous_hash` wajib identik dengan `current_hash` entri V3 sebelumnya. |

### Penolakan Format Tidak Sesuai (Strict Enforcement)
- Jika entri pertama bertanda `hash_version = 3` tetapi memiliki `previous_hash` 64 karakter nol, rantai dinyatakan **INVALID**.
- Jika entri pertama bertanda `hash_version = 2` atau V1 tetapi memiliki `previous_hash` 128 karakter nol, rantai dinyatakan **INVALID**.

---

## 7. Perubahan File dan Fungsi

### A. `backend_php/utils/Audit.php`
1. **Menambahkan `computeEntryHashV2(array $entry): string`**:
   - Mempertahankan kalkulasi SHA-256 canonical historis untuk memverifikasi entri V2.
2. **Memperbarui `computeEntryHash(array $entry): string`**:
   - Dialihkan untuk memanggil `self::computeEntryHashV2($entry)` demi backward compatibility terhadap skrip pemanggil terdahulu.
3. **Menambahkan `computeEntryHashV3(array $entry): string`**:
   - Mengimplementasikan kalkulasi kanonikal dengan `version = 3` dan `hash('sha3-512', $encoded)`.
4. **Memperbarui `logEvent(...)`**:
   - Entri baru diinisialisasi dengan `hash_version = 3`.
   - Menghitung `previous_hash`: jika database kosong, gunakan `str_repeat('0', 128)`; jika ada log sebelumnya, gunakan `current_hash` dari log terakhir tersebut.
   - Menghitung `current_hash` menggunakan `computeEntryHashV3()`.
5. **Memperbarui `verifyChain()`**:
   - Menerapkan aturan genesis ketat (64 nol untuk V1/V2, 128 nol untuk V3 instalasi baru).
   - Menghitung ulang hash secara dinamis berdasarkan versi masing-masing entri.
   - Menghitung statistik rincian: `totalRecords`, `v3Records`, `v2Records`, `legacyRecords`, `genesisHash`, `headHash`, dan `isValid`.

### B. `backend_php/db/Database.php`
1. **Memperbarui `seed()`**:
   - Pada inisialisasi basis data baru, catatan genesis `SYSTEM_INIT` dibuat langsung menggunakan standar V3:
     - `previous_hash = str_repeat('0', 128)`
     - `hash_version = 3`
     - `payload['version'] = 3`
     - `current_hash = hash('sha3-512', $encoded)`

### C. `backend_php/tests/security_stage2.py`
1. **Penyesuaian Role User Pengujian**:
   - Mengubah role user pengujian di fixture menjadi `'role' => 'admin'` agar memiliki wewenang untuk mengeksekusi endpoint verifikasi audit `/api/audit/verify`.
2. **Penyesuaian Fixture Legacy**:
   - Menetapkan `$e['previous_hash'] = str_repeat('0', 64)` secara eksplisit pada pengujian mock migrasi legacy V1 agar memenuhi aturan genesis historis V1 yang ketat.

### D. `backend_php/tests/audit_sha3_compat_test.php`
- File pengujian baru yang menguji 12 skenario kompabilitas, transisi, penolakan genesis tidak valid, deteksi manipulasi, dan audit anchor pada runtime terisolasi.

---

## 8. Dampak Database

### A. Analisis Skema SQLite
Tabel `audit_logs` pada `backend_php/db/schema.sql` memiliki definisi:
```sql
CREATE TABLE IF NOT EXISTS audit_logs (
    id TEXT PRIMARY KEY,
    sequence_number INTEGER NOT NULL,
    timestamp TEXT NOT NULL,
    action_type TEXT NOT NULL,
    user_id TEXT,
    file_id TEXT,
    status TEXT NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    previous_hash TEXT NOT NULL,
    current_hash TEXT NOT NULL,
    payload TEXT NOT NULL
);
```

### B. Hasil Evaluasi Penyimpanan
1. **Tipe Kolom `TEXT` pada SQLite**:
   SQLite menggunakan *dynamic typing* di mana kolom bertipe `TEXT` tidak memiliki batasan panjang karakter statis (berbeda dengan `VARCHAR(64)` pada DBMS lain). Oleh karena itu, digest SHA3-512 sepanjang 128 karakter heksadesimal dapat langsung disimpan pada kolom `previous_hash` dan `current_hash` tanpa perubahan DDL (`ALTER TABLE`).
2. **Persistensi `hash_version`**:
   Informasi versi tersimpan di dalam JSON string pada kolom `payload`. Saat dibaca melalui `Database::load()` atau query SQLite, JSON tersebut didekode kembali secara utuh menjadi array asosiatif sehingga `$entry['hash_version']` terbaca secara persisten.

---

## 9. Pengujian Beserta Hasil Aktual

Pengujian komprehensif dieksekusi menggunakan test suite `backend_php/tests/audit_sha3_compat_test.php` pada lingkungan PHP 8.x:

```text
========================================================
  SECURE VAULT AUDIT HASH-CHAIN (SHA3-512) COMPAT TEST
========================================================

  [PASS] Preflight: PHP native sha3-512 algorithm support

--- Skenario 1: Rantai Murni V1 ---
  [PASS] V1 hash is 64 hex characters
  [PASS] 1. Rantai murni V1 terverifikasi valid (legacyRecords: 2)

--- Skenario 2: Rantai Murni V2 ---
  [PASS] V2 hash is 64 hex characters (SHA-256)
  [PASS] 2. Rantai murni V2 terverifikasi valid (v2Records: 2)

--- Skenario 3: Genesis Baru V3 ---
  [PASS] V3 hash length is 128 hex characters (SHA3-512)
  [PASS] V3 hash format is valid hex 128
  [PASS] 3. Genesis baru V3 terverifikasi valid

--- Skenario 4: Transisi V2 ke V3 ---
  [PASS] Transition previous_hash preserves V2 64-hex format
  [PASS] Transition current_hash produces V3 128-hex format
  [PASS] 4. Transisi V2 -> V3 terverifikasi valid tanpa menghitung ulang data lama

--- Skenario 5: Rantai V3 Berkelanjutan ---
  [PASS] New logEvent gets sequence 4
  [PASS] New logEvent produces hash_version = 3
  [PASS] Continuous V3 previous_hash is 128 hex
  [PASS] Continuous V3 current_hash is 128 hex
  [PASS] 5. Rantai V3 berkelanjutan via logEvent() terverifikasi valid

--- Skenario 6: Penolakan Genesis V3 yang Salah ---
  [PASS] 6. Penolakan genesis V3 yang salah memakai 64 nol

--- Skenario 7: Penolakan Genesis V2 yang Salah ---
  [PASS] 7. Penolakan genesis V2 yang salah memakai 128 nol

--- Skenario 8: Deteksi Manipulasi Entri Historis (V1/V2) ---
  [PASS] Pre-tamper baseline valid
  [PASS] 8. Deteksi manipulasi metadata pada entri historis V2 berhasil

--- Skenario 9: Deteksi Manipulasi Entri V3 ---
  [PASS] 9. Deteksi manipulasi payload pada entri V3 berhasil

--- Skenario 10: Deteksi Manipulasi Titik Transisi ---
  [PASS] 10. Deteksi pemutusan rantai pada titik transisi V2->V3 berhasil

--- Skenario 11 & 12: Audit Anchor Aktual (V2 & V3) ---
  [PASS] 11a. Ekspor anchor V2 via skrip aktual berhasil (exit 0)
  [PASS] 11b. Verifikasi anchor V2 via skrip aktual berhasil (exit 0)
  [PASS] Full 4-record chain valid
  [PASS] 11c. Checkpoint V2 lama tetap valid pada rantai yang bertambah V3
  [PASS] 12a. Ekspor anchor V3 via skrip aktual berhasil (exit 0)
  [PASS] 12b. Head hash pada dokumen anchor V3 memiliki panjang 128 karakter (SHA3-512)
  [PASS] 12c. Verifikasi anchor V3 via skrip aktual berhasil (exit 0)

========================================================
  RINGKASAN HASIL TEST: 29 PASSED, 0 FAILED
========================================================
```

### Hasil Pengujian Regresi Keseluruhan:
1. `backend_php/tests/audit_sha3_compat_test.php` $\rightarrow$ **PASS (29/29 assertions)**
2. `backend_php/tests/security_stage2.py` $\rightarrow$ **PASS (Exit Code 0)**
3. `backend_php/tests/onboarding_integration.mjs` $\rightarrow$ **PASS (Exit Code 0)**
4. `backend_php/tests/iteration5_sqlite_integration_test.py` $\rightarrow$ **PASS (Exit Code 0)**
5. `backend_php/tests/mfa_challenge_lock_test.php` $\rightarrow$ **PASS (Exit Code 0)**
6. `backend_php/tests/security_stage1.py` $\rightarrow$ **PASS (Exit Code 0)** (Seluruh 7 asersi keamanan lulus dan koneksi SQLite ditutup secara deterministik via `contextlib.closing()` sehingga cleanup direktori temporer pada Windows berjalan bersih tanpa `WinError 32`).

---

## 10. Pengujian Audit Anchor

Skrip audit anchor (`backend_php/scripts/export_audit_anchor.php` dan `backend_php/scripts/verify_audit_anchor.php`) digunakan untuk mengekspor state hash terakhir rantai audit (*head hash*) ke dalam berkas tanda tangan aman berbasis HMAC-SHA256 (`anchor.json`). Pengujian dieksekusi secara nyata menggunakan pemanggilan skrip CLI aktual (`proc_open`) pada basis data terisolasi.

### Hasil Analisis dan Pengujian:
1. **Tidak Ada Ketergantungan Panjang Hash**:
   Kedua skrip membaca `$res['headHash']` dan memverifikasi integritasnya melalui `Audit::verifyChain()`. Tidak ditemukan asumsi `strlen($head) === 64`.
2. **Anchor V2 Lama Tetap Valid pada Rantai Diperluas**:
   Anchor yang dibuat pada masa V2 (berisi `head_hash` 64 karakter heksadesimal) tetap valid diverifikasi menggunakan `verify_audit_anchor.php` bahkan setelah rantai bertambah entri V3 baru, karena sub-rantai historisnya tetap terbukti utuh dan cocok dengan prefix saat ini.
3. **Anchor V3 Baru**:
   Anchor baru berhasil diekspor menggunakan `export_audit_anchor.php` dengan `head_hash` 128 karakter heksadesimal (SHA3-512), dan lulus verifikasi `verify_audit_anchor.php` dengan integritas HMAC-SHA256 penuh.

---

## 11. Pemeriksaan Keamanan dan Regresi

### A. Ketahanan Deteksi Manipulasi (*Tamper Evidence*)
Sistem secara akurat menolak validasi jika:
1. Mengubah `user_agent`, `ip_address`, atau `details` pada record V2 historis $\rightarrow$ Terdeteksi (`isValid = false`).
2. Mengubah data pada record V3 baru $\rightarrow$ Terdeteksi (`isValid = false`).
3. Mengubah hash transisi penghubung V2 ke V3 $\rightarrow$ Terdeteksi (`isValid = false`).
4. Memotong atau menyisipkan baris di tengah rantai $\rightarrow$ Terdeteksi (`isValid = false`).

### B. Batasan Ruang Lingkup Kriptografi (Verifikasi Non-Terdampak)
Dipastikan secara ketat bahwa perubahan ini **HANYA** berlaku pada hash-chain Jejak Audit. Algoritma kriptografi lainnya tetap dipertahankan tanpa perubahan:
- **Zero-Knowledge Encryption**: AES-256-GCM (client) & Master Passphrase (Argon2id/PBKDF2) tetap tidak tersentuh.
- **Key Wrapping**: AES-KW (`wrappedDek`) tetap tidak tersentuh.
- **Integritas Chunk Berkas**: SHA-256 per chunk tetap digunakan untuk validasi transmisi berkas.
- **Token Aktivasi Registrasi**: HMAC-SHA256 tetap digunakan.
- **Token Otentikasi Sesi**: JWT HS256 tetap digunakan.
- **Penyimpanan Password Pengguna**: Argon2id tetap digunakan.
- **Enkripsi MFA Secret**: AES-256-GCM dengan `MFA_ENCRYPTION_KEY` tetap digunakan.

---

## 12. Kesimpulan dan Keterbatasan

### Kesimpulan
Implementasi **Perbaikan 1 (SHA3-512 pada Hash-Chain Jejak Audit)** telah selesai dilaksanakan dengan sempurna:
- Algoritma hashing audit baru telah beralih ke SHA3-512 (128 heksadesimal, `hash_version = 3`).
- Kompatibilitas mundur terhadap rekaman audit V1 dan V2 terbukti terjaga 100%.
- Transisi V2 $\rightarrow$ V3 dan genesis V3 instalasi baru berfungsi sesuai spesifikasi teknis.
- Seluruh rangkaian pengujian unit dan regresi sistem berhasil lulus (*PASS*).

### Keterbatasan dan Langkah Berikutnya
Sesuai batasan instruksi pengerjaan:
1. Perbaikan kolom Pengguna/IP pada Jejak Audit (**Perbaikan 2**) **belum dikerjakan** pada tahap ini.
2. Penghilangan kolom Rantai Hash pada antarmuka frontend (**Perbaikan 3**) **belum dikerjakan** pada tahap ini.
3. Tidak ada modifikasi kode pada antarmuka frontend maupun perubahan skema database SQLite yang tidak diperlukan.

Tahap selanjutnya menunggu persetujuan dan instruksi resmi dari pengguna untuk melanjutkan ke Perbaikan berikutnya.
