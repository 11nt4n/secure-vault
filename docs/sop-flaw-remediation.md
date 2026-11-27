# Standar Operasional Prosedur (SOP) Flaw Remediation Secure Vault

---

## 1. Identitas dan Tujuan Dokumen

| Atribut Dokumen | Keterangan |
| :--- | :--- |
| **Nama Dokumen** | Standar Operasional Prosedur (SOP) Flaw Remediation Secure Vault |
| **Kode / Lokasi** | `docs/sop-flaw-remediation.md` |
| **Acuan Sistem** | Secure Vault (PHP 8 REST API + SQLite `pdo_sqlite` + Frontend ES Modules *Zero-Knowledge*) |
| **Referensi Desain** | ISO/IEC 15408 dan ISO/IEC 18045 (referensi desain keamanan; bukan klaim sertifikasi) |

**Tujuan dokumen ini** adalah menetapkan prosedur baku dan terkendali untuk menangani kelemahan keamanan (*security flaws / vulnerabilities*) pada **Secure Vault**—mulai dari identifikasi, pelaporan, validasi, penilaian risiko, analisis akar penyebab, perbaikan, pengujian, rilis, hingga penutupan temuan atau pengecualian risiko.

---

## 2. Ruang Lingkup

SOP ini mencakup seluruh komponen kode, konfigurasi, dan aset operasional Secure Vault:
- **Backend REST API (`backend_php/`):** autentikasi, otorisasi, JWT (`Jwt.php`), manajemen sesi (`AuthMiddleware.php`), password hashing (`Database::hashPassword()`), MFA/TOTP (`Totp.php`), enkripsi/penyimpanan berkas (`FileRoutes.php`), basis data SQLite & `PersistentStorage.php`, audit log & Audit Anchor (`Audit.php`, `export_audit_anchor.php`), *rate limiting*, serta validasi input dan header keamanan (`Response.php`).
- **Frontend (`frontend/`):** klien API (`api.js`), utilitas kriptografi sisi klien (`crypto.js`, `crypto-worker.js`), antarmuka (`app.js`), aset lokal (`argon2-bundled.min.js`), serta header keamanan (`router.php`).
- **Komponen Pihak Ketiga & Konfigurasi:** runtime PHP 8, ekstensi `pdo_sqlite`/`openssl`, `argon2-bundled.min.js`, dan artefak lama (`frontend/package.json`).

> [!NOTE]
> Berdasarkan pemeriksaan repository aktual, Secure Vault **belum memiliki** *pipeline* CI/CD (`.github/workflows`), SAST/DAST otomatis, *vulnerability scanner* terjadwal, pemantauan *dependency* otomatis, maupun program *bug bounty*. Seluruh proses identifikasi, perbaikan, dan pengujian dijalankan **secara manual** oleh tim pengembang dan administrator menggunakan skrip pengujian lokal serta tinjauan kode.

---

## 3. Definisi dan Istilah

Untuk ketepatan penanganan, tim wajib membedakan empat kategori berikut:
- **Kelemahan Keamanan (*Security Flaw / Vulnerability*):** Cacat desain atau implementasi kode yang berpotensi dieksploitasi untuk melanggar kerahasiaan, integritas, ketersediaan, otorisasi, atau autentikasi (mis. celah XSS, SQL injection, *bypass* autentikasi/MFA, atau kesalahan pengelolaan kunci).
- **Bug Fungsional:** Cacat logika atau antarmuka yang mengganggu fungsi aplikasi tanpa menimbulkan dampak keamanan langsung.
- **Kesalahan Konfigurasi (*Misconfiguration*):** Kelemahan akibat pengaturan lingkungan yang tidak aman (mis. `JWT_SECRET` lemah, `SECURE_VAULT_CORS_ORIGINS` terlalu longgar, atau `PRIVATE_DIR` di dalam web root).
- **Risiko Operasional:** Keterbatasan inheren sistem atau proses manual (mis. tidak ada *atomic snapshot* lintas SQLite dan filesystem, atau tidak adanya penyimpanan *Audit Anchor* eksternal otomatis).

---

## 4. Peran dan Tanggung Jawab

| Peran | Tanggung Jawab dalam Siklus Flaw Remediation |
| :--- | :--- |
| **Pelapor Temuan** | Melaporkan indikasi kelemahan melalui saluran internal resmi tanpa mengeksploitasi sistem produksi dan tanpa menyertakan secret/data pribadi. |
| **Tim Pengembang / Maintainer** | Memvalidasi dan mereproduksi temuan di lingkungan terisolasi, menganalisis akar penyebab, merancang perbaikan, menulis/menjalankan uji regresi, serta mendokumentasikan perubahan. |
| **Penelaah Keamanan (*Reviewer*)** | Meninjau desain perbaikan, memverifikasi hasil pengujian kontrol keamanan, dan memeriksa dampak kompatibilitas sebelum persetujuan rilis. |
| **Administrator Sistem** | Menerapkan pembaruan rilis di lingkungan operasional, membuat backup sebelum perubahan (`backup_sqlite.php` + backup manual storage/secret), dan menjalankan `production_readiness.php`. |
| **Penanggung Jawab Risiko Organisasi** | Menetapkan prioritas/SLA organisasi serta menyetujui atau menolak permohonan pengecualian/penerimaan risiko (*risk acceptance*). |

---

## 5. Sumber Identifikasi Kelemahan

### 5.1 Sumber yang Tersedia Saat Ini
- **Pengujian keamanan dan statis bawaan (`backend_php/tests/` & `frontend/diagnostics/`):**
  - Pengujian keamanan API & statis: `security_stage1.py`, `security_stage2.py`, `frontend_security_static.py`, `iteration4_static_test.py`, `iteration5_relational_static_test.py`.
  - Pengujian integrasi & kriptografi: `audit_sha3_compat_test.php`, `audit_ip_column_test.mjs`, `audit_table_columns_test.mjs`, `mfa_challenge_lock_test.php`, `persistent_storage_recovery_test.php`, `legacy_structure_simulation_test.php`, `relational_migration_integration.php`, `iteration5_sqlite_integration_test.py`, `onboarding_integration.mjs`, `folder_api_integration.mjs`, `smtp_config_integration.mjs`, `crypto_worker_node_test.mjs`, serta `frontend/diagnostics/crypto-rewrap-test.mjs`.
  - Pemeriksaan kesiapan & sintaks: `production_readiness.php` dan `php -l`.
- **Tinjauan kode (*code review*) manual** dan temuan dari **Jejak Audit** / **pengujian fungsional** / **laporan pengguna atau administrator**.

### 5.2 Metode yang Direkomendasikan untuk Masa Depan *(Belum Tersedia)*
- Integrasi CI/CD untuk menjalankan seluruh suite `backend_php/tests/` secara otomatis pada setiap *pull request*.
- Pemindaian SAST/DAST berkala dan pemantauan CVE untuk runtime PHP, SQLite, serta `argon2-bundled.min.js`.

---

## 6. Mekanisme Pelaporan dan Pencatatan Temuan

1. Setiap temuan dicatat menggunakan **Formulir Pencatatan Temuan** (Bagian 17) dengan ID unik (mis. `FLAW-YYYY-NNN`).
2. Saluran pelaporan internal: `[Diisi oleh Organisasi]`.
3. **Aturan Kerahasiaan:** Pelapor dan pengembang **dilarang** mencantumkan *password*, *JWT*, `JWT_SECRET`, `MFA_ENCRYPTION_KEY`, kredensial SMTP, `AUDIT_ANCHOR_HMAC_KEY`, atau data pribadi pengguna ke dalam laporan maupun commit Git publik sebelum perbaikan dirilis.

---

## 7. Validasi dan Reproduksi Temuan

Sebelum diklasifikasikan sebagai temuan aktif, tim pengembang wajib:
1. **Memastikan kondisi reproduksi** di lingkungan terisolasi/lokal (bukan sistem produksi), menggunakan data uji sementara (seperti pola pada `persistent_storage_recovery_test.php` atau `audit_sha3_compat_test.php`).
2. **Memverifikasi relevansi terhadap konfigurasi aktual:** Memastikan apakah kelemahan terjadi pada kode aktif (mis. `frontend/js/app.js` + `backend_php/`) dan bukan pada artefak lama yang tidak aktif (seperti `frontend/src/` atau `backend_php/.env.example`).
3. **Membedakan kategori temuan** (kelemahan keamanan, bug fungsional, kesalahan konfigurasi, atau risiko operasional).

---

## 8. Klasifikasi dan Penilaian Risiko

| Tingkat Risiko | Kriteria Penilaian | Target Waktu Penyelesaian (*SLA*) |
| :--- | :--- | :--- |
| **Critical** | Mudah dieksploitasi tanpa autentikasi/otorisasi; berdampak langsung pada pembobolan brankas, pemalsuan sesi/MFA, eksekusi kode, atau manipulasi massal database/audit. | `[Diisi oleh Organisasi]` |
| **High** | Memerlukan autentikasi awal atau kondisi tertentu, namun berdampak besar pada kerahasiaan/integritas data pengguna atau eskalasi hak akses ke `admin`. | `[Diisi oleh Organisasi]` |
| **Medium** | Memerlukan kondisi khusus atau berdampak terbatas pada fungsi/informasi sekunder (mis. celah konfigurasi non-kritis atau *rate limit* parsial). | `[Diisi oleh Organisasi]` |
| **Low** | Dampak minimal, memerlukan prasyarat tinggi, atau bersifat *defense-in-depth* tanpa jalur eksploitasi langsung. | `[Diisi oleh Organisasi]` |

**Faktor penilaian yang wajib dipertimbangkan:**
1. Kemudahan eksploitasi (akses jaringan, butuh autentikasi atau tidak, kompleksitas serangan).
2. Dampak terhadap kerahasiaan, integritas, dan ketersediaan (termasuk arsitektur *Zero-Knowledge*).
3. Jumlah komponen atau pengguna terdampak.
4. Ketersediaan mitigasi sementara (mis. pembatasan CORS, penonaktifan akun, pembatasan firewall).
5. Kebutuhan operasional.

> [!NOTE]
> Apabila organisasi menggunakan skor **CVSS**, skor **wajib dihitung berdasarkan vektor CVSS yang dapat dipertanggungjawabkan** setelah temuan direproduksi. Jangan mencantumkan skor CVSS fiktif untuk temuan yang belum diuji.

---

## 9. Prioritas dan Penentuan Tindakan

- **Critical / High:** Ditangani sebagai prioritas utama; pertimbangkan mitigasi sementara segera (mis. pembatasan akses jaringan atau penonaktifan fitur/akun terdampak) sambil menyiapkan perbaikan kode.
- **Medium / Low:** Dijadwalkan pada siklus perbaikan berikutnya sesuai target organisasi.
- **Hubungan dengan SOP Penanganan Insiden:**
  - **SOP Flaw Remediation** berfokus pada perbaikan kelemahan sebelum atau tanpa indikasi eksploitasi.
  - **SOP Penanganan Insiden** ([docs/sop-penanganan-insiden-keamanan.md](sop-penanganan-insiden-keamanan.md)) berlaku apabila kelemahan **sudah dieksploitasi** atau menimbulkan indikasi kompromi. Dalam kondisi tersebut, kedua prosedur berjalan terkoordinasi (tangani insiden dan preservasi bukti terlebih dahulu sebelum mengubah kode/konfigurasi).

---

## 10. Analisis Akar Penyebab

Untuk setiap temuan valid, pengembang mendokumentasikan:
1. Lokasi pasti pada kode/konfigurasi (file, fungsi/metode, baris).
2. Penyebab teknis (mis. validasi input tidak lengkap, *race condition* tanpa `flock`, *fallback* tidak aman, atau kesalahan *prepared statement*).
3. Pola historis serupa yang perlu diperiksa ulang di modul lain (merujuk pada pola perbaikan sebelumnya di `SECURITY_FIXES.md` dan `docs/perbaikan/README.md`, seperti pemindahan AES-GCM ke Web Worker, pengetatan CSP, serialisasi lock tantangan MFA, migrasi relasional SQLite, dan penguatan SHA3-512 audit).

---

## 11. Prosedur Perbaikan Kelemahan

1. **Perancangan Perubahan:** Terapkan prinsip *least privilege*, *fail-closed*, *prepared statements* (PDO) untuk SQL, *output encoding* (`esc()` di `frontend/js/app.js`) untuk mencegah XSS, serta jaga *backward compatibility* terhadap data yang sudah ada (mis. kompatibilitas V1/V2/V3 pada `Audit::verifyChain()`).
2. **Tinjauan Perubahan (*Code Review*):** Pastikan tidak ada duplikasi logika, tidak ada secret *hardcoded*, dan perubahan tidak merusak isolasi web root (`config.php`) maupun arsitektur *Zero-Knowledge*.
3. **Pemeriksaan Dampak Data & Backup:**
   - **Jangan memodifikasi database produksi secara langsung** tanpa prosedur migrasi teruji.
   - Jika perbaikan menyentuh skema SQLite atau struktur penyimpanan, siapkan migrasi transaksional (seperti `Database::migrateRelationalSchema()`) dan wajibkan **backup penuh** sebelum penerapan sesuai [SOP Backup dan Restore](prosedur-backup-restore.md).
4. **Pencatatan via Git:** Kembangkan dan uji perbaikan pada branch/lingkungan kerja terkontrol sebelum di-commit ke repository resmi.

---

## 12. Pengujian dan Verifikasi Hasil Perbaikan

Perbaikan tidak boleh dianggap selesai sebelum seluruh tahap pengujian berikut lulus di lingkungan terisolasi (tanpa menyentuh database operasional aktif):

1. **Uji Reproduksi Pra-Perbaikan:** Buktikan skenario eksploitasi/kelemahan gagal ditahan sebelum perbaikan.
2. **Uji Verifikasi Pasca-Perbaikan:** Buktikan skenario yang sama kini ditolak atau ditangani dengan aman setelah perbaikan.
3. **Regression Testing & Fungsi Terkait:** Jalankan suite pengujian yang relevan di `backend_php/tests/` dan `frontend/diagnostics/`:
   ```bash
   # Contoh pemeriksaan sintaks dan suite keamanan yang tersedia di repository
   php backend_php/tests/mfa_challenge_lock_test.php
   php backend_php/tests/audit_sha3_compat_test.php
   php backend_php/tests/persistent_storage_recovery_test.php
   node --experimental-default-type=module frontend/diagnostics/crypto-rewrap-test.mjs
   python backend_php/tests/frontend_security_static.py
   python backend_php/tests/security_stage1.py
   python backend_php/tests/security_stage2.py
   ```
   *(Catatan: `security_stage1.py`, `security_stage2.py`, dan pengujian PDO memerlukan ekstensi PHP `pdo_sqlite` aktif).*
4. **Pencatatan Bukti Uji:** Catat nama skrip uji, jumlah *assertions*, dan status hasil uji (*PASS*) pada catatan temuan / dokumen perbaikan di `docs/perbaikan/`.
5. **Pengujian yang Belum Tersedia *(Rekomendasi)*:** Pengujian *fuzzing* otomatis, *headless browser E2E* penuh, dan pengujian penetrasi independen belum terotomasi di repository dan direkomendasikan sebagai gerbang rilis produksi.

---

## 13. Pengelolaan Perubahan dan Rilis

1. **Persetujuan Rilis:** Perubahan harus mendapat persetujuan dari `[Diisi oleh Organisasi — mis. Penelaah Keamanan / Lead Maintainer]`.
2. **Commit & Dokumentasi Perubahan:** Commit perubahan dengan pesan yang jelas serta perbarui dokumentasi teknis (mis. indeks `docs/perbaikan/README.md` atau panduan terkait bila perilaku operasional berubah).
3. **Penerapan & Verifikasi Pascarilis:**
   - Lakukan backup sebelum rilis (`backup_sqlite.php` + backup manual `STORAGE_DIR`, `secrets.php`, `smtp.json`).
   - Setelah pembaruan diterapkan, jalankan:
     ```bash
     php backend_php/scripts/production_readiness.php
     ```
     dan pastikan status `PASS`, layanan `/api/health` merespons `OK`, serta rantai audit tetap valid (`GET /api/audit/verify`).

---

## 14. Penutupan Temuan dan Dokumentasi

Suatu temuan hanya dapat diubah statusnya menjadi **Ditutup (*Closed*)** apabila memenuhi seluruh kriteria:
- Perbaikan kode/konfigurasi telah di-commit dan diverifikasi.
- Bukti pengujian pra-perbaikan, pasca-perbaikan, dan regresi telah tercatat.
- Verifikasi pascarilis di lingkungan target telah dinyatakan lulus (atau pengecualian risiko resmi telah disetujui).

---

## 15. Pengecualian atau Penerimaan Risiko

Apabila kelemahan belum dapat segera diperbaiki karena kendala teknis atau operasional:
1. Pengembang **tidak berwenang** menyetujui penerimaan risiko atas nama organisasi.
2. Ajukan dokumen pengecualian yang memuat:
   - **Justifikasi** mengapa perbaikan belum dapat dilakukan.
   - **Dampak dan risiko residual** yang tetap ada.
   - **Mitigasi sementara** (mis. pembatasan akses jaringan, penonaktifan fitur/akun, atau pemantauan manual lebih ketat).
   - **Persetujuan Penanggung Jawab Risiko:** `[Diisi oleh Organisasi]`.
   - **Tanggal evaluasi ulang** wajib ditetapkan agar temuan tidak terbengkalai permanen.

---

## 16. Evaluasi Berkala dan Perbaikan Berkelanjutan

Secara berkala (`[Diisi oleh Organisasi — mis. setiap kuartal / sebelum rilis besar]`):
- Tinjau daftar temuan terbuka, temuan berulang, serta status pengecualian risiko yang mendekati tanggal evaluasi ulang.
- Periksa pembaruan keamanan untuk PHP 8, SQLite, dan pustaka Argon2id WASM (`frontend/argon2-bundled.min.js`) secara manual mengingat belum adanya pemantauan *dependency* otomatis.

---

## 17. Checklist dan Formulir Pencatatan Temuan

### 17.1 Checklist Siklus Remediation
- [ ] Temuan dicatat dengan ID unik tanpa secret, token, password, atau data pribadi.
- [ ] Temuan direproduksi dan divalidasi di lingkungan terisolasi (bukan produksi).
- [ ] Risiko diklasifikasikan dan dicek apakah ada indikasi eksploitasi (jika ya, jalankan [SOP Penanganan Insiden](sop-penanganan-insiden-keamanan.md)).
- [ ] Akar penyebab dianalisis dan desain perbaikan ditinjau.
- [ ] Backup disiapkan sebelum penerapan jika menyentuh data/skema.
- [ ] Uji sebelum perbaikan, sesudah perbaikan, dan regresi dinyatakan `PASS`.
- [ ] Persetujuan rilis diperoleh, perubahan di-commit, dan `production_readiness.php` pascarilis berstatus `PASS`.
- [ ] Temuan ditutup dengan bukti verifikasi (atau dicatat sebagai pengecualian risiko resmi).

### 17.2 Formulir Pencatatan Temuan Kelemahan

| Kolom | Isian |
| :--- | :--- |
| **ID Temuan** | `FLAW-[YYYY]-[NNN]` |
| **Tanggal Ditemukan** | `[YYYY-MM-DD]` |
| **Kategori** | `[Kelemahan Keamanan / Bug Fungsional / Kesalahan Konfigurasi / Risiko Operasional]` |
| **Komponen Terdampak** | `[Nama file, fungsi, atau modul]` |
| **Versi / Commit Terdampak** | `[Hash commit / build stamp]` |
| **Tingkat Risiko** | `[Critical / High / Medium / Low — + vektor CVSS jika dihitung]` |
| **Pelapor & Penanggung Jawab** | `[Nama / Peran]` |
| **Deskripsi Kelemahan** | `[Penjelasan teknis singkat tanpa secret/data pribadi]` |
| **Bukti & Langkah Reproduksi** | `[Langkah reproduksi di lingkungan uji terisolasi]` |
| **Dampak Potensial** | `[Dampak terhadap kerahasiaan, integritas, ketersediaan]` |
| **Rencana Perbaikan & Mitigasi Sementara** | `[Ringkasan perbaikan & mitigasi bila ada]` |
| **Bukti Pengujian & Commit Perbaikan** | `[Daftar skrip uji PASS & hash commit]` |
| **Status Penanganan** | `[Terbuka / Dalam Perbaikan / Diuji / Ditutup / Pengecualian Risiko]` |

---

## 18. Referensi Teknis

- **Dokumentasi Resmi Secure Vault:**
  - [Panduan Instalasi dan Konfigurasi Aman](panduan-instalasi-konfigurasi-aman.md)
  - [Panduan Operasional](panduan-operasional.md)
  - [SOP Backup dan Restore](prosedur-backup-restore.md)
  - [Panduan Audit Log](panduan-audit-log.md)
  - [SOP Penanganan Insiden Keamanan](sop-penanganan-insiden-keamanan.md)
  - [Dokumentasi Perbaikan Sistem](perbaikan/README.md) dan [SECURITY_FIXES.md](../SECURITY_FIXES.md)
- **Pengujian & Skrip Validasi Repository:**
  - `backend_php/tests/` (`security_stage1.py`, `security_stage2.py`, `frontend_security_static.py`, `audit_sha3_compat_test.php`, `mfa_challenge_lock_test.php`, `persistent_storage_recovery_test.php`, `iteration5_sqlite_integration_test.py`, dll.)
  - `frontend/diagnostics/` (`crypto-rewrap-test.mjs`, `argon2-self-test.html`, `crypto-worker-self-test.html`)
  - `backend_php/scripts/production_readiness.php`
