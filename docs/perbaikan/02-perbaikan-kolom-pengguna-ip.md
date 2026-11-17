# DOKUMENTASI TEKNIS PERBAIKAN 2: PERBAIKAN TAMPILAN KOLOM PENGGUNA/IP PADA JEJAK AUDIT SECURE VAULT

---

## 1. Latar Belakang Perubahan

Pada antarmuka Konsol Administrator Secure Vault, halaman **Jejak Audit** (*Audit Trail*) menyajikan tabel ringkasan aktivitas sistem yang mencakup nomor urut (*sequence*), waktu stempel (*timestamp*), jenis aksi (*action type*), pengguna dan alamat IP sumber, status keberhasilan, serta rantai *cryptographic hash*.

Pada implementasi awal, kolom keempat tabel tersebut menampilkan identitas pengguna (`user_id` / username) dan alamat IP (`ip_address`) secara bertumpuk (*stacked*) di dalam satu sel yang sama. Untuk meningkatkan privasi tampilan, menyederhanakan visualisasi konsol, dan memfokuskan pemantauan jaringan pada alamat IP asal, sistem disesuaikan agar kolom tersebut secara eksklusif hanya menampilkan alamat IP sumber aktivitas.

---

## 2. Kondisi Tampilan Sebelum dan Sesudah

### A. Kondisi Sebelum Perbaikan
- **Label Header Kolom**: `Pengguna / IP`
- **Penyajian Data Sel**: Menampilkan `user_id` pada baris atas dan `ip_address` pada baris bawah dalam satu sel tabel.
- **Markup Sebelum**:
  ```html
  <th scope="col">Pengguna / IP</th>
  ...
  <td>
    <span class="audit-user-id">${esc(log.user_id || '-')}</span>
    <small class="table-subtext">${esc(log.ip_address || '-')}</small>
  </td>
  ```
- **Ilustrasi Visual Sebelum**:
  ```text
  +-------------------------------------------------------+
  |                    Pengguna / IP                      |
  +-------------------------------------------------------+
  | admin                                                 |  <- Username
  | 192.168.1.10                                          |  <- Alamat IP
  +-------------------------------------------------------+
  ```

### B. Kondisi Sesudah Perbaikan
- **Label Header Kolom**: `Alamat IP`
- **Penyajian Data Sel**: Hanya menampilkan `ip_address` dalam format font monospace (`mono`). Identitas username/user_id tidak lagi ditampilkan pada kolom tersebut.
- **Penanganan Fallback**: Jika nilai alamat IP adalah `null`, `undefined`, atau string kosong (`""`), sistem secara eksplisit menampilkan teks `Tidak tersedia`.
- **Markup Sesudah**:
  ```html
  <th scope="col">Alamat IP</th>
  ...
  <td>
    <span class="audit-user-id mono">${esc(log.ip_address || 'Tidak tersedia')}</span>
  </td>
  ```
- **Ilustrasi Visual Sesudah**:
  ```text
  +-------------------------------------------------------+
  |                       Alamat IP                       |
  +-------------------------------------------------------+
  | 192.168.1.10                                          |  <- IPv4
  | 2001:0db8:85a3:0000:0000:8a2e:0370:7334              |  <- IPv6
  | Tidak tersedia                                        |  <- Null / Kosong
  +-------------------------------------------------------+
  ```

---

## 3. Tujuan Perbaikan

1. **Eksklusivitas Alamat IP**: Menghilangkan penyajian nama pengguna/username dari kolom tabel Jejak Audit dan hanya menampilkan alamat IP aktivitas.
2. **Penyesuaian Label Header**: Memperbarui label header dari `Pengguna / IP` menjadi `Alamat IP`.
3. **Penyajian Fallback yang Jelas**: Menampilkan representasi eksplisit `Tidak tersedia` apabila alamat IP tidak tercatat atau bernilai null/kosong (tanpa mengarang IP palsu).
4. **Pencegahan XSS**: Memastikan alamat IP disanitasi menggunakan fungsi `esc(...)` bawaan untuk mencegah serangan *Cross-Site Scripting*.
5. **Preservasi Data Backend & Kriptografi**: Memastikan field `user_id` dan `ip_address` pada database SQLite dan hash-chain SHA3-512 V3 tetap tersimpan utuh dan tidak terpengaruh oleh perubahan visual ini.

---

## 4. File yang Dimodifikasi dan File yang Tidak Dimodifikasi

### A. File yang Dimodifikasi
- [`frontend/js/app.js`](file:///C:/Users/AXIOO/Documents/PKL/Secure-Vault/secure-vault-main/secure-vault-main/frontend/js/app.js) (Baris 460 pada fungsi `auditTemplate()`).

### B. File Backup yang Dibuat
- [`frontend/js/app.js.bak`](file:///C:/Users/AXIOO/Documents/PKL/Secure-Vault/secure-vault-main/secure-vault-main/frontend/js/app.js.bak).

### C. Komponen `frontend/src/components/AuditLogViewer.tsx` (Tidak Dimodifikasi)
- **Status**: **TIDAK DIMODIFIKASI**.
- **Alasan Teknis**: Berdasarkan file startup launcher [`start_all_php.bat`](file:///C:/Users/AXIOO/Documents/PKL/Secure-Vault/secure-vault-main/secure-vault-main/start_all_php.bat) baris 42 dan 48, runtime aktif Secure Vault secara eksklusif menggunakan **Vanilla HTML + CSS + JavaScript** (`frontend/index.html` dan `frontend/js/app.js`) yang dilayani oleh `php -S 127.0.0.1:5173 router.php`. Direktori `frontend/src` merupakan artefak TypeScript React dari iterasi pengujian awal yang tidak dikompilasi atau digunakan oleh runtime produksi ("Tidak diperlukan Node.js, npm, React, TypeScript, atau Vite"). Sesuai prinsip perubahan minimum non-invasif, file tersebut dibiarkan utuh.

---

## 5. Penjelasan Perubahan Kode

Pada file [`frontend/js/app.js`](file:///C:/Users/AXIOO/Documents/PKL/Secure-Vault/secure-vault-main/secure-vault-main/frontend/js/app.js) baris 460:
1. Mengubah elemen header `<th>`:
   - Semula: `<th scope="col">Pengguna / IP</th>`
   - Menjadi: `<th scope="col">Alamat IP</th>`
2. Mengubah sel data baris `<td>`:
   - Semula:
     ```javascript
     <td><span class="audit-user-id">${esc(log.user_id || '-')}</span><small class="table-subtext">${esc(log.ip_address || '-')}</small></td>
     ```
   - Menjadi:
     ```javascript
     <td><span class="audit-user-id mono">${esc(log.ip_address || 'Tidak tersedia')}</span></td>
     ```
   - Elemen `<span class="audit-user-id">` yang menampilkan `log.user_id` dihapus.
   - Tag `<small class="table-subtext">` dihapus, digantikan oleh elemen tunggal dengan class `.mono` (`font-family: var(--font-mono)`) untuk keterbacaan alamat IP yang optimal.
   - Menggunakan fallback `'Tidak tersedia'` bila `log.ip_address` tidak terdefinisi atau string kosong.

---

## 6. Alasan Backend dan Database Tidak Diubah

1. **Ketersediaan Field Mandiri**:
   Endpoint API `GET /api/audit` via `AuditRoutes::list()` telah mengembalikan array log lengkap dari SQLite dengan properti `log.ip_address` dan `log.user_id` sebagai dua entitas terpisah. Frontend dapat langsung memilih field mana yang dirender tanpa perlu modifikasi backend.
2. **Kebutuhan Forensik dan Integritas Audit**:
   Informasi identitas pengguna (`user_id`) wajib tetap tersimpan di basis data untuk penelusuran insiden keamanan, audit kepatuhan, serta tanggung gugat (*non-repudiation*).
3. **Integritas Hash-Chain SHA3-512 V3**:
   Metode hashing kanonikal `computeEntryHashV3()` mengikat field `user_id` dan `ip_address` ke dalam digest 128 karakter heksadesimal. Mengubah payload backend atau menghapus `user_id` akan memutus dan merusak integritas hash rantai audit.
4. **Prinsip Least Invasive**:
   Permintaan ini murni merupakan penyesuaian visual (*presentation layer*), sehingga modifikasi minimum pada template rendering frontend adalah pendekatan paling aman dan elegan.

---

## 7. Hasil Pengujian Aktual

Dibuat test suite verifikasi khusus pada [`backend_php/tests/audit_ip_column_test.mjs`](file:///C:/Users/AXIOO/Documents/PKL/Secure-Vault/secure-vault-main/secure-vault-main/backend_php/tests/audit_ip_column_test.mjs) yang mengeksekusi fungsi rendering `auditTemplate()` secara nyata terhadap berbagai skenario:

```
========================================================
  SECURE VAULT AUDIT IP COLUMN VERIFICATION TEST
========================================================

  [PASS] 1. Header tabel Jejak Audit menggunakan label "Alamat IP"
  [PASS] 2. Header lama "Pengguna / IP" sudah tidak ada lagi
  [PASS] 3. Rendering sel menggunakan esc(log.ip_address || 'Tidak tersedia')
  [PASS] 4. Format tumpuk username dan IP lama sudah dihapus
  [PASS] 5. Tabel berhasil merender elemen <tbody>
  [PASS] 6. Seluruh 4 baris log berhasil dirender (ditemukan: 4)
  [PASS] 7. IPv4 "192.168.1.10" tampil pada kolom Alamat IP
  [PASS] 8. Username "super_admin_alice" TIDAK tampil pada kolom Alamat IP
  [PASS] 9. Styling monospace (mono) terpasang pada sel Alamat IP
  [PASS] 10. IPv6 "2001:0db8:85a3:..." tampil pada kolom Alamat IP
  [PASS] 11. Username "bob_operator" TIDAK tampil pada kolom Alamat IP
  [PASS] 12. IP null menampilkan fallback "Tidak tersedia"
  [PASS] 13. Username "charlie_system" TIDAK tampil pada kolom Alamat IP
  [PASS] 14. IP string kosong ("") menampilkan fallback "Tidak tersedia"
  [PASS] 15. Username "david_user" TIDAK tampil pada kolom Alamat IP
  [PASS] 16. Karakter berbahaya pada alamat IP disanitasi secara aman (XSS protected)

========================================================
  RINGKASAN HASIL TEST: 16 PASSED, 0 FAILED
========================================================
```

---

## 8. Hasil Pemeriksaan Regresi Keseluruhan

Seluruh test suite regresi yang telah ada dijalankan kembali pada lingkungan terisolasi untuk memastikan tidak ada dampak samping:

| No | Test Suite | Target Verifikasi | Hasil | Keterangan |
| :---: | :--- | :--- | :---: | :--- |
| 1 | `backend_php/tests/audit_ip_column_test.mjs` | Rendering Alamat IP, Fallback, Monospace, XSS | **PASS** | 16/16 assertions passed |
| 2 | `backend_php/tests/audit_sha3_compat_test.php` | Integritas SHA3-512 V3, transisi rantai, anchor | **PASS** | 29/29 assertions passed |
| 3 | `backend_php/tests/frontend_security_static.py` | Guardrails CSP, no inline style/event, cache-buster >= V9 | **PASS** | Exit code 0 |
| 4 | `backend_php/tests/security_stage1.py` | Keamanan otentikasi, TOTP, kontrol akses | **PASS** | Exit code 0, clean teardown |
| 5 | `backend_php/tests/security_stage2.py` | Kuota, integritas chunk, tamper detection | **PASS** | Exit code 0 |
| 6 | `backend_php/tests/onboarding_integration.mjs` | Registrasi admin, aktivasi, verifikasi email | **PASS** | Exit code 0 |
| 7 | `backend_php/tests/iteration5_sqlite_integration_test.py` | Skema SQLite, relasi, rollback transaksi | **PASS** | Exit code 0 |
| 8 | `backend_php/tests/mfa_challenge_lock_test.php` | Serialisasi dan pencegahan replay MFA | **PASS** | Exit code 0 |

---

## 9. Kesimpulan dan Keterbatasan

### Kesimpulan
Implementasi **Perbaikan 2 (Kolom Pengguna/IP pada Jejak Audit)** telah berhasil diselesaikan secara sempurna:
- Header tabel kini bertuliskan **Alamat IP**.
- Kolom tabel hanya menyajikan alamat IP (IPv4 maupun IPv6) dengan font monospace.
- Username tidak lagi muncul di kolom tersebut.
- Record tanpa IP menyajikan representasi fallback **`Tidak tersedia`**.
- Database, backend API, dan algoritma hash-chain SHA3-512 V3 tetap utuh dan valid 100%.

### Keterbatasan dan Langkah Berikutnya
Sesuai batasan instruksi kerja:
- Kolom **Rantai hash** masih ditampilkan pada tabel audit saat ini (**Perbaikan 3** belum dikerjakan).
- Pengerjaan Perbaikan 3 akan menunggu persetujuan dan instruksi resmi selanjutnya dari pengguna.
