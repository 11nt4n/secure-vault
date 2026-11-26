# Panduan Operasional Secure Vault

---

## 1. Pendahuluan

### 1.1 Tujuan Panduan
Dokumen ini disusun sebagai panduan operasional resmi bagi administrator dan pengguna dalam mengoperasikan aplikasi **Secure Vault** sesuai fitur dan alur kerja yang benar-benar tersedia pada implementasi aplikasi.

### 1.2 Sasaran Pengguna
- **Administrator:** Pengelola sistem yang bertugas membuat dan mengelola akun pengguna, mengatur kuota penyimpanan, meninjau ringkasan sistem pada **Konsol Admin**, memantau **Jejak Audit**, serta melakukan pemeriksaan operasional dasar.
- **Pengguna Biasa (*User*):** Pengguna terdaftar yang mengaktifkan akun, menyiapkan autentikasi dua faktor (TOTP), menginisialisasi/membuka brankas pribadi, serta mengelola folder dan berkas terenkripsi milik sendiri.

### 1.3 Gambaran Singkat Secure Vault
Secure Vault adalah aplikasi penyimpanan berkas berbasis arsitektur *Zero-Knowledge Client-Side Encryption* dengan *3-Layer Envelope Encryption*:
- Seluruh proses enkripsi dan dekripsi berkas, nama berkas, nama folder, serta label (*tag*) dilakukan di browser pengguna menggunakan Web Crypto API, Argon2id WebAssembly, dan Web Worker.
- Server (PHP 8 REST API + SQLite) hanya menyimpan *ciphertext*, kunci terbungkus (*wrapped keys*), metadata terenkripsi, profil akun, dan catatan jejak audit berantai (SHA3-512).
- Server tidak memiliki akses terhadap *passphrase* brankas maupun *plaintext* berkas pengguna.

---

## 2. Peran dan Hak Akses

Berdasarkan implementasi pada `backend_php/middleware/AuthMiddleware.php`, `backend_php/routes/AdminRoutes.php`, `backend_php/routes/AuditRoutes.php`, dan `frontend/js/app.js`, sistem membagi peran menjadi dua: **Administrator (`admin`)** dan **Pengguna Biasa (`user`)**.

| Kemampuan / Menu | Administrator (`admin`) | Pengguna Biasa (`user`) |
| :--- | :--- | :--- |
| Login & Verifikasi MFA (TOTP) | Ya | Ya |
| Mengelola Brankas Pribadi (**Beranda** & **Brankas Saya**) | Ya (khusus milik sendiri) | Ya (khusus milik sendiri) |
| Membuat Folder, Unggah Berkas/Folder, Pratinjau, Unduh, Edit Metadata, Hapus Berkas | Ya (khusus milik sendiri) | Ya (khusus milik sendiri) |
| Mengganti *Passphrase* Brankas (**Re-Wrap**) | Ya (khusus milik sendiri) | Ya (khusus milik sendiri) |
| Mengakses Menu **Konsol Admin** | Ya | Tidak (ditolak API dengan HTTP 403) |
| Membuat Akun Pengguna Baru & Mengirim Ulang Tautan Aktivasi | Ya | Tidak |
| Mengubah Kuota Penyimpanan Pengguna | Ya (hanya akun `user`) | Tidak |
| Menonaktifkan (*Cabut Sesi & Nonaktifkan*), Mengaktifkan Kembali, & Menghapus Akun | Ya (hanya akun `user`) | Tidak |
| Mengubah / Menghapus Akun Administrator Melalui Konsol Admin | Tidak (dilindungi; `"Akun terlindungi"`) | Tidak |
| Mengakses Menu **Jejak Audit** & Endpoint `/api/audit*` | Ya | Tidak (ditolak API dengan HTTP 403) |
| Melihat *Plaintext* atau Membuka Brankas Milik Pengguna Lain | Tidak (arsitektur *Zero-Knowledge*) | Tidak |

> [!NOTE]
> Pendaftaran mandiri (*self-registration*) melalui `/api/auth/register` dinonaktifkan secara permanen (`HTTP 403`). Akun pengguna baru hanya dapat dibuat oleh Administrator melalui **Konsol Admin**, sedangkan akun Administrator pertama dibuat melalui skrip CLI `init_admin.php` (atau promosi CLI `promote_admin.php`).

---

## 3. Login dan Logout

### 3.1 Prosedur Login (Administrator dan Pengguna)
1. Buka alamat aplikasi di browser (pada instalasi lokal default: `http://127.0.0.1:5173`).
2. Pada halaman **Selamat Datang di Secure Vault**, masukkan **Username** dan **Kata Sandi**.
3. Klik tombol **Masuk**.
4. Jika kredensial benar dan akun sudah aktif, sistem melanjutkan ke tahap verifikasi MFA:
   - Apabila MFA belum pernah diaktifkan, sistem menampilkan layar **Aktifkan Authenticator** (lihat Bagian 5).
   - Apabila MFA sudah aktif, sistem menampilkan layar **Verifikasi Dua Faktor (MFA)**. Masukkan kode 6 digit dari aplikasi authenticator pada kolom **Kode autentikator (6 digit)** lalu klik **Verifikasi & Masuk**.
5. Setelah verifikasi berhasil, pengguna masuk ke dashboard dan secara otomatis muncul dialog untuk menginisialisasi atau membuka kunci brankas.

### 3.2 Penanganan MFA saat Login
- Tantangan login MFA (*mfaToken*) berlaku selama **20 menit** (`1200` detik) dan hanya dapat digunakan satu kali.
- Sistem menerapkan perlindungan *anti-replay* TOTP (`mfa_last_counter`): kode 6 digit yang sudah pernah digunakan pada jendela waktu yang sama tidak dapat dipakai ulang.
- Jika waktu perangkat authenticator sedikit berbeda dari waktu server, pastikan sinkronisasi jam perangkat sudah aktif (toleransi bawaan TOTP ±1 periode 30 detik).

### 3.3 Prosedur Logout
1. Klik tombol **Logout** (ikon keluar berwarna merah) pada bilah atas kanan aplikasi.
2. Aplikasi memanggil endpoint `POST /api/auth/logout` untuk menaikkan `session_version` di server sehingga token JWT lama langsung tidak berlaku, kemudian menghapus token sesi dari `sessionStorage`, membersihkan kunci brankas di RAM, dan menghentikan Web Worker kriptografi.
3. Muncul notifikasi *"Logout berhasil. Kunci RAM & token sesi telah dimusnahkan."*

### 3.4 Penanganan Kegagalan Login
- **Username atau password salah:** Sistem menampilkan pesan *"Username atau password salah."* (pesan sengaja disamakan untuk mencegah enumerasi akun).
- **Pembatasan laju (*Rate Limit*):** Setelah **5 kali** percobaan login gagal atau **5 kali** percobaan MFA gagal dalam jendela waktu **15 menit** (`900` detik), sistem memblokir percobaan berikutnya sementara dengan pesan *"Terlalu banyak percobaan login. Coba kembali setelah 15 menit."* atau *"Terlalu banyak percobaan MFA. Coba kembali setelah 15 menit."*
- **Akun dinonaktifkan:** Jika akun dicabut/dinonaktifkan administrator, login ditolak dengan pesan *"Akun Anda dinonaktifkan oleh administrator."*
- **Sesi kedaluwarsa atau dicabut:** Token JWT berlaku **8 jam** (*sliding session* yang diperbarui pada setiap permintaan API terautentikasi). Bila sesi dicabut atau kedaluwarsa, aplikasi otomatis mengembalikan pengguna ke halaman login.

---

## 4. Pengelolaan Pengguna

Seluruh pengelolaan akun pengguna biasa dilakukan oleh **Administrator** melalui menu **Konsol Admin**.

### 4.1 Prosedur Undangan Pengguna oleh Administrator
1. Masuk sebagai Administrator dan buka menu **Konsol Admin** di sidebar kiri.
2. Pada bagian **Buat akun pengguna**, isi:
   - **Username** (3–64 karakter, hanya huruf, angka, `_`, `.`, atau `-`).
   - **Email pengguna** (alamat email valid).
3. Klik tombol **Buat akun**.
4. Sistem secara otomatis membuat tautan aktivasi sekali pakai (berlaku **24 jam**) dan mengirimkannya ke email pengguna melalui SMTP.
5. Jika pengiriman email SMTP gagal, pembuatan akun **dibatalkan** dan sistem menampilkan pesan error konfigurasi SMTP.

### 4.2 Pengaturan Password dan Verifikasi Email oleh Pengguna Baru
1. Pengguna membuka tautan aktivasi dari email (berformat `<APP_URL>/#activate=<userId>.<token>.<username>`).
2. Browser membuka halaman **Aktivasi Akun**.
3. Pengguna mengisi **Kata sandi baru** (minimal **12 karakter**) dan **Ulangi kata sandi baru**, lalu klik **Buat Kata Sandi & Aktifkan Akun**.
4. Setelah berhasil, pengguna diarahkan kembali ke halaman login dengan notifikasi *"Akun aktif. Masuk dengan kata sandi baru untuk melanjutkan ke OTP authenticator."*
5. Pada login pertama setelah aktivasi, pengguna wajib menyiapkan autentikasi TOTP (Bagian 5).

> [!NOTE]
> Aplikasi juga memiliki alur *onboarding* berbasis kode email 8 digit (`/api/auth/onboarding/verify-email` dan `/api/auth/onboarding/set-password`) untuk akun yang masih berstatus `onboarding_pending` saat mencoba login sebelum menyelesaikan aktivasi. Pada alur standar undangan admin, tautan aktivasi langsung memverifikasi email dan menetapkan kata sandi.

### 4.3 Status Akun Pengguna
Pada tabel **Daftar akun pengguna** di **Konsol Admin**, setiap akun memiliki salah satu status berikut:
- **MENUNGGU AKTIVASI:** Akun telah dibuat admin tetapi pengguna belum menyelesaikan aktivasi/pengaturan kata sandi melalui tautan email.
- **AKTIF:** Akun telah aktif dan dapat login menggunakan kata sandi serta MFA.
- **DINONAKTIFKAN:** Akun dinonaktifkan oleh administrator; seluruh sesi aktif dicabut dan pengguna tidak dapat login maupun mengakses API.

### 4.4 Tindakan Pengelolaan Lainnya oleh Administrator
Pada kolom **Tindakan** di tabel pengguna (khusus akun `user`; akun `admin` ditandai **Akun terlindungi**):
- **Kirim Ulang Aktivasi:** Tersedia jika akun berstatus **MENUNGGU AKTIVASI** dan email belum terverifikasi (jeda minimal 1 menit antar pengiriman). Mengirim tautan aktivasi baru dan membatalkan tautan lama.
- **Kuota:** Mengubah batas penyimpanan pengguna dalam satuan GB (antara 1 byte hingga 5 TiB, dan tidak boleh lebih kecil dari penyimpanan yang sudah terpakai).
- **Cabut Sesi & Nonaktifkan:** Memutus seluruh sesi aktif pengguna secara langsung dan mengubah status menjadi **DINONAKTIFKAN**. Akun dan berkas tetap tersimpan.
- **Aktifkan Akun:** Tersedia pada akun **DINONAKTIFKAN** (yang sudah selesai *onboarding*) untuk mengizinkan pengguna login kembali dengan sesi baru.
- **Hapus Akun:** Tersedia hanya setelah akun **DINONAKTIFKAN**. Admin wajib mengetik ulang **username** persis sebagai konfirmasi. Tindakan ini menghapus permanen akun, profil brankas, folder, berkas, dan *chunk* terenkripsi milik pengguna tersebut (catatan pada **Jejak Audit** tetap dipertahankan).

---

## 5. Pengaturan MFA

Setiap pengguna wajib mengaktifkan **Multi-Factor Authentication (MFA)** berbasis **TOTP** (6 digit, SHA-1, periode 30 detik) pada saat login pertama kali setelah akun aktif.

### 5.1 Aktivasi MFA dan Pemindaian QR Code
1. Login dengan username dan kata sandi pada halaman login.
2. Karena MFA belum aktif, sistem menampilkan halaman **Aktifkan Authenticator**.
3. Buka aplikasi authenticator di ponsel (misalnya Google Authenticator, Microsoft Authenticator, Authy, 1Password, atau aplikasi TOTP standar lainnya).
4. **Pindai QR Code** yang tampil di layar. QR Code dibuat **secara lokal di browser** tanpa mengirim secret ke layanan eksternal.
5. Jika kamera tidak dapat memindai QR Code, gunakan bagian **Kode setup manual**: klik **Salin kode** untuk menyalin secret, lalu tambahkan akun secara manual pada aplikasi authenticator (jenis TOTP, issuer `Secure Vault`, 6 digit, SHA-1, periode 30 detik).

### 5.2 Verifikasi Kode OTP
1. Setelah akun ditambahkan ke authenticator, masukkan kode 6 digit yang sedang tampil ke kolom **3. Masukkan kode 6 digit untuk menyelesaikan aktivasi TOTP**.
2. Klik **Aktifkan TOTP & Masuk**.
3. Sistem memverifikasi kode dan menyimpan secret TOTP secara terenkripsi (`AES-256-GCM`) di server, lalu membuka sesi pengguna.

### 5.3 Penggunaan MFA saat Login Berikutnya
Pada setiap login berikutnya, setelah memasukkan username dan kata sandi yang benar, sistem langsung meminta **Kode autentikator (6 digit)** pada layar **Verifikasi Dua Faktor (MFA)** sebelum menerbitkan token sesi.

---

## 6. Pengelolaan Brankas dan Berkas

### 6.1 Inisialisasi dan Membuka Brankas
1. **Inisialisasi Pertama Kali:** Jika pengguna belum memiliki profil brankas, akan muncul dialog **Inisialisasi Brankas Pribadi**. Masukkan **Passphrase Brankas Baru** (minimal **12 karakter**) dan **Konfirmasi Passphrase**, lalu klik **Inisialisasi & Buka Brankas**.
   > [!IMPORTANT]
   > *Passphrase* brankas **tidak pernah dikirim ke server** dan **tidak dapat dipulihkan** oleh administrator apabila lupa.
2. **Membuka Brankas:** Jika profil brankas sudah ada, muncul dialog **Buka Kunci Brankas Pribadi** (atau klik tombol **Brankas terkunci** di bagian bawah sidebar). Masukkan **Passphrase Brankas** lalu klik **Buka Kunci Brankas**.
3. Setelah terbuka, indikator berubah menjadi **Brankas terbuka** dan **RAM Active**. Kunci disimpan di RAM browser sebagai kunci *non-extractable*.
4. **Kunci Otomatis & Manual:** Brankas akan mengunci kunci di RAM secara otomatis setelah **15 menit** tanpa aktivitas (tanpa mengeluarkan pengguna dari sesi akun), atau dapat dikunci manual kapan saja dengan tombol **Kunci**.
5. **Mengganti Passphrase (Re-Wrap):** Saat brankas terbuka, klik tombol **Re-Wrap** untuk membuka dialog **Ganti Passphrase (Re-Wrap MK)**. Fitur ini membungkus ulang *Master Key* dengan KEK baru tanpa perlu mengenkripsi ulang seluruh berkas.

### 6.2 Membuat Folder dan Mengunggah Berkas / Folder
Brankas harus dalam keadaan terbuka sebelum membuat folder atau mengunggah berkas:
- **Membuat Folder Baru:** Klik **+ Baru → Folder baru**, masukkan nama folder (1–120 karakter, tanpa karakter path `/ \ : * ? " < > |`), lalu klik **Buat folder**. Nama folder dienkripsi di browser sebelum dikirim.
- **Mengunggah Berkas:** Klik **+ Baru → Upload file** (atau tombol **Unggah berkas** saat brankas kosong).
  1. Pilih berkas lewat tombol **Pilih Berkas** atau tarik & letakkan (*drag & drop*) ke area unggah.
  2. Isi atau ubah **Label / Tag Virtual Terenkripsi** (pisahkan dengan koma).
  3. Klik **Enkripsi Sisi-Klien & Unggah**.
  4. **Batasan:** Ukuran berkas 1 byte hingga **500 MB** (`524.288.000` byte). Ekstensi executable/script berbahaya (`.exe`, `.dll`, `.bat`, `.cmd`, `.ps1`, `.vbs`, `.js`, `.php`, `.sh`, `.jar`, `.apk`, dll.) serta berkas dengan *file signature* (*magic bytes*) yang tidak sesuai ekstensi (PDF, PNG, JPG/JPEG, GIF, ZIP, DOCX, XLSX) akan ditolak di sisi klien.
- **Mengunggah Folder:** Klik **+ Baru → Upload folder** (didukung pada browser berbasis Chromium seperti Chrome atau Edge melalui `webkitdirectory`).
  - Batas maksimal **1.000 berkas** per pemilihan, kedalaman struktur folder maksimal 20 tingkat, dan maksimal 500 MB per berkas.
  - Subfolder kosong tidak terbaca oleh pemilih folder browser; buat subfolder kosong secara manual melalui **Folder baru**.

### 6.3 Melihat Daftar, Pratinjau, dan Mengedit Metadata Berkas
- Buka menu **Beranda** atau **Brankas Saya** di sidebar. Gunakan bilah pencarian **Telusuri berkas di brankas**, pengurutan (**Tanggal**, **Nama**, **Ukuran**), filter **tag**, serta tombol tampilan **daftar** (*list*) atau **kartu** (*grid*).
- **Pratinjau (*Preview*):** Klik tombol **Pratinjau** (ikon berkas) pada berkas berukuran maksimal **50 MiB** dengan format **PDF**, **gambar** (`PNG`, `JPG`, `JPEG`, `GIF`, `WebP`, `BMP`, `AVIF`), **TXT**, **CSV**, **JSON**, atau **Markdown (`MD`)**. Pratinjau dilakukan setelah dekripsi lokal di browser.
- **Detail & Edit Metadata:** Klik tombol **Detail berkas** / **Spesifikasi Kriptografis** (ikon `i`) untuk melihat File ID (UUID v4), *Wrapped DEK*, ukuran, skema chunking, formula AAD, serta klik **Edit Nama & Tag** untuk mengubah nama atau tag berkas secara terenkripsi.

### 6.4 Mengunduh Berkas
1. Klik tombol **Unduh** (ikon panah ke bawah) pada berkas yang diinginkan.
2. Pada browser yang mendukung File System Access API (`showSaveFilePicker`), pilih lokasi penyimpanan di perangkat; plaintext hasil dekripsi ditulis bertahap per chunk (*streaming*) ke disk tanpa menumpuk di RAM.
3. Pada browser yang belum mendukung API tersebut, dekripsi menggunakan jalur *Blob* di memori (untuk berkas > 100 MB browser akan meminta konfirmasi terlebih dahulu).

### 6.5 Menghapus Berkas dan Folder
- **Menghapus Berkas:** Pada tampilan daftar, klik ikon tempat sampah (**Hapus Berkas**) lalu konfirmasi penghapusan permanen. Sistem menandai `deletion_pending`, menghapus objek chunk fisik di `storage/`, dan melepaskan kuota penyimpanan pengguna. Jika penghapusan terputus, status tampil sebagai *Penghapusan tertunda* dan tombol hapus dapat diklik ulang untuk melanjutkan pembersihan.
- **Menghapus Folder:** Folder hanya dapat dihapus apabila sudah kosong (tidak memiliki berkas atau subfolder di dalamnya). Klik ikon tempat sampah pada kartu folder lalu konfirmasi.

### 6.6 Ringkasan Proses Enkripsi Sisi Klien
1. *Passphrase* + *salt* 16-byte diturunkan via **Argon2id** menjadi **KEK** (256-bit).
2. **KEK** membungkus **Master Key** (`AES-256-KW`).
3. Setiap berkas/folder memiliki **DEK** acak 256-bit yang dibungkus oleh **Master Key**.
4. Nama berkas, tag, dan nama folder dienkripsi memakai **AES-256-GCM**.
5. Isi berkas dipecah menjadi potongan (*chunk*) **5 MB** dan masing-masing dienkripsi dengan **AES-256-GCM** menggunakan IV 12-byte acak dan AAD `{file_id}-{chunk_index}` untuk mencegah manipulasi atau penukaran urutan potongan.

---

## 7. Konsol Administrator

Menu **Konsol Admin** hanya terlihat dan dapat diakses oleh pengguna dengan peran **Administrator**. Fitur yang tersedia di halaman ini meliputi:

1. **Ringkasan Sistem:**
   - **Total akun** (termasuk administrator).
   - **Akun aktif** (siap digunakan).
   - **Menunggu aktivasi** (perlu verifikasi email/aktivasi).
   - **Akun nonaktif** (akses dibatasi).
   - Grafik **Distribusi status akun** dan kartu **Kapasitas teralokasi** (total penyimpanan terpakai vs kuota teralokasi, jumlah berkas terenkripsi, dan jumlah catatan audit).
2. **Buat Akun Pengguna:** Formulir pembuatan akun baru beserta pengiriman tautan aktivasi email otomatis (lihat Bagian 4.1).
3. **Daftar Akun Pengguna:** Pencarian berdasarkan username/email, filter status (**Semua status**, **Aktif**, **Menunggu aktivasi**, **Nonaktif**), serta tombol tindakan (**Kuota**, **Kirim Ulang Aktivasi**, **Cabut Sesi & Nonaktifkan**, **Aktifkan Akun**, **Hapus Akun**).
4. **Pembaruan Data:** Tombol **Perbarui data** di kanan atas untuk memuat ulang statistik dan daftar akun terbaru.

---

## 8. Jejak Audit

### 8.1 Hak Akses
Menu **Jejak Audit** hanya tersedia untuk **Administrator** (`GET /api/audit` dan `GET /api/audit/verify`). Pengguna biasa yang mencoba mengakses endpoint audit akan ditolak dengan HTTP 403.

### 8.2 Melihat dan Menyaring Audit Log
1. Klik menu **Jejak Audit** di sidebar kiri.
2. Bagian **Ringkasan audit** menampilkan **Total aktivitas**, **Berhasil**, dan **Gagal**.
3. Gunakan filter **Aktivitas** dan **Status** (**Semua status**, **Berhasil**, **Gagal**) untuk menyaring catatan, atau klik **Perbarui data** untuk memuat log terbaru.
4. Tabel **Daftar aktivitas** menampilkan 5 kolom:
   - **No.:** Nomor urut sekuensial catatan audit (`#1`, `#2`, dst.).
   - **Waktu:** Stempel waktu lokal konversi dari UTC.
   - **Aktivitas:** Deskripsi aktivitas yang mudah dibaca (misalnya masuk akun, gagal login, verifikasi MFA, unggah/unduh/hapus berkas, tindakan administrator) beserta detail terkait (ukuran berkas, jumlah bagian, batas penyimpanan) jika tersedia.
   - **Alamat IP:** Alamat IP sumber permintaan (atau `Tidak tersedia` bila kosong).
   - **Status:** **Berhasil** atau **Gagal**.

### 8.3 Verifikasi Integritas Audit
- Setiap entri audit baru dicatat menggunakan rantai hash **SHA3-512** (`hash_version = 3`) yang mengikat `previous_hash` ke `current_hash` entri sebelumnya.
- **Pada antarmuka web (UI):** Tabel **Jejak Audit** tidak menampilkan kolom teknis rantai hash dan tidak menyediakan tombol verifikasi rantai secara langsung di UI (sesuai penyederhanaan tampilan pada dokumentasi perbaikan).
- **Melalui API / CLI Administrator:**
  - Endpoint `GET /api/audit/verify` (dengan token sesi Administrator) dan `GET /api/admin/stats` (`chainIntegrity`) memanggil `Audit::verifyChain()` untuk memverifikasi seluruh urutan dan konsistensi hash rantai audit (mendukung kompatibilitas v1, v2, dan v3).
  - Untuk verifikasi terhadap bukti eksternal di luar host, administrator dapat menggunakan skrip CLI `backend_php/scripts/export_audit_anchor.php` dan `backend_php/scripts/verify_audit_anchor.php` (memerlukan environment variable `AUDIT_ANCHOR_HMAC_KEY`).

---

## 9. Pemeliharaan dan Pemeriksaan Operasional

### 9.1 Memastikan Aplikasi Berjalan
- **Pemeriksaan Antarmuka & Backend:**
  - Pastikan halaman frontend (`http://127.0.0.1:5173` atau URL deployment) dapat dibuka dan menampilkan form login.
  - Periksa endpoint healthcheck backend: akses `GET http://127.0.0.1:5000/api/health` dan pastikan respons berstatus HTTP 200 dengan `"status": "OK"`.
- **Pemeriksaan Kesiapan CLI:**
  Jalankan dari root proyek:
  ```bash
  php backend_php/scripts/production_readiness.php
  ```
  Pastikan keluaran menunjukkan `"status": "PASS"`.

### 9.2 Mengenali Kegagalan Layanan
- Jika muncul pesan *"Tidak dapat terhubung ke server Secure Vault. Pastikan backend PHP berjalan pada port 5000"*, proses PHP backend berhenti atau alamat API (`window.SECURE_VAULT_API_URL`) tidak sesuai.
- Jika backend mengembalikan HTTP 500 (*"Terjadi kesalahan internal pada peladen Secure Vault."*), periksa *error log* PHP/web server untuk melihat detail eksepsi internal (detail stack trace sengaja tidak ditampilkan ke browser).
- Jika pembuatan akun gagal dengan HTTP 503, periksa konfigurasi atau konektivitas server SMTP.

### 9.3 Pemeriksaan Dasar oleh Administrator
- Memantau **Konsol Admin** untuk memastikan tidak ada akun tidak dikenal, memeriksa pemakaian kuota pengguna, dan meninjau akun berstatus **MENUNGGU AKTIVASI** yang belum aktif.
- Meninjau **Jejak Audit** secara berkala untuk mendeteksi lonjakan aktivitas **Gagal** (seperti percobaan login/MFA gagal berulang atau kegagalan integritas chunk).
- Melakukan pemeriksaan kesiapan sistem (`production_readiness.php`) dan rekonsiliasi penyimpanan (`php backend_php/scripts/reconcile_storage.php` dalam mode *dry-run*) bila diperlukan.

> [!NOTE]
> Prosedur lengkap *backup*, *restore*, dan penanganan insiden belum disusun sebagai SOP terpisah dalam dokumen ini dan **perlu didokumentasikan pada dokumen terpisah** (skrip utilitas CLI seperti `backup_sqlite.php`, `verify_sqlite_backup.php`, dan `reconcile_storage.php` tersedia di `backend_php/scripts/`).

---

## 10. Troubleshooting

| Masalah | Kemungkinan Penyebab | Langkah Penanganan |
| :--- | :--- | :--- |
| **Tidak dapat login** | Username/password salah; terkena *rate limit* (5x gagal dalam 15 menit); atau akun dinonaktifkan admin. | Pastikan username dan kata sandi benar. Jika terkena *rate limit*, tunggu 15 menit. Jika muncul pesan akun dinonaktifkan, hubungi Administrator untuk mengaktifkan kembali melalui **Konsol Admin**. |
| **MFA bermasalah** | Kode OTP salah; jam perangkat tidak sinkron; kode yang sama dipakai ulang dalam 30 detik; atau tantangan MFA kedaluwarsa (> 20 menit) / terkunci (5x salah). | Pastikan jam ponsel/perangkat sinkron otomatis. Tunggu pergantian kode 6 digit berikutnya (30 detik). Jika tantangan kedaluwarsa/terkunci, klik **Kembali ke Login** lalu ulangi login dari awal. |
| **Email undangan tidak diterima** | Email masuk ke folder Spam; tautan kedaluwarsa (> 24 jam); atau SMTP server bermasalah. | Minta pengguna memeriksa folder Spam. Jika belum diterima atau kedaluwarsa, Administrator dapat menekan **Kirim Ulang Aktivasi** di **Konsol Admin**. Pastikan SMTP server aktif dan diuji dengan `php backend_php/scripts/test_smtp.php`. |
| **Verifikasi email gagal** | Tautan aktivasi tidak lengkap/terpotong; sudah kedaluwarsa (> 24 jam); sudah pernah dipakai; atau sudah digantikan tautan baru. | Minta Administrator menekan **Kirim Ulang Aktivasi** dan gunakan tautan terbaru. Jika terkena pembatasan percobaan aktivasi, tunggu 15 menit. |
| **Gagal mengunggah atau mengunduh berkas** | Brankas masih terkunci; ukuran berkas > 500 MB; ekstensi diblokir; *signature* berkas tidak cocok; kuota penuh; atau *chunk* terputus/gagal verifikasi integritas. | Pastikan status brankas **Brankas terbuka**, ukuran berkas ≤ 500 MB, dan jenis berkas diizinkan. Periksa sisa kuota di sidebar. Untuk unggahan yang terputus (*Unggahan belum lengkap*), hapus entri tersebut lalu unggah ulang. |
| **Brankas tidak dapat dibuka** | *Passphrase* salah; atau browser memblokir Web Crypto / WebAssembly / diakses melalui HTTP non-localhost. | Periksa kembali *passphrase* brankas (ingat: tidak ada fitur reset *passphrase* jika lupa). Pastikan akses melalui `http://127.0.0.1:5173` / `localhost` atau `https://`, dan uji kompatibilitas browser melalui `/diagnostics/argon2-self-test.html`. |
| **Aplikasi tidak dapat diakses** | Server PHP backend (port 5000) atau frontend (port 5173) belum dijalankan, atau terblokir firewall/CORS. | Jalankan ulang aplikasi (`start_all_php.bat` atau terminal backend & frontend). Periksa `http://127.0.0.1:5000/api/health` dan pastikan origin browser terdaftar pada `SECURE_VAULT_CORS_ORIGINS`. |

---

## 11. Batasan Operasional

1. **Tidak Ada Pemulihan *Passphrase*:** Karena arsitektur *Zero-Knowledge*, Administrator maupun server tidak dapat memulihkan *passphrase* brankas pengguna yang lupa. Kehilangan *passphrase* berarti kehilangan akses ke seluruh berkas di brankas tersebut.
2. **Batas Ukuran dan Format Unggahan:** Maksimal **500 MiB** per berkas (dengan chunk 5 MB, maksimal 100 chunk per berkas), maksimal **1.000 berkas** per unggahan folder, dan batas **50 MiB** untuk pratinjau di browser.
3. **Pemindaian Malware Terbatas:** Validasi unggahan di browser hanya memeriksa ekstensi berisiko, karakter nama file, dan *magic bytes* beberapa format umum. Server hanya menerima *ciphertext* sehingga tidak dapat menjalankan antivirus pada *plaintext*.
4. **Dukungan Browser:** Unggah folder (`webkitdirectory`) dan *streaming download* (`showSaveFilePicker`) bekerja optimal pada browser berbasis Chromium (Chrome/Edge). Browser tanpa `showSaveFilePicker` memakai fallback *Blob* yang dapat memakan RAM lebih besar untuk berkas > 100 MB.
5. **Penguncian Brankas Otomatis:** Brankas otomatis terkunci setelah **15 menit** tidak aktif, sehingga pengguna harus memasukkan ulang *passphrase* untuk mendekripsi berkas.
6. **Konkurensi Database:** Database SQLite menggunakan *process-wide file lock* (`database.lock`) pada setiap permintaan; aplikasi saat ini belum ditujukan untuk konkurensi *multi-worker* skala tinggi (lihat batasan pada `README.md`).
7. **Akun Administrator:** Akun administrator tidak dapat diubah kuotanya, dinonaktifkan, atau dihapus melalui **Konsol Admin** (*Akun terlindungi*). Penambahan hak admin pada akun lain hanya dapat dilakukan melalui CLI `promote_admin.php`.
8. **Tidak Ada Reset MFA Mandiri di UI:** Fitur reset/nonaktifkan MFA mandiri oleh pengguna atau melalui Konsol Admin belum tersedia di antarmuka web — *Perlu dikonfirmasi* prosedur operasional resminya bila pengguna kehilangan perangkat authenticator.

---

## 12. Referensi

- **Panduan Instalasi & Konfigurasi Aman:** [docs/panduan-instalasi-konfigurasi-aman.md](panduan-instalasi-konfigurasi-aman.md)
- **Dokumentasi Perbaikan Sistem:**
  - [docs/perbaikan/README.md](perbaikan/README.md)
  - [docs/perbaikan/01-perubahan-sha3-512-audit.md](perbaikan/01-perubahan-sha3-512-audit.md)
  - [docs/perbaikan/02-perbaikan-kolom-pengguna-ip.md](perbaikan/02-perbaikan-kolom-pengguna-ip.md)
  - [docs/perbaikan/03-penghapusan-kolom-rantai-hash.md](perbaikan/03-penghapusan-kolom-rantai-hash.md)
  - [docs/perbaikan/04-persistent-local-database.md](perbaikan/04-persistent-local-database.md)
- **Dokumentasi Utama Repository:** [README.md](../README.md)
- **Kode Sumber Terkait:**
  - Frontend: `frontend/index.html`, `frontend/js/app.js`, `frontend/js/api.js`, `frontend/js/crypto.js`, `frontend/router.php`
  - Backend Routes & Middleware: `backend_php/index.php`, `backend_php/middleware/AuthMiddleware.php`, `backend_php/routes/AuthRoutes.php`, `backend_php/routes/AdminRoutes.php`, `backend_php/routes/FileRoutes.php`, `backend_php/routes/AuditRoutes.php`
  - Utilitas & Skrip Operasional: `backend_php/utils/Audit.php`, `backend_php/utils/Activation.php`, `backend_php/utils/SmtpMailer.php`, `backend_php/utils/Totp.php`, `backend_php/scripts/production_readiness.php`, `backend_php/scripts/test_smtp.php`
