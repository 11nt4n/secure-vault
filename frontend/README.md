# Secure Vault Frontend (Native HTML/CSS/JavaScript)

Frontend ini sudah dikonversi dari React + TypeScript + Vite menjadi HTML, CSS, dan JavaScript ES Modules murni. Tidak ada dependensi npm atau proses build.

## Menjalankan

Dari folder ini:

```bash
php -S 127.0.0.1:5173 router.php
```

Kemudian buka `http://127.0.0.1:5173`. Backend PHP harus berjalan pada `http://127.0.0.1:5000`. Tantangan aktivasi MFA berlaku 20 menit; sesi aktif berlaku 8 jam sejak aktivitas terakhir karena token diputar ulang otomatis pada setiap request API terautentikasi.

Konfigurasi URL API dapat diubah dengan menetapkan `window.SECURE_VAULT_API_URL` di `index.html` sebelum `js/app.js` dijalankan. Untuk origin frontend non-default, izinkan origin tersebut melalui `SECURE_VAULT_CORS_ORIGINS` di backend.

## Perilaku kriptografi, MFA, dan sesi

- Derivasi KEK Argon2id (64 MiB, 3 iterasi) menggunakan runtime WASM lokal `argon2-bundled.min.js` yang dimuat langsung oleh `index.html`, sesuai jalur yang dipakai frontend asli dan telah diuji bekerja. Pemanggilan langsung menghindari hang pada eksekusi Argon2 di Web Worker pada sebagian browser. Kegagalan runtime dan impor KEK ditampilkan sebagai pesan yang jelas; parameter dan format kunci tidak berubah.
- Enrollment TOTP memakai QR yang dirender offline oleh `js/qr.js`. URI `otpauth://` diproses di browser; secret manual tetap tersedia sebagai cadangan.
- Tantangan MFA berlaku 20 menit. JWT sesi berlaku 8 jam dan diperbarui pada setiap request API terautentikasi.
- Penguncian otomatis brankas setelah 15 menit tidak aktif tetap dipertahankan. Ini hanya membersihkan kunci dari RAM dan tidak mengeluarkan akun dari sesi login.

## Perbaikan passphrase dan pesan kesalahan

- Proses Argon2id kembali memakai pemanggilan langsung `window.argon2.hash()` dengan parameter yang sama seperti implementasi React awal: Argon2id, 64 MiB, 3 iterasi, paralelisme 1, dan keluaran 32 byte.
- Tidak ada Web Worker, fallback KDF, atau penurunan parameter. Selama derivasi, antarmuka hanya memperbarui elemen status dan tombol modal. Seluruh DOM aplikasi tidak dibangun ulang di tengah proses sehingga form dan alur derivasi tidak saling mengganggu.
- Kesalahan login/MFA mengambil pesan JSON asli dari backend. HTTP 401 dari `/auth/login` tidak lagi dianggap sebagai sesi habis; HTTP 401 pada endpoint terlindungi tetap mengakhiri sesi dan menampilkan alasan yang diberikan backend.
- Username yang tidak terdaftar dan password login yang salah sengaja memakai pesan umum yang sama untuk mencegah enumerasi akun. Kesalahan registrasi, seperti password di bawah 12 karakter, tetap menampilkan alasan spesifik.
- Uji browser mandiri tersedia di `http://127.0.0.1:5173/diagnostics/argon2-self-test.html`. Halaman ini menguji runtime Argon2id dan AES-KW tanpa menggunakan passphrase brankas sebenarnya atau mengirim data ke server.


## Iterasi 3: pemrosesan chunk dan hardening frontend

- Operasi AES-256-GCM per chunk (enkripsi dan dekripsi) berjalan di ES Module Web Worker melalui `js/crypto-worker.js`. `CryptoKey` dikirim melalui structured clone; material kunci tetap non-extractable. Argon2id tetap menggunakan jalur browser yang sudah teruji karena implementasi sebelumnya mencatat masalah kompatibilitas pada Web Worker.
- Upload tetap membaca satu potongan 5 MiB dari `File.slice()` pada satu waktu, lalu mentransfer buffer ke worker. Worker membersihkan buffer plaintext setelah operasi selesai.
- Pada browser yang mendukung File System Access API, unduhan didekripsi per chunk dan ditulis langsung melalui `FileSystemWritableFileStream`; tidak ada Blob berukuran penuh di memori JavaScript.
- Browser tanpa File System Access API menggunakan fallback Blob. Untuk file di atas 100 MiB, aplikasi meminta konfirmasi karena fallback dapat memakai RAM besar. Pratinjau tetap dibatasi 50 MiB.
- Semua chunk diverifikasi menggunakan AES-GCM, AAD yang mengikat ID file dan indeks chunk, serta pemeriksaan panjang plaintext per chunk dan ukuran total.
- CSP tidak lagi mengizinkan `unsafe-inline` pada style. Font eksternal Google dihapus; tampilan menggunakan system font. `worker-src 'self'` membatasi worker ke origin aplikasi. `wasm-unsafe-eval` tetap diizinkan secara khusus untuk runtime Argon2id WASM.
- CSP kompatibel, tetapi router pengembangan ini tetap menggunakan HTTP localhost untuk API. Untuk deployment jaringan/produksi, wajib menggunakan HTTPS dan meninjau ulang `connect-src`, HSTS, cookie/token policy, reverse proxy, serta konfigurasi TLS.

### Pengujian Iterasi 3

Jalankan pemeriksaan statis dari root proyek:

```bash
python backend_php/tests/frontend_security_static.py
node backend_php/tests/crypto_worker_node_test.mjs
node frontend/diagnostics/crypto-rewrap-test.mjs
node --check frontend/js/app.js
node --check frontend/js/crypto-worker-client.js
node --check frontend/js/crypto-worker.js
php -l frontend/router.php
```

Uji worker, File System Access API, dan memori download tetap harus diverifikasi di browser Chromium/Edge yang mendukung API tersebut. Browser lain mengikuti fallback Blob. Jangan menyimpan file rahasia nyata sebelum seluruh suite API dan pengujian browser dijalankan pada lingkungan dengan `pdo_sqlite`.
