# 🛡️ Secure Vault

> **Zero-Knowledge 3-Layer Envelope Encryption Web Application**  
> Evaluated against **ISO/IEC 15408-1:2022** & **ISO/IEC 18045:2026** (Common Criteria).

---

## 🌟 Fitur Utama
* **Zero-Knowledge Architecture**: Enkripsi dan dekripsi file sepenuhnya dilakukan di sisi klien (browser) menggunakan Web Crypto API (`crypto.subtle`) dan Argon2id (WebAssembly).
* **3-Layer Envelope Encryption**:
  1. **KEK (Key Encryption Key)**: Diturunkan dari Passphrase pengguna via Argon2id.
  2. **MK (Master Key)**: AES-256-KW di-wrap oleh KEK.
  3. **DEK (Data Encryption Key)**: AES-256-KW unik per berkas di-wrap oleh Master Key.
  4. **Chunks**: Potongan berkas (5 MB) dienkripsi dengan AES-256-GCM + AAD (`fileId + chunkIndex`).
* **Tamper-Resistant SHA-256 Hash Chain**: Jejak audit berantai yang tidak dapat dimanipulasi diam-diam.
* **Modern Backend**: REST API berbasis **PHP 8** (PDO, OpenSSL, native HS256 JWT, dan chunk streaming).
* **Modern Frontend**: React + TypeScript + Vite + Glassmorphism Dark UI.

---

## 🚀 Panduan Memulai Cepat

### 1. Prasyarat
* PHP 8.0+
* Node.js 18+ & npm

### 2. Menjalankan Aplikasi
Cukup klik ganda file:
```cmd
start_all_php.bat
```
Atau jalankan secara terpisah:

**Terminal 1 (Backend PHP):**
```bash
cd backend_php
php -S 127.0.0.1:5000 -t . index.php
```

**Terminal 2 (Frontend React):**
```bash
cd frontend
npm run dev
```

Buka peramban di `http://localhost:5173`.

---

## 🔑 Akun Demo Pengujian
* **Administrator**: Username `admin` | Password `admin123` | TOTP `123456`
* **User Biasa**: Username `user` | Password `user123` | TOTP `123456`

---

## 📄 Standar Keamanan
* **ISO/IEC 15408-1:2022** (Common Criteria for Information Technology Security Evaluation)
* **ISO/IEC 18045:2026** (Methodology for IT Security Evaluation)
