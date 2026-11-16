@echo off
setlocal
 title Secure Vault Launcher (PHP Backend + Vanilla Frontend)
color 0B
cd /d "%~dp0"
echo ========================================================
echo   SECURE VAULT - Zero-Knowledge Client-Side Encryption
echo   Backend : PHP 8 REST API (Port 5000)
echo   Frontend: HTML + CSS + JavaScript (Port 5173)
echo ========================================================
echo.

where php >nul 2>nul
if errorlevel 1 (
  echo PHP CLI tidak ditemukan. Pasang PHP 8+ dan aktifkan extension pdo_sqlite.
  pause
  exit /b 1
)
php -r "if (!extension_loaded('pdo_sqlite')) {fwrite(STDERR, 'Ekstensi pdo_sqlite belum aktif pada PHP CLI. Periksa php.ini.\n'); exit(1);}"
if errorlevel 1 (
  pause
  exit /b 1
)

echo [1/3] Memastikan secret lokal dibuat di luar web root...
php backend_php\scripts\init_local_secrets.php
if errorlevel 1 (
  echo Gagal membuat secret lokal. Periksa konfigurasi PHP.
  pause
  exit /b 1
)
if not defined SECURE_VAULT_SMTP_HOST if not exist "var\secure-vault\smtp.json" (
  echo Gmail SMTP belum diatur. Sebelum membuat akun pengguna, jalankan configure_gmail_smtp.bat.
)
echo.

echo [2/3] Menjalankan Backend PHP di port 5000...
start "Secure Vault - PHP Backend (Port 5000)" /D "%~dp0backend_php" cmd /k "php -d upload_max_filesize=8M -d post_max_size=10M -d max_execution_time=120 -d max_input_time=120 -S 127.0.0.1:5000 -t . index.php"
echo.

echo [3/3] Menjalankan Frontend HTML/CSS/JS di port 5173...
start "Secure Vault - Static Frontend (Port 5173)" /D "%~dp0frontend" cmd /k "php -S 127.0.0.1:5173 router.php"
echo Menunggu server siap...
timeout /t 3 > nul
start http://127.0.0.1:5173
echo.
echo ========================================================
echo Tidak diperlukan Node.js, npm, React, TypeScript, atau Vite.
echo Untuk membuat administrator, hentikan backend lalu jalankan:
echo php backend_php\scripts\promote_admin.php USERNAME
echo ========================================================
pause
endlocal
