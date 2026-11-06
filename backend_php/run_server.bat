@echo off
title Secure Vault - PHP Backend API
color 0A
cd /d "%~dp0.."
echo ========================================================
echo  SECURE VAULT - PHP Backend API
echo ========================================================
php -r "if (!extension_loaded('pdo_sqlite')) {fwrite(STDERR, 'Ekstensi pdo_sqlite belum aktif pada PHP CLI. Periksa php.ini.\n'); exit(1);}"
if errorlevel 1 (
  pause
  exit /b 1
)
php backend_php\scripts\init_local_secrets.php
if errorlevel 1 (
  echo Gagal membuat secret lokal. Pastikan PHP CLI terpasang.
  pause
  exit /b 1
)
echo Server: http://127.0.0.1:5000
php -d upload_max_filesize=8M -d post_max_size=10M -d max_execution_time=120 -d max_input_time=120 -S 127.0.0.1:5000 -t backend_php backend_php\index.php
pause
