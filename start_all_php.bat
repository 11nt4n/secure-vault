@echo off
title Secure Vault Launcher (PHP Backend + React Frontend)
color 0B
echo ========================================================
echo   SECURE VAULT - Zero-Knowledge Client-Side Encryption
echo   Backend : PHP 8 REST API (Port 5000)
echo   Frontend: React + Vite + Web Crypto (Port 5173)
echo ========================================================
echo.
echo [1/3] Menjalankan Backend PHP di latar belakang...
start "Secure Vault - PHP Backend (Port 5000)" cmd /k "cd backend_php && php -S 127.0.0.1:5000 -t . index.php"

echo [2/3] Menjalankan Frontend React (Vite)...
start "Secure Vault - Frontend (Port 5173)" cmd /k "cd frontend && npm run dev"

echo [3/3] Menunggu server siap...
timeout /t 3 > nul

echo.
echo Membuka aplikasi di browser...
start http://localhost:5173

echo.
echo ========================================================
echo  Secure Vault telah aktif!
echo  - Frontend : http://localhost:5173
echo  - Backend  : http://127.0.0.1:5000/api/health
echo ========================================================
pause
