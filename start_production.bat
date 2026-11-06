@echo off
title Secure Vault - Production Deployment (Port 5000)
color 0A
echo ========================================================
echo   SECURE VAULT - Production Server
echo   Zero-Knowledge 3-Layer Client-Side Envelope Encryption
echo   ISO/IEC 15408-1:2022 & ISO/IEC 18045:2026 Compliant
echo ========================================================
echo.

if not exist "frontend\dist\index.html" (
    echo [1/2] Bundle produksi frontend belum ditemukan. Membangun...
    cd frontend && npm run build && cd ..
)

echo [1/2] Memulai server terpadu Secure Vault pada port 5000...
echo URL: http://localhost:5000
echo.

start "Secure Vault Production Server (Port 5000)" cmd /k "cd backend_php && php -S 0.0.0.0:5000 index.php"

timeout /t 2 > nul
echo [2/2] Membuka Secure Vault di browser...
start http://localhost:5000

echo.
echo ========================================================
echo  Secure Vault telah aktif dalam mode Single-Port Production!
echo  - Antarmuka Web : http://localhost:5000
echo  - API Health Check : http://localhost:5000/api/health
echo ========================================================
pause

