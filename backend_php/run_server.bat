@echo off
title Secure Vault - PHP Backend API
color 0A
echo ========================================================
echo  SECURE VAULT - Zero-Knowledge PHP Backend API
echo  Standard: ISO/IEC 15408-1:2022 & ISO/IEC 18045:2026
echo ========================================================
echo.
echo [1/2] Menyiapkan server PHP pada http://127.0.0.1:5000 ...
echo [2/2] Endpoint Healthcheck: http://127.0.0.1:5000/api/health
echo.
echo Tekan CTRL + C untuk menghentikan server.
echo.
php -S 127.0.0.1:5000 -t . index.php
pause
