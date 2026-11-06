@echo off
 title Secure Vault Frontend (HTML + CSS + JavaScript)
cd /d "%~dp0"
php -S 127.0.0.1:5173 router.php
