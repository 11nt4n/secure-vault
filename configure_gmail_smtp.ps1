$ErrorActionPreference = 'Stop'
$projectDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$configDir = Join-Path $projectDir 'var\secure-vault'
$configPath = Join-Path $configDir 'smtp.json'
if (-not (Get-Command php -ErrorAction SilentlyContinue)) {
    Write-Error 'PHP CLI tidak ditemukan. Pasang PHP 8+ dan jalankan lagi.'
    exit 1
}

Write-Host 'Konfigurasi Gmail untuk email verifikasi Secure Vault'
Write-Host 'Aktifkan Verifikasi 2 Langkah di Google, lalu buat App Password di https://myaccount.google.com/apppasswords'
$gmailAddress = (Read-Host 'Alamat Gmail pengirim').Trim()
try {
    $parsedAddress = [System.Net.Mail.MailAddress]::new($gmailAddress)
    if ($parsedAddress.Address -ne $gmailAddress) { throw 'invalid' }
} catch {
    Write-Error 'Alamat Gmail tidak valid.'
    exit 1
}

$securePassword = Read-Host 'App Password Gmail (16 karakter, bukan password akun)' -AsSecureString
$secretPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
try {
    $appPassword = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($secretPointer) -replace '\s', ''
} finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($secretPointer)
}
if ($appPassword -notmatch '^[A-Za-z0-9]{16}$') {
    Write-Error 'App Password harus 16 karakter. Buat App Password dari pengaturan akun Google.'
    exit 1
}

New-Item -ItemType Directory -Path $configDir -Force | Out-Null
$settings = [ordered]@{
    HOST = 'smtp.gmail.com'
    PORT = '465'
    ENCRYPTION = 'ssl'
    FROM = $gmailAddress
    USER = $gmailAddress
    PASSWORD = $appPassword
}
$json = ConvertTo-Json -InputObject $settings -Compress
$temporaryPath = "$configPath.tmp"
[System.IO.File]::WriteAllText($temporaryPath, $json, [System.Text.UTF8Encoding]::new($false))
Move-Item -LiteralPath $temporaryPath -Destination $configPath -Force
$appPassword = $null
$settings.PASSWORD = $null

Write-Host 'Menguji koneksi dan pengiriman email ke alamat Gmail pengirim...'
& php (Join-Path $projectDir 'backend_php\scripts\init_local_secrets.php')
if ($LASTEXITCODE -ne 0) { exit 1 }
& php (Join-Path $projectDir 'backend_php\scripts\test_smtp.php')
if ($LASTEXITCODE -ne 0) {
    Write-Host 'Konfigurasi tersimpan, tetapi tes gagal. Jalankan skrip ini lagi setelah memeriksa App Password atau koneksi internet.' -ForegroundColor Yellow
    exit 1
}
Write-Host 'SMTP Gmail siap. Periksa email tes di kotak masuk atau folder Spam.' -ForegroundColor Green
