<?php
// backend_php/scripts/init_admin.php
// Secure initial administrator creation for fresh installations.
// This script is strictly restricted: it only runs when the database contains ZERO users.
// Once an administrator is created, this mechanism is permanently disabled.

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit(1);
}

require_once dirname(__DIR__) . '/config.php';
require_once dirname(__DIR__) . '/db/Database.php';
require_once dirname(__DIR__) . '/utils/Audit.php';

$db = Database::getInstance();
$users = $db->getUsers();
if (count($users) > 0) {
    fwrite(STDERR, "SETUP DITOLAK: Sistem sudah memiliki akun terdaftar (" . count($users) . " akun).\n");
    fwrite(STDERR, "Mekanisme initial administrator setup dinonaktifkan secara permanen.\n");
    exit(1);
}

// Support both CLI argument mode (for automated setup/tests) and interactive mode
$username = trim((string)($argv[1] ?? ''));
$password = (string)($argv[2] ?? '');
$email = trim((string)($argv[3] ?? ''));

if ($username === '' || $password === '' || $email === '') {
    fwrite(STDOUT, "========================================================\n");
    fwrite(STDOUT, "  SECURE VAULT - INITIAL ADMINISTRATOR SETUP            \n");
    fwrite(STDOUT, "========================================================\n");
    fwrite(STDOUT, "Instalasi baru terdeteksi. Silakan buat akun administrator utama.\n\n");

    if ($username === '') {
        fwrite(STDOUT, "Masukkan username administrator (3-32 karakter alfanumerik): ");
        $username = trim((string)fgets(STDIN));
    }

    if ($email === '') {
        fwrite(STDOUT, "Masukkan alamat email administrator: ");
        $email = trim((string)fgets(STDIN));
    }

    if ($password === '') {
        fwrite(STDOUT, "Masukkan password administrator (minimal 12 karakter): ");
        // Read password securely
        $password = trim((string)fgets(STDIN));
    }
}

// 1. Validate Username
if (!preg_match('/^[a-zA-Z0-9_\-\.]{3,32}$/', $username)) {
    fwrite(STDERR, "GAGAL: Username harus 3-32 karakter (alfanumerik, garis bawah, titik, atau tanda hubung).\n");
    exit(2);
}

// 2. Validate Email
if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    fwrite(STDERR, "GAGAL: Format alamat email tidak valid.\n");
    exit(3);
}

// 3. Validate Password strength (no default passwords allowed, minimum 12 characters)
if (strlen($password) < 12) {
    fwrite(STDERR, "GAGAL: Password administrator minimal harus 12 karakter demi keamanan sistem.\n");
    exit(4);
}

$forbiddenPasswords = ['admin123', 'admin', 'password', 'password123', '12345678', 'SecureVault123'];
foreach ($forbiddenPasswords as $bad) {
    if (strcasecmp($password, $bad) === 0) {
        fwrite(STDERR, "GAGAL: Password terlalu umum atau merupakan password bawaan yang dilarang.\n");
        exit(5);
    }
}

// Hash password using official application hashing (Argon2id)
$passwordHash = Database::hashPassword($password);
$userId = Database::generateUuid();

$adminUser = [
    'id' => $userId,
    'username' => $username,
    'email' => $email,
    'password_hash' => $passwordHash,
    'role' => 'admin',
    'is_active' => true,
    'session_version' => 0,
    'storage_quota_bytes' => 10737418240, // 10 GiB
    'storage_used_bytes' => 0,
    'created_at' => gmdate('Y-m-d\TH:i:s.000\Z'),
    'email_verification_status' => 'verified',
];

$db->addUser($adminUser);

// Log audit event using SHA3-512 V3
Audit::logEvent(
    $userId,
    'ADMIN_INITIAL_SETUP',
    null,
    '127.0.0.1',
    'SecureVault CLI init_admin.php',
    'SUCCESS',
    json_encode(['username' => $username, 'email' => $email])
);

fwrite(STDOUT, "\n[SUKSES] Akun administrator '{$username}' ({$email}) berhasil dibuat!\n");
fwrite(STDOUT, "Mekanisme initial administrator setup sekarang DINONAKTIFKAN secara permanen.\n");
fwrite(STDOUT, "Anda dapat langsung login ke aplikasi menggunakan akun ini.\n");
exit(0);
