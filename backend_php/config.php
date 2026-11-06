<?php
// Secure Vault runtime configuration.
// Runtime data and local development secrets are intentionally stored outside the web root.

error_reporting(E_ALL);
ini_set('display_errors', '0');
umask(0077);

define('BASE_DIR', __DIR__);
define('PROJECT_DIR', dirname(BASE_DIR));
define('PRIVATE_DIR', PROJECT_DIR . DIRECTORY_SEPARATOR . 'var' . DIRECTORY_SEPARATOR . 'secure-vault');

$localSecretsFile = PRIVATE_DIR . DIRECTORY_SEPARATOR . 'secrets.php';
$localSecrets = [];
if (is_file($localSecretsFile) && is_readable($localSecretsFile)) {
    $loadedSecrets = require $localSecretsFile;
    if (is_array($loadedSecrets)) {
        $localSecrets = $loadedSecrets;
    }
}

$jwtSecret = getenv('JWT_SECRET');
if ($jwtSecret === false || $jwtSecret === '') {
    $jwtSecret = (string)($localSecrets['JWT_SECRET'] ?? '');
}
if (strlen($jwtSecret) < 32) {
    throw new RuntimeException(
        'JWT_SECRET is not configured or is too short. Set a cryptographically random secret (at least 32 bytes) in the environment, or run backend_php/scripts/init_local_secrets.php for local development.'
    );
}
define('JWT_SECRET', $jwtSecret);

// Sliding user sessions: 8 hours, renewed while the account remains active.
$jwtTtlSeconds = getenv('JWT_TTL_SECONDS');
if ($jwtTtlSeconds === false || $jwtTtlSeconds === '') $jwtTtlSeconds = 28800;
$jwtTtlSeconds = filter_var($jwtTtlSeconds, FILTER_VALIDATE_INT);
if ($jwtTtlSeconds === false || $jwtTtlSeconds < 900 || $jwtTtlSeconds > 86400) {
    throw new RuntimeException('JWT_TTL_SECONDS must be between 900 and 86400 seconds.');
}
define('JWT_TTL_SECONDS', $jwtTtlSeconds);

$mfaKeyBase64 = getenv('MFA_ENCRYPTION_KEY');
if ($mfaKeyBase64 === false || $mfaKeyBase64 === '') {
    $mfaKeyBase64 = (string)($localSecrets['MFA_ENCRYPTION_KEY'] ?? '');
}
$mfaEncryptionKey = base64_decode($mfaKeyBase64, true);
if (!is_string($mfaEncryptionKey) || strlen($mfaEncryptionKey) !== 32) {
    throw new RuntimeException(
        'MFA_ENCRYPTION_KEY is not configured or invalid. It must be base64-encoded 32-byte key material. Set it in the environment, or run backend_php/scripts/init_local_secrets.php for local development.'
    );
}
define('MFA_ENCRYPTION_KEY', $mfaEncryptionKey);

$defaultPrivateData = PRIVATE_DIR . DIRECTORY_SEPARATOR . 'data';
$defaultPrivateStorage = PRIVATE_DIR . DIRECTORY_SEPARATOR . 'storage';
$dataDirEnv = getenv('SECURE_VAULT_DATA_DIR');
$storageDirEnv = getenv('SECURE_VAULT_STORAGE_DIR');
define('DATA_DIR', rtrim(($dataDirEnv !== false && $dataDirEnv !== '') ? $dataDirEnv : $defaultPrivateData, DIRECTORY_SEPARATOR));
define('STORAGE_DIR', rtrim(($storageDirEnv !== false && $storageDirEnv !== '') ? $storageDirEnv : $defaultPrivateStorage, DIRECTORY_SEPARATOR));
define('DB_FILE', DATA_DIR . DIRECTORY_SEPARATOR . 'secure-vault.sqlite');
define('LEGACY_JSON_DB_FILE', DATA_DIR . DIRECTORY_SEPARATOR . 'database.json');
define('DB_LOCK_FILE', DATA_DIR . DIRECTORY_SEPARATOR . 'database.lock');

// Only development origins that are explicitly approved may read API responses.
$corsEnv = getenv('SECURE_VAULT_CORS_ORIGINS');
$corsOrigins = ($corsEnv !== false && trim($corsEnv) !== '')
    ? array_values(array_filter(array_map('trim', explode(',', $corsEnv))))
    : [
        'http://localhost:5173',
        'http://127.0.0.1:5173',
        'http://localhost:3000',
        'http://127.0.0.1:3000'
    ];
define('CORS_ALLOWED_ORIGINS', $corsOrigins);

foreach ([PRIVATE_DIR, DATA_DIR, STORAGE_DIR] as $directory) {
    if (!is_dir($directory) && !mkdir($directory, 0700, true) && !is_dir($directory)) {
        throw new RuntimeException('Unable to create a private Secure Vault runtime directory.');
    }
    @chmod($directory, 0700);
}

$webRootReal = realpath(BASE_DIR);
$runtimePaths = [realpath(PRIVATE_DIR), realpath(DATA_DIR), realpath(STORAGE_DIR)];
if (is_string($webRootReal)) {
    $webRootPrefix = rtrim(str_replace('\\', '/', $webRootReal), '/') . '/';
    foreach ($runtimePaths as $runtimePath) {
        if (!is_string($runtimePath)) {
            throw new RuntimeException('Unable to resolve a private runtime directory.');
        }
        $normalizedRuntime = str_replace('\\', '/', $runtimePath);
        $normalizedPrefix = DIRECTORY_SEPARATOR === '\\' ? strtolower($webRootPrefix) : $webRootPrefix;
        if (str_starts_with(DIRECTORY_SEPARATOR === '\\' ? strtolower($normalizedRuntime . '/') : $normalizedRuntime . '/', $normalizedPrefix)) {
            throw new RuntimeException('Secure Vault runtime data and secrets must be stored outside the web root.');
        }
    }
}
