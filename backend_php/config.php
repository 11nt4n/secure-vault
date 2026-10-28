<?php
// backend_php/config.php
// Secure Vault Configuration

error_reporting(E_ALL);
ini_set('display_errors', '0'); // Return JSON errors rather than HTML warnings

define('BASE_DIR', __DIR__);
define('DATA_DIR', BASE_DIR . DIRECTORY_SEPARATOR . 'data');
define('STORAGE_DIR', BASE_DIR . DIRECTORY_SEPARATOR . 'storage');
define('DB_FILE', DATA_DIR . DIRECTORY_SEPARATOR . 'database.json');

// JWT Secret Key (matching TypeScript backend default)
define('JWT_SECRET', getenv('JWT_SECRET') ?: 'secure_vault_super_secret_jwt_key_2026_bssn');

// Allowed Origins for CORS
define('CORS_ALLOWED_ORIGINS', [
    'http://localhost:5173',
    'http://127.0.0.1:5173',
    'http://localhost:3000',
    'http://127.0.0.1:3000'
]);

// Ensure data and storage directories exist
if (!is_dir(DATA_DIR)) {
    mkdir(DATA_DIR, 0755, true);
}
if (!is_dir(STORAGE_DIR)) {
    mkdir(STORAGE_DIR, 0755, true);
}
