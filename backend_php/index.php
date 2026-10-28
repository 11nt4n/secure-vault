<?php
// backend_php/index.php
// Secure Vault REST API (PHP Edition)
// Compatible with ISO/IEC 15408:2022 & ISO/IEC 18045:2026 Common Criteria

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/utils/Response.php';
require_once __DIR__ . '/routes/AuthRoutes.php';
require_once __DIR__ . '/routes/FileRoutes.php';
require_once __DIR__ . '/routes/AuditRoutes.php';
require_once __DIR__ . '/routes/AdminRoutes.php';

// Handle CORS
Response::handleCors();

// Extract URI path and normalize
$requestUri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$method = $_SERVER['REQUEST_METHOD'];

// Find position of '/api' in URI (works in standalone server or subfolder like /secure-vault-api/api)
$apiPos = strpos($requestUri, '/api');
if ($apiPos !== false) {
    $path = substr($requestUri, $apiPos);
} else {
    $path = $requestUri;
}
$path = rtrim($path, '/');
if (empty($path)) $path = '/';

// Parse JSON Body
$rawInput = file_get_contents('php://input');
$body = [];
if (!empty($rawInput)) {
    $decoded = json_decode($rawInput, true);
    if (is_array($decoded)) {
        $body = $decoded;
    }
}
if (!empty($_POST)) {
    $body = array_merge($body, $_POST);
}

// Global Exception Handler
try {
    // ----------------------------------------------------
    // Healthcheck
    // ----------------------------------------------------
    if ($method === 'GET' && ($path === '/api/health' || $path === '/api')) {
        Response::json([
            'status' => 'OK',
            'service' => 'Secure Vault API (PHP Edition)',
            'security' => 'Zero-Knowledge Client-Side Encryption + SHA-256 Hash-Chain Audit',
            'standard' => 'ISO/IEC 15408:2022 & ISO/IEC 18045:2026',
            'timestamp' => gmdate('Y-m-d\TH:i:s.000\Z')
        ]);
    }

    // ----------------------------------------------------
    // Auth Routes
    // ----------------------------------------------------
    if ($path === '/api/auth/register' && $method === 'POST') {
        AuthRoutes::register($body);
    }
    if ($path === '/api/auth/login' && $method === 'POST') {
        AuthRoutes::login($body);
    }
    if ($path === '/api/auth/mfa/verify' && $method === 'POST') {
        AuthRoutes::verifyMfa($body);
    }
    if ($path === '/api/auth/me' && $method === 'GET') {
        AuthRoutes::me();
    }
    if ($path === '/api/auth/vault-profile' && $method === 'GET') {
        AuthRoutes::getVaultProfile();
    }
    if ($path === '/api/auth/setup-vault' && $method === 'POST') {
        AuthRoutes::setupVault($body);
    }
    if ($path === '/api/auth/rewrap-master-key' && $method === 'POST') {
        AuthRoutes::rewrapMasterKey($body);
    }

    // ----------------------------------------------------
    // File Routes
    // ----------------------------------------------------
    if ($path === '/api/files' && $method === 'GET') {
        FileRoutes::list();
    }
    if ($path === '/api/files/init' && $method === 'POST') {
        FileRoutes::init($body);
    }

    // Pattern: /api/files/{fileId}/chunk/{idx} (POST)
    if (preg_match('#^/api/files/([a-zA-Z0-9\-]+)/chunk/([0-9]+)$#', $path, $m) && $method === 'POST') {
        FileRoutes::uploadChunk($m[1], (int)$m[2]);
    }

    // Pattern: /api/files/{fileId}/complete (POST)
    if (preg_match('#^/api/files/([a-zA-Z0-9\-]+)/complete$#', $path, $m) && $method === 'POST') {
        FileRoutes::complete($m[1]);
    }

    // Pattern: /api/files/{fileId}/chunk/{idx}/meta (GET)
    if (preg_match('#^/api/files/([a-zA-Z0-9\-]+)/chunk/([0-9]+)/meta$#', $path, $m) && $method === 'GET') {
        FileRoutes::getChunkMeta($m[1], (int)$m[2]);
    }

    // Pattern: /api/files/{fileId}/chunk/{idx}/data (GET)
    if (preg_match('#^/api/files/([a-zA-Z0-9\-]+)/chunk/([0-9]+)/data$#', $path, $m) && $method === 'GET') {
        FileRoutes::streamChunkData($m[1], (int)$m[2]);
    }

    // Pattern: /api/files/{fileId}/metadata (PATCH)
    if (preg_match('#^/api/files/([a-zA-Z0-9\-]+)/metadata$#', $path, $m) && $method === 'PATCH') {
        FileRoutes::updateMetadata($m[1], $body);
    }

    // Pattern: /api/files/{fileId} (DELETE)
    if (preg_match('#^/api/files/([a-zA-Z0-9\-]+)$#', $path, $m) && $method === 'DELETE') {
        FileRoutes::delete($m[1]);
    }

    // ----------------------------------------------------
    // Audit Routes
    // ----------------------------------------------------
    if ($path === '/api/audit' && $method === 'GET') {
        AuditRoutes::list();
    }
    if ($path === '/api/audit/verify' && $method === 'GET') {
        AuditRoutes::verify();
    }

    // ----------------------------------------------------
    // Admin Routes
    // ----------------------------------------------------
    if ($path === '/api/admin/users' && $method === 'GET') {
        AdminRoutes::listUsers();
    }
    if ($path === '/api/admin/stats' && $method === 'GET') {
        AdminRoutes::getStats();
    }
    if (preg_match('#^/api/admin/users/([a-zA-Z0-9\-]+)/quota$#', $path, $m) && $method === 'PATCH') {
        AdminRoutes::updateQuota($m[1], $body);
    }
    if (preg_match('#^/api/admin/users/([a-zA-Z0-9\-]+)/revoke$#', $path, $m) && $method === 'POST') {
        AdminRoutes::revokeUser($m[1]);
    }

    // Endpoint Not Found
    Response::error("Endpoint {$method} {$path} tidak ditemukan pada Secure Vault PHP API.", 404);

} catch (Throwable $e) {
    Response::error('Terjadi kesalahan internal pada peladen Secure Vault PHP: ' . $e->getMessage(), 500);
}
