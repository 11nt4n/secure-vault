<?php
// backend_php/utils/Response.php

class Response
{
    public static function handleCors(): void
    {
        $origin = $_SERVER['HTTP_ORIGIN'] ?? '';
        header('Vary: Origin');
        header('X-Content-Type-Options: nosniff');
        header('X-Frame-Options: DENY');
        header('Referrer-Policy: no-referrer');
        header('Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()');
        // API responses never need active content. The frontend must set its own
        // CSP at the reverse proxy/static-host layer.
        header("Content-Security-Policy: default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'");
        header('Cache-Control: no-store');

        // HSTS is only valid over HTTPS. Enable it explicitly in a TLS deployment.
        if (getenv('SECURE_VAULT_ENABLE_HSTS') === '1') {
            header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
        }

        if ($origin !== '' && in_array($origin, CORS_ALLOWED_ORIGINS, true)) {
            header("Access-Control-Allow-Origin: {$origin}");
            header('Access-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE, OPTIONS');
            header('Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With');
            header('Access-Control-Expose-Headers: X-Secure-Vault-Token');
        }

        if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'OPTIONS') {
            http_response_code(204);
            exit();
        }
    }

    public static function json($data, int $statusCode = 200): void
    {
        http_response_code($statusCode);
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        exit();
    }

    public static function error(string $message, int $statusCode = 400): void
    {
        self::json(['error' => $message], $statusCode);
    }

    public static function streamBinary(string $filePath): void
    {
        if (!file_exists($filePath)) {
            self::error('File tidak ditemukan di storage server.', 404);
        }

        header('Content-Type: application/octet-stream');
        header('Content-Length: ' . filesize($filePath));
        header('Content-Disposition: attachment; filename="' . basename($filePath) . '"');
        readfile($filePath);
        exit();
    }
}
