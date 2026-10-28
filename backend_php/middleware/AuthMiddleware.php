<?php
// backend_php/middleware/AuthMiddleware.php

require_once __DIR__ . '/../config.php';
require_once __DIR__ . '/../utils/Jwt.php';
require_once __DIR__ . '/../utils/Response.php';
require_once __DIR__ . '/../db/Database.php';

class AuthMiddleware
{
    public static function authenticate(): array
    {
        $headers = self::getRequestHeaders();
        $authHeader = $headers['authorization'] ?? $headers['Authorization'] ?? '';

        if (!preg_match('/Bearer\s(\S+)/i', $authHeader, $matches)) {
            Response::error('Token autentikasi tidak ditemukan.', 401);
        }

        $token = $matches[1];
        $payload = Jwt::verify($token, JWT_SECRET);

        if (!$payload) {
            Response::error('Token sesi kedaluwarsa atau tidak valid. Silakan login kembali.', 401);
        }

        $db = Database::getInstance();
        $user = $db->getUserById($payload['id']);

        if (!$user || empty($user['is_active'])) {
            Response::error('Akun dinonaktifkan atau telah dicabut oleh administrator.', 401);
        }

        return $user;
    }

    public static function requireAdmin(array $user): void
    {
        if (($user['role'] ?? '') !== 'admin') {
            Response::error('Akses ditolak: Memerlukan wewenang Administrator.', 403);
        }
    }

    private static function getRequestHeaders(): array
    {
        if (function_exists('apache_request_headers')) {
            $headers = apache_request_headers();
            if ($headers !== false) {
                return $headers;
            }
        }

        $headers = [];
        foreach ($_SERVER as $key => $value) {
            if (str_starts_with($key, 'HTTP_')) {
                $name = str_replace('_', '-', substr($key, 5));
                $headers[$name] = $value;
                $headers[strtolower($name)] = $value;
            }
        }

        if (isset($_SERVER['CONTENT_TYPE'])) {
            $headers['content-type'] = $_SERVER['CONTENT_TYPE'];
        }
        if (isset($_SERVER['CONTENT_LENGTH'])) {
            $headers['content-length'] = $_SERVER['CONTENT_LENGTH'];
        }
        if (isset($_SERVER['REDIRECT_HTTP_AUTHORIZATION'])) {
            $headers['authorization'] = $_SERVER['REDIRECT_HTTP_AUTHORIZATION'];
        }

        return $headers;
    }
}
