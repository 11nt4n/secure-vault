<?php
require_once __DIR__ . '/SmtpMailer.php';

class Activation
{
    public const TTL_SECONDS = 86400;

    public static function newToken(): string
    {
        return bin2hex(random_bytes(32));
    }

    public static function tokenHash(string $token): string
    {
        return hash_hmac('sha256', $token, JWT_SECRET);
    }

    public static function send(array $user, string $token): void
    {
        $base = rtrim(trim((string)(getenv('SECURE_VAULT_APP_URL') ?: 'http://127.0.0.1:5173')), '/');
        $parts = parse_url($base);
        if (!is_array($parts)) {
            throw new RuntimeException('SECURE_VAULT_APP_URL tidak valid.');
        }
        $scheme = strtolower((string)($parts['scheme'] ?? ''));
        $host = strtolower((string)($parts['host'] ?? ''));
        if (!filter_var($base, FILTER_VALIDATE_URL) || isset($parts['query']) || isset($parts['fragment'])
            || ($scheme !== 'https' && !($scheme === 'http' && in_array($host, ['localhost', '127.0.0.1', '::1'], true)))) {
            throw new RuntimeException('SECURE_VAULT_APP_URL harus URL HTTPS, atau HTTP localhost untuk pengembangan.');
        }
        $link = $base . '/#activate=' . rawurlencode((string)$user['id']) . '.' . $token . '.' . rawurlencode((string)$user['username']);
        SmtpMailer::sendActivationLink((string)$user['email'], $link, (string)$user['username']);
    }
}
