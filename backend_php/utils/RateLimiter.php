<?php
// backend_php/utils/RateLimiter.php
// Fixed-window limiter with lockout, persisted in SQLite (brute-force protection, FIA_AFL.1).

require_once __DIR__ . '/../db/Database.php';

class RateLimiter
{
    /** Returns seconds remaining if locked, otherwise 0. */
    public static function lockedFor(string $key): int
    {
        $row = Database::getInstance()->getRateLimit($key);
        if (!$row) return 0;
        $remaining = (int)$row['locked_until'] - time();
        return $remaining > 0 ? $remaining : 0;
    }

    /** Registers a failure; returns true if the key is now locked. */
    public static function hit(string $key, int $maxAttempts, int $windowSeconds, int $lockSeconds): bool
    {
        $db = Database::getInstance();
        $now = time();
        $row = $db->getRateLimit($key);
        $attempts = 1;
        $windowStart = $now;
        if ($row && ((int)$row['window_start'] + $windowSeconds) > $now) {
            $attempts = (int)$row['attempts'] + 1;
            $windowStart = (int)$row['window_start'];
        }
        $lockedUntil = $attempts >= $maxAttempts ? $now + $lockSeconds : 0;
        $db->setRateLimit($key, $attempts, $windowStart, $lockedUntil);
        return $lockedUntil > 0;
    }

    public static function clear(string $key): void
    {
        Database::getInstance()->clearRateLimit($key);
    }

    public static function clientIp(): string
    {
        // Only trust X-Forwarded-For when explicitly behind a trusted proxy
        if (Env::bool('TRUST_PROXY', false) && !empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $parts = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
            $ip = trim($parts[0]);
            if (filter_var($ip, FILTER_VALIDATE_IP)) return $ip;
        }
        return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    }
}
