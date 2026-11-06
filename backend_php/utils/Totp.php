<?php
require_once __DIR__ . '/../config.php';

class Totp
{
    private const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    public static function generateSecret(int $bytes = 20): string
    {
        return self::base32Encode(random_bytes($bytes));
    }

    public static function provisioningUri(string $secret, string $username): string
    {
        $issuer = 'Secure Vault';
        $label = rawurlencode($issuer . ':' . $username);
        return 'otpauth://totp/' . $label . '?secret=' . rawurlencode($secret)
            . '&issuer=' . rawurlencode($issuer) . '&algorithm=SHA1&digits=6&period=30';
    }

    public static function verify(string $secret, string $code, ?int $time = null, int $window = 1): bool
    {
        return self::matchingCounter($secret, $code, $time, $window) !== null;
    }

    /** Return the matched 30-second counter so callers can prevent TOTP replay. */
    public static function matchingCounter(string $secret, string $code, ?int $time = null, int $window = 1): ?int
    {
        if (!preg_match('/^\d{6}$/', $code)) {
            return null;
        }
        $key = self::base32Decode($secret);
        if ($key === false || strlen($key) < 10) {
            return null;
        }
        $counter = intdiv($time ?? time(), 30);
        $range = max(0, $window);
        for ($offset = -$range; $offset <= $range; $offset++) {
            $step = $counter + $offset;
            if ($step < 0) continue;
            $candidate = self::hotp($key, $step);
            if (hash_equals($candidate, $code)) {
                return $step;
            }
        }
        return null;
    }

    public static function encryptSecret(string $secret, string $userId): string
    {
        $iv = random_bytes(12);
        $tag = '';
        $ciphertext = openssl_encrypt($secret, 'aes-256-gcm', MFA_ENCRYPTION_KEY, OPENSSL_RAW_DATA, $iv, $tag, $userId, 16);
        if (!is_string($ciphertext) || strlen($tag) !== 16) {
            throw new RuntimeException('Unable to protect MFA secret at rest.');
        }
        return base64_encode($iv . $tag . $ciphertext);
    }

    public static function decryptSecret(string $packed, string $userId): ?string
    {
        $raw = base64_decode($packed, true);
        if (!is_string($raw) || strlen($raw) < 29) {
            return null;
        }
        $iv = substr($raw, 0, 12);
        $tag = substr($raw, 12, 16);
        $ciphertext = substr($raw, 28);
        $plaintext = openssl_decrypt($ciphertext, 'aes-256-gcm', MFA_ENCRYPTION_KEY, OPENSSL_RAW_DATA, $iv, $tag, $userId);
        return is_string($plaintext) ? $plaintext : null;
    }

    private static function hotp(string $key, int $counter): string
    {
        $high = intdiv($counter, 0x100000000);
        $low = $counter % 0x100000000;
        $digest = hash_hmac('sha1', pack('N2', $high, $low), $key, true);
        $offset = ord($digest[19]) & 0x0f;
        $binary = ((ord($digest[$offset]) & 0x7f) << 24)
            | ((ord($digest[$offset + 1]) & 0xff) << 16)
            | ((ord($digest[$offset + 2]) & 0xff) << 8)
            | (ord($digest[$offset + 3]) & 0xff);
        return str_pad((string)($binary % 1000000), 6, '0', STR_PAD_LEFT);
    }

    private static function base32Encode(string $data): string
    {
        $bits = '';
        foreach (str_split($data) as $char) {
            $bits .= str_pad(decbin(ord($char)), 8, '0', STR_PAD_LEFT);
        }
        $output = '';
        foreach (str_split($bits, 5) as $chunk) {
            if (strlen($chunk) < 5) {
                $chunk = str_pad($chunk, 5, '0', STR_PAD_RIGHT);
            }
            $output .= self::BASE32_ALPHABET[bindec($chunk)];
        }
        return $output;
    }

    private static function base32Decode(string $data): string|false
    {
        $data = strtoupper(rtrim($data, '='));
        if ($data === '' || preg_match('/[^A-Z2-7]/', $data)) {
            return false;
        }
        $bits = '';
        foreach (str_split($data) as $char) {
            $index = strpos(self::BASE32_ALPHABET, $char);
            if ($index === false) {
                return false;
            }
            $bits .= str_pad(decbin($index), 5, '0', STR_PAD_LEFT);
        }
        $output = '';
        foreach (str_split($bits, 8) as $chunk) {
            if (strlen($chunk) === 8) {
                $output .= chr(bindec($chunk));
            }
        }
        return $output;
    }
}
