<?php
// Minimal HS256 JWT implementation with strict header and claim validation.

class Jwt
{
    private static function base64UrlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    private static function base64UrlDecode(string $data): string|false
    {
        if ($data === '' || preg_match('/[^A-Za-z0-9_\-]/', $data)) {
            return false;
        }
        $padded = strtr($data, '-_', '+/');
        $padded .= str_repeat('=', (4 - strlen($padded) % 4) % 4);
        return base64_decode($padded, true);
    }

    public static function sign(array $payload, string $secret, int $expiresInSeconds = 900): string
    {
        if (strlen($secret) < 32) {
            throw new InvalidArgumentException('JWT signing key must be at least 32 bytes.');
        }
        $header = ['alg' => 'HS256', 'typ' => 'JWT'];
        $now = time();
        $payload['iat'] = $now;
        $payload['exp'] = $now + max(1, $expiresInSeconds);

        $headerJson = json_encode($header, JSON_UNESCAPED_SLASHES);
        $payloadJson = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if ($headerJson === false || $payloadJson === false) {
            throw new RuntimeException('Unable to encode JWT.');
        }

        $encodedHeader = self::base64UrlEncode($headerJson);
        $encodedPayload = self::base64UrlEncode($payloadJson);
        $signature = hash_hmac('sha256', "{$encodedHeader}.{$encodedPayload}", $secret, true);
        return "{$encodedHeader}.{$encodedPayload}." . self::base64UrlEncode($signature);
    }

    public static function verify(string $token, string $secret): ?array
    {
        if (strlen($secret) < 32 || strlen($token) > 8192) {
            return null;
        }
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            return null;
        }
        [$encodedHeader, $encodedPayload, $encodedSignature] = $parts;
        $headerJson = self::base64UrlDecode($encodedHeader);
        $payloadJson = self::base64UrlDecode($encodedPayload);
        $signature = self::base64UrlDecode($encodedSignature);
        if (!is_string($headerJson) || !is_string($payloadJson) || !is_string($signature)) {
            return null;
        }

        $header = json_decode($headerJson, true);
        $payload = json_decode($payloadJson, true);
        if (!is_array($header) || ($header['alg'] ?? null) !== 'HS256' || ($header['typ'] ?? null) !== 'JWT') {
            return null;
        }
        if (!is_array($payload) || !isset($payload['id'], $payload['iat'], $payload['exp'])) {
            return null;
        }
        if (!is_string($payload['id']) || !is_numeric($payload['iat']) || !is_numeric($payload['exp'])) {
            return null;
        }

        $expected = hash_hmac('sha256', "{$encodedHeader}.{$encodedPayload}", $secret, true);
        if (!hash_equals($expected, $signature)) {
            return null;
        }

        $now = time();
        if ((int)$payload['exp'] <= $now || (int)$payload['iat'] > $now + 60 || (int)$payload['exp'] <= (int)$payload['iat']) {
            return null;
        }
        if (isset($payload['nbf']) && (!is_numeric($payload['nbf']) || (int)$payload['nbf'] > $now)) {
            return null;
        }
        return $payload;
    }
}
