<?php
// backend_php/utils/Jwt.php

class Jwt
{
    private static function base64UrlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    private static function base64UrlDecode(string $data): string
    {
        return base64_decode(strtr($data, '-_', '+/'));
    }

    /**
     * Sign a JWT token with HMAC-SHA256
     */
    public static function sign(array $payload, string $secret, int $expiresInSeconds = 900): string
    {
        $header = ['alg' => 'HS256', 'typ' => 'JWT'];
        
        $payload['iat'] = time();
        $payload['exp'] = time() + $expiresInSeconds;

        $encodedHeader = self::base64UrlEncode(json_encode($header));
        $encodedPayload = self::base64UrlEncode(json_encode($payload));

        $signature = hash_hmac('sha256', "{$encodedHeader}.{$encodedPayload}", $secret, true);
        $encodedSignature = self::base64UrlEncode($signature);

        return "{$encodedHeader}.{$encodedPayload}.{$encodedSignature}";
    }

    /**
     * Verify and decode a JWT token
     */
    public static function verify(string $token, string $secret): ?array
    {
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            return null;
        }

        [$encodedHeader, $encodedPayload, $encodedSignature] = $parts;

        $expectedSig = hash_hmac('sha256', "{$encodedHeader}.{$encodedPayload}", $secret, true);
        $expectedEncodedSig = self::base64UrlEncode($expectedSig);

        if (!hash_equals($expectedEncodedSig, $encodedSignature)) {
            return null; // Invalid signature
        }

        $payload = json_decode(self::base64UrlDecode($encodedPayload), true);
        if (!$payload || !is_array($payload)) {
            return null;
        }

        if (isset($payload['exp']) && $payload['exp'] < time()) {
            return null; // Expired
        }

        return $payload;
    }
}
