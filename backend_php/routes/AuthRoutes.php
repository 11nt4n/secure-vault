<?php
// backend_php/routes/AuthRoutes.php

require_once __DIR__ . '/../config.php';
require_once __DIR__ . '/../db/Database.php';
require_once __DIR__ . '/../utils/Jwt.php';
require_once __DIR__ . '/../utils/Response.php';
require_once __DIR__ . '/../utils/Audit.php';
require_once __DIR__ . '/../middleware/AuthMiddleware.php';

class AuthRoutes
{
    private static function getMfaTokens(): array
    {
        $file = DATA_DIR . DIRECTORY_SEPARATOR . 'mfa_tokens.json';
        if (!file_exists($file)) return [];
        $raw = file_get_contents($file);
        $data = json_decode($raw, true);
        if (!is_array($data)) return [];

        // Prune expired
        $now = time();
        $valid = [];
        foreach ($data as $token => $val) {
            if (($val['expiresAt'] ?? 0) > $now) {
                $valid[$token] = $val;
            }
        }
        return $valid;
    }

    private static function saveMfaToken(string $token, string $userId): void
    {
        $file = DATA_DIR . DIRECTORY_SEPARATOR . 'mfa_tokens.json';
        $tokens = self::getMfaTokens();
        $tokens[$token] = [
            'userId' => $userId,
            'expiresAt' => time() + 300 // 5 minutes
        ];
        file_put_contents($file, json_encode($tokens), LOCK_EX);
    }

    private static function consumeMfaToken(string $token): ?string
    {
        $file = DATA_DIR . DIRECTORY_SEPARATOR . 'mfa_tokens.json';
        $tokens = self::getMfaTokens();
        if (!isset($tokens[$token])) {
            return null;
        }
        $userId = $tokens[$token]['userId'];
        unset($tokens[$token]);
        file_put_contents($file, json_encode($tokens), LOCK_EX);
        return $userId;
    }

    public static function register(array $body): void
    {
        $username = trim($body['username'] ?? '');
        $password = trim($body['password'] ?? '');
        $email = trim($body['email'] ?? '');
        $role = ($body['role'] ?? '') === 'admin' ? 'admin' : 'user';

        if (!$username || !$password || !$email) {
            Response::error('Username, password, dan email wajib diisi.', 400);
        }

        $db = Database::getInstance();
        if ($db->getUserByUsername($username) || $db->getUserByEmail($email)) {
            Response::error('Username atau email sudah terdaftar.', 409);
        }

        $newUser = [
            'id' => Database::generateUuid(),
            'username' => $username,
            'password_hash' => Database::hashPassword($password),
            'email' => $email,
            'role' => $role,
            'is_active' => true,
            'storage_quota_bytes' => 5 * 1024 * 1024 * 1024,
            'storage_used_bytes' => 0,
            'created_at' => gmdate('Y-m-d\TH:i:s.000\Z')
        ];

        $db->addUser($newUser);

        Audit::logEvent($newUser['id'], 'USER_REGISTER', null, null, null, 'SUCCESS');

        Response::json([
            'message' => 'Registrasi berhasil.',
            'user' => [
                'id' => $newUser['id'],
                'username' => $newUser['username'],
                'email' => $newUser['email'],
                'role' => $newUser['role'],
            ]
        ], 201);
    }

    public static function login(array $body): void
    {
        $username = trim($body['username'] ?? '');
        $password = trim($body['password'] ?? '');

        $db = Database::getInstance();
        $user = $db->getUserByUsername($username);

        if (!$user || $user['password_hash'] !== Database::hashPassword($password)) {
            Audit::logEvent(
                $user ? $user['id'] : 'UNKNOWN_USER',
                'AUTH_LOGIN_FAILED',
                null,
                null,
                null,
                'FAILED'
            );
            Response::error('Username atau password salah.', 401);
        }

        if (empty($user['is_active'])) {
            Response::error('Akun Anda dinonaktifkan oleh administrator.', 403);
        }

        // Issue MFA challenge (24 bytes hex)
        $mfaToken = bin2hex(random_bytes(24));
        self::saveMfaToken($mfaToken, $user['id']);

        Audit::logEvent($user['id'], 'AUTH_CREDENTIALS_VERIFIED', null, null, null, 'SUCCESS');

        Response::json([
            'mfaRequired' => true,
            'mfaToken' => $mfaToken,
            'user' => [
                'id' => $user['id'],
                'username' => $user['username'],
                'email' => $user['email'],
                'role' => $user['role'],
            ]
        ]);
    }

    public static function verifyMfa(array $body): void
    {
        $mfaToken = trim($body['mfaToken'] ?? '');
        $code = trim($body['code'] ?? '');

        $userId = self::consumeMfaToken($mfaToken);
        if (!$userId) {
            Response::error('Tantangan MFA kedaluwarsa. Silakan login ulang.', 400);
        }

        // Code '123456' accepted per demo specification
        if ($code !== '123456') {
            Audit::logEvent($userId, 'AUTH_MFA_FAILED', null, null, null, 'FAILED');
            Response::error('Kode TOTP salah! Gunakan kode demo: 123456', 400);
        }

        $db = Database::getInstance();
        $user = $db->getUserById($userId);
        if (!$user) {
            Response::error('Pengguna tidak ditemukan.', 404);
        }

        // Issue 15-minute JWT token
        $token = Jwt::sign([
            'id' => $user['id'],
            'username' => $user['username'],
            'email' => $user['email'],
            'role' => $user['role'],
        ], JWT_SECRET, 900); // 15 mins

        Audit::logEvent($user['id'], 'AUTH_MFA_SUCCESS', null, null, null, 'SUCCESS');

        Response::json([
            'token' => $token,
            'user' => [
                'id' => $user['id'],
                'username' => $user['username'],
                'email' => $user['email'],
                'role' => $user['role'],
                'storageQuotaBytes' => $user['storage_quota_bytes'],
                'storageUsedBytes' => $user['storage_used_bytes'],
            ]
        ]);
    }

    public static function me(): void
    {
        $user = AuthMiddleware::authenticate();
        Response::json([
            'user' => [
                'id' => $user['id'],
                'username' => $user['username'],
                'email' => $user['email'],
                'role' => $user['role'],
                'storageQuotaBytes' => $user['storage_quota_bytes'],
                'storageUsedBytes' => $user['storage_used_bytes'],
            ]
        ]);
    }

    public static function getVaultProfile(): void
    {
        $user = AuthMiddleware::authenticate();
        $db = Database::getInstance();
        $profile = $db->getVaultProfile($user['id']);

        if (!$profile) {
            Response::json(['hasProfile' => false]);
        }

        Response::json([
            'hasProfile' => true,
            'argon2Salt' => $profile['argon2_salt'],
            'wrappedMasterKey' => $profile['wrapped_master_key'],
            'verifierCiphertext' => $profile['verifier_ciphertext'],
            'verifierIv' => $profile['verifier_iv'],
            'verifierWrappedDek' => $profile['verifier_wrapped_dek'],
        ]);
    }

    public static function setupVault(array $body): void
    {
        $user = AuthMiddleware::authenticate();
        $argon2Salt = $body['argon2Salt'] ?? null;
        $wrappedMasterKey = $body['wrappedMasterKey'] ?? null;
        $verifierCiphertext = $body['verifierCiphertext'] ?? null;
        $verifierIv = $body['verifierIv'] ?? null;
        $verifierWrappedDek = $body['verifierWrappedDek'] ?? null;

        if (!$argon2Salt || !$wrappedMasterKey || !$verifierCiphertext || !$verifierIv || !$verifierWrappedDek) {
            Response::error('Parameter konfigurasi brankas tidak lengkap.', 400);
        }

        $db = Database::getInstance();
        if ($db->getVaultProfile($user['id'])) {
            Response::error('Brankas sudah pernah diinisialisasi sebelumnya.', 409);
        }

        $newProfile = [
            'user_id' => $user['id'],
            'argon2_salt' => $argon2Salt,
            'wrapped_master_key' => $wrappedMasterKey,
            'verifier_ciphertext' => $verifierCiphertext,
            'verifier_iv' => $verifierIv,
            'verifier_wrapped_dek' => $verifierWrappedDek,
            'created_at' => gmdate('Y-m-d\TH:i:s.000\Z'),
            'updated_at' => gmdate('Y-m-d\TH:i:s.000\Z')
        ];

        $db->setVaultProfile($newProfile);

        Audit::logEvent($user['id'], 'VAULT_SETUP', null, null, null, 'SUCCESS');

        Response::json(['message' => 'Brankas Zero-Knowledge berhasil diinisialisasi.']);
    }

    public static function rewrapMasterKey(array $body): void
    {
        $user = AuthMiddleware::authenticate();
        $argon2Salt = $body['argon2Salt'] ?? null;
        $wrappedMasterKey = $body['wrappedMasterKey'] ?? null;
        $verifierCiphertext = $body['verifierCiphertext'] ?? null;
        $verifierIv = $body['verifierIv'] ?? null;
        $verifierWrappedDek = $body['verifierWrappedDek'] ?? null;

        $db = Database::getInstance();
        $profile = $db->getVaultProfile($user['id']);

        if (!$profile) {
            Response::error('Profil brankas tidak ditemukan.', 404);
        }

        $profile['argon2_salt'] = $argon2Salt;
        $profile['wrapped_master_key'] = $wrappedMasterKey;
        $profile['verifier_ciphertext'] = $verifierCiphertext;
        $profile['verifier_iv'] = $verifierIv;
        $profile['verifier_wrapped_dek'] = $verifierWrappedDek;
        $profile['updated_at'] = gmdate('Y-m-d\TH:i:s.000\Z');

        $db->setVaultProfile($profile);

        Audit::logEvent($user['id'], 'VAULT_REWRAP_MK', null, null, null, 'SUCCESS');

        Response::json(['message' => 'Passphrase berhasil diperbarui dan Master Key berhasil di-wrap ulang.']);
    }
}
