<?php
// backend_php/routes/AuthRoutes.php

require_once __DIR__ . '/../config.php';
require_once __DIR__ . '/../db/Database.php';
require_once __DIR__ . '/../utils/Jwt.php';
require_once __DIR__ . '/../utils/Response.php';
require_once __DIR__ . '/../utils/Audit.php';
require_once __DIR__ . '/../utils/Totp.php';
require_once __DIR__ . '/../utils/SmtpMailer.php';
require_once __DIR__ . '/../utils/Activation.php';
require_once __DIR__ . '/../middleware/AuthMiddleware.php';

class AuthRoutes
{
    private const LOGIN_MAX_ATTEMPTS = 5;
    private const MFA_MAX_ATTEMPTS = 5;
    private const AUTH_WINDOW_SECONDS = 900;
    private const MFA_CHALLENGE_TTL_SECONDS = 1200;
    private const ONBOARDING_TTL_SECONDS = 600;

    private static function requestIp(): string
    {
        return (string)($_SERVER['REMOTE_ADDR'] ?? 'unknown');
    }

    private static function throttleKey(string $scope, string $subject): string
    {
        return hash('sha256', $scope . "\0" . strtolower($subject) . "\0" . self::requestIp());
    }

    private static function validVaultMaterial($salt, $wrappedMasterKey, $verifierCiphertext, $verifierIv, $verifierWrappedDek): bool
    {
        $decode = static function ($value, int $length): bool {
            if (!is_string($value) || $value === '' || strlen($value) > 16384) return false;
            $decoded = base64_decode($value, true);
            return is_string($decoded) && strlen($decoded) === $length && base64_encode($decoded) === $value;
        };
        return $decode($salt, 16) && $decode($wrappedMasterKey, 40)
            && $decode($verifierIv, 12) && $decode($verifierWrappedDek, 40)
            && $decode($verifierCiphertext, 16 + strlen('SECURE_VAULT_PASS_VERIFIER_V1'));
    }
    private static function mfaTokenFile(): string
    {
        return DATA_DIR . DIRECTORY_SEPARATOR . 'mfa_tokens.json';
    }

    /** Serialize MFA challenge state transitions across PHP workers. */
    private static function withMfaTokenLock(callable $callback)
    {
        $lockPath = self::mfaTokenFile() . '.lock';
        $lock = fopen($lockPath, 'c');
        if ($lock === false) {
            throw new RuntimeException('Unable to open MFA challenge lock.');
        }
        @chmod($lockPath, 0600);
        if (!flock($lock, LOCK_EX)) {
            fclose($lock);
            throw new RuntimeException('Unable to lock MFA challenge state.');
        }
        try {
            return $callback();
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }

    /** Caller must hold withMfaTokenLock(). */
    private static function readMfaTokensUnlocked(): array
    {
        $file = self::mfaTokenFile();
        if (!is_file($file)) return [];
        $raw = file_get_contents($file);
        $data = json_decode(is_string($raw) ? $raw : '', true);
        if (!is_array($data)) return [];

        $now = time();
        $valid = [];
        foreach ($data as $token => $val) {
            if (is_array($val) && (int)($val['expiresAt'] ?? 0) > $now && (int)($val['attempts'] ?? 0) < 5) {
                $valid[$token] = $val;
            }
        }
        return $valid;
    }

    /** Caller must hold withMfaTokenLock(). */
    private static function writeMfaTokensUnlocked(array $tokens): void
    {
        $file = self::mfaTokenFile();
        $temporaryFile = $file . '.tmp.' . bin2hex(random_bytes(8));
        $json = json_encode($tokens);
        if (!is_string($json) || file_put_contents($temporaryFile, $json, LOCK_EX) === false) {
            @unlink($temporaryFile);
            throw new RuntimeException('Unable to save MFA challenge state.');
        }
        @chmod($temporaryFile, 0600);
        if (!rename($temporaryFile, $file)) {
            @unlink($temporaryFile);
            throw new RuntimeException('Unable to update MFA challenge state.');
        }
        @chmod($file, 0600);
    }

    private static function getMfaTokens(): array
    {
        return self::withMfaTokenLock(static fn() => self::readMfaTokensUnlocked());
    }

    private static function saveMfaToken(string $token, string $userId): void
    {
        self::withMfaTokenLock(static function () use ($token, $userId): void {
            $tokens = self::readMfaTokensUnlocked();
            $tokens[$token] = [
                'userId' => $userId,
                'expiresAt' => time() + self::MFA_CHALLENGE_TTL_SECONDS,
                'attempts' => 0
            ];
            self::writeMfaTokensUnlocked($tokens);
        });
    }

    private static function getMfaTokenUserId(string $token): ?string
    {
        if ($token === '' || !preg_match('/^[a-f0-9]{48}$/', $token)) {
            return null;
        }
        return self::withMfaTokenLock(static function () use ($token): ?string {
            $tokens = self::readMfaTokensUnlocked();
            return isset($tokens[$token]['userId']) ? (string)$tokens[$token]['userId'] : null;
        });
    }

    private static function recordMfaFailure(string $token): void
    {
        self::withMfaTokenLock(static function () use ($token): void {
            $tokens = self::readMfaTokensUnlocked();
            if (!isset($tokens[$token])) return;
            $tokens[$token]['attempts'] = (int)($tokens[$token]['attempts'] ?? 0) + 1;
            if ($tokens[$token]['attempts'] >= 5) {
                unset($tokens[$token]);
            }
            self::writeMfaTokensUnlocked($tokens);
        });
    }

    private static function consumeMfaToken(string $token): ?string
    {
        return self::withMfaTokenLock(static function () use ($token): ?string {
            $tokens = self::readMfaTokensUnlocked();
            if (!isset($tokens[$token])) {
                return null;
            }
            $userId = (string)$tokens[$token]['userId'];
            unset($tokens[$token]);
            self::writeMfaTokensUnlocked($tokens);
            return $userId;
        });
    }

    private static function publicUser(array $user): array
    {
        return [
            'id' => $user['id'],
            'username' => $user['username'],
            'email' => $user['email'],
            'role' => $user['role'],
            'mfaEnabled' => !empty($user['mfa_secret_encrypted']),
            'storageQuotaBytes' => $user['storage_quota_bytes'],
            'storageUsedBytes' => $user['storage_used_bytes'],
        ];
    }

    private static function issueSession(array $user): void
    {
        $token = Jwt::sign([
            'id' => $user['id'],
            'username' => $user['username'],
            'email' => $user['email'],
            'role' => $user['role'],
            'sv' => (int)($user['session_version'] ?? 0),
        ], JWT_SECRET, JWT_TTL_SECONDS);

        Audit::logEvent($user['id'], 'AUTH_MFA_SUCCESS', null, null, null, 'SUCCESS');
        Response::json(['token' => $token, 'user' => self::publicUser($user)]);
    }

    public static function login(array $body): void
    {
        $username = trim((string)($body['username'] ?? ''));
        $password = (string)($body['password'] ?? '');

        $db = Database::getInstance();
        $loginThrottleKey = self::throttleKey('login', $username);
        if ($db->isRateLimited($loginThrottleKey, self::LOGIN_MAX_ATTEMPTS, self::AUTH_WINDOW_SECONDS)) {
            Response::error('Terlalu banyak percobaan login. Coba kembali setelah 15 menit.', 429);
        }
        $user = $db->getUserByUsername($username);

        if (!$user || !Database::verifyPassword($password, (string)($user['password_hash'] ?? ''))) {
            $db->recordRateLimitFailure($loginThrottleKey, self::AUTH_WINDOW_SECONDS);
            Audit::logEvent($user ? $user['id'] : 'UNKNOWN_USER', 'AUTH_LOGIN_FAILED', null, null, null, 'FAILED');
            Response::error('Username atau password salah.', 401);
        }
        $db->clearRateLimit($loginThrottleKey);

        // Upgrade legacy SHA-256 hashes after a successful password check.
        if (Database::isLegacyPasswordHash((string)$user['password_hash'])) {
            $newHash = Database::hashPassword($password);
            $db->updateUser($user['id'], ['password_hash' => $newHash]);
            $user = $db->getUserById($user['id']) ?? $user;
        }

        if (!empty($user['onboarding_pending'])) {
            self::startOnboarding($db, $user);
        }
        if (empty($user['is_active'])) {
            Response::error('Akun Anda dinonaktifkan oleh administrator.', 403);
        }

        $mfaToken = bin2hex(random_bytes(24));
        self::saveMfaToken($mfaToken, $user['id']);
        Audit::logEvent($user['id'], 'AUTH_CREDENTIALS_VERIFIED', null, null, null, 'SUCCESS');

        Response::json([
            'mfaRequired' => true,
            'mfaSetupRequired' => empty($user['mfa_secret_encrypted']),
            'mfaToken' => $mfaToken,
            'user' => [
                'id' => $user['id'],
                'username' => $user['username'],
                'email' => $user['email'],
                'role' => $user['role'],
            ]
        ]);
    }

    private static function startOnboarding(Database $db, array $user): void
    {
        $now = time();
        if (!empty($user['email_verified_at'])) {
            $passwordToken = bin2hex(random_bytes(32));
            $db->updateUser((string)$user['id'], [
                'onboarding_password_token_hash' => hash('sha256', $passwordToken),
                'onboarding_password_expires_at' => $now + self::ONBOARDING_TTL_SECONDS,
            ]);
            Response::json([
                'onboardingRequired' => true,
                'passwordToken' => $passwordToken,
                'message' => 'Email sudah terverifikasi. Buat kata sandi baru.',
            ]);
        }
        $challenge = bin2hex(random_bytes(32));
        $hasValidCode = !empty($user['onboarding_code_hash'])
            && (int)($user['onboarding_expires_at'] ?? 0) > $now
            && (int)($user['onboarding_attempts'] ?? 0) < 5;
        $updates = [
            'onboarding_challenge_hash' => hash('sha256', $challenge),
            'onboarding_password_token_hash' => null,
            'onboarding_password_expires_at' => null,
        ];
        if (!$hasValidCode) {
            if ($now - (int)($user['onboarding_sent_at'] ?? 0) < 60) {
                Response::error('Kode baru dapat dikirim setelah 1 menit. Periksa email Anda.', 429);
            }
            $code = (string)random_int(10000000, 99999999);
            try {
                SmtpMailer::sendVerificationCode((string)$user['email'], $code, (string)$user['username']);
            } catch (Throwable $e) {
                error_log('[Secure Vault] Onboarding email delivery failed: ' . $e->getMessage());
                Response::error('Email verifikasi belum dapat dikirim. Hubungi administrator untuk memeriksa konfigurasi SMTP.', 503);
            }
            $updates['onboarding_code_hash'] = hash_hmac('sha256', $code, JWT_SECRET);
            $updates['onboarding_expires_at'] = $now + self::ONBOARDING_TTL_SECONDS;
            $updates['onboarding_sent_at'] = $now;
            $updates['onboarding_attempts'] = 0;
        }
        $db->updateUser((string)$user['id'], $updates);
        if (!$hasValidCode) Audit::logEvent((string)$user['id'], 'AUTH_EMAIL_CODE_SENT', null, null, null, 'SUCCESS');
        $email = (string)$user['email'];
        $at = strrpos($email, '@');
        Response::json([
            'onboardingRequired' => true,
            'challenge' => $challenge,
            'emailHint' => substr($email, 0, 1) . '***' . substr($email, $at),
            'message' => 'Kode verifikasi telah dikirim ke email terdaftar.',
        ]);
    }

    public static function verifyOnboardingEmail(array $body): void
    {
        $username = trim((string)($body['username'] ?? ''));
        $challenge = (string)($body['challenge'] ?? '');
        $code = (string)($body['code'] ?? '');
        if (!preg_match('/^[a-f0-9]{64}$/', $challenge) || !preg_match('/^[0-9]{8}$/', $code)) {
            Response::error('Kode verifikasi tidak valid atau kedaluwarsa.', 400);
        }
        $db = Database::getInstance();
        $user = $db->getUserByUsername($username);
        if (!$user || empty($user['onboarding_pending']) || (int)($user['onboarding_expires_at'] ?? 0) < time()
            || (int)($user['onboarding_attempts'] ?? 0) >= 5
            || !hash_equals((string)($user['onboarding_challenge_hash'] ?? ''), hash('sha256', $challenge))) {
            Response::error('Kode verifikasi tidak valid atau kedaluwarsa. Masuk kembali untuk meminta kode baru.', 400);
        }
        if (!hash_equals((string)($user['onboarding_code_hash'] ?? ''), hash_hmac('sha256', $code, JWT_SECRET))) {
            $db->updateUser((string)$user['id'], ['onboarding_attempts' => (int)($user['onboarding_attempts'] ?? 0) + 1]);
            Audit::logEvent((string)$user['id'], 'AUTH_EMAIL_VERIFY_FAILED', null, null, null, 'FAILED');
            Response::error('Kode verifikasi salah atau kedaluwarsa.', 400);
        }
        $passwordToken = bin2hex(random_bytes(32));
        $db->updateUser((string)$user['id'], [
            'onboarding_challenge_hash' => null,
            'onboarding_code_hash' => null,
            'email_verified_at' => gmdate('Y-m-d\TH:i:s.000\Z'),
            'onboarding_password_token_hash' => hash('sha256', $passwordToken),
            'onboarding_password_expires_at' => time() + self::ONBOARDING_TTL_SECONDS,
        ]);
        Audit::logEvent((string)$user['id'], 'AUTH_EMAIL_VERIFIED', null, null, null, 'SUCCESS');
        Response::json(['passwordToken' => $passwordToken, 'message' => 'Email terverifikasi. Buat kata sandi baru.']);
    }

    public static function activateAccount(array $body): void
    {
        $userId = (string)($body['userId'] ?? '');
        $token = (string)($body['token'] ?? '');
        $password = (string)($body['newPassword'] ?? '');
        if (!preg_match('/^[a-f0-9-]{36}$/i', $userId) || !preg_match('/^[a-f0-9]{64}$/', $token)) {
            Response::error('Tautan aktivasi tidak valid atau sudah kedaluwarsa.', 400);
        }
        if (strlen($password) < 12 || strlen($password) > 1024) {
            Response::error('Kata sandi baru harus 12–1024 karakter.', 400);
        }
        $db = Database::getInstance();
        $throttleKey = self::throttleKey('activation', $userId);
        if ($db->isRateLimited($throttleKey, self::LOGIN_MAX_ATTEMPTS, self::AUTH_WINDOW_SECONDS)) {
            Response::error('Terlalu banyak percobaan aktivasi. Coba kembali setelah 15 menit.', 429);
        }
        $user = $db->getUserById($userId);
        if (!$user || empty($user['onboarding_pending']) || !empty($user['is_active'])
            || (int)($user['activation_expires_at'] ?? 0) < time()
            || !hash_equals((string)($user['activation_token_hash'] ?? ''), Activation::tokenHash($token))) {
            $db->recordRateLimitFailure($throttleKey, self::AUTH_WINDOW_SECONDS);
            Response::error('Tautan aktivasi tidak valid atau sudah kedaluwarsa. Minta admin mengirim ulang tautan.', 400);
        }
        $db->transaction(function (Database $tx) use ($user, $password): void {
            $tx->updateUser((string)$user['id'], [
                'password_hash' => Database::hashPassword($password),
                'role' => 'user',
                'is_active' => true,
                'onboarding_pending' => false,
                'email_verified_at' => gmdate('Y-m-d\TH:i:s.000\Z'),
                'activation_token_hash' => null,
                'activation_expires_at' => null,
                'onboarding_code_hash' => null,
                'onboarding_challenge_hash' => null,
                'onboarding_password_token_hash' => null,
                'session_version' => (int)($user['session_version'] ?? 0) + 1,
            ]);
            Audit::logEvent((string)$user['id'], 'AUTH_EMAIL_VERIFIED');
            Audit::logEvent((string)$user['id'], 'AUTH_ONBOARDING_COMPLETE');
        });
        $db->clearRateLimit($throttleKey);
        Response::json(['message' => 'Akun aktif. Masuk dengan kata sandi baru untuk melanjutkan ke OTP.']);
    }

    public static function completeOnboarding(array $body): void
    {
        $username = trim((string)($body['username'] ?? ''));
        $token = (string)($body['passwordToken'] ?? '');
        $password = (string)($body['newPassword'] ?? '');
        if (!preg_match('/^[a-f0-9]{64}$/', $token)) Response::error('Sesi aktivasi tidak valid.', 400);
        if (strlen($password) < 12 || strlen($password) > 1024) {
            Response::error('Kata sandi baru harus 12–1024 karakter.', 400);
        }
        $db = Database::getInstance();
        $user = $db->getUserByUsername($username);
        if (!$user || empty($user['onboarding_pending']) || (int)($user['onboarding_password_expires_at'] ?? 0) < time()
            || !hash_equals((string)($user['onboarding_password_token_hash'] ?? ''), hash('sha256', $token))) {
            Response::error('Sesi aktivasi kedaluwarsa. Masuk kembali dengan kata sandi sementara.', 400);
        }
        if (Database::verifyPassword($password, (string)$user['password_hash'])) {
            Response::error('Kata sandi baru harus berbeda dari kata sandi sementara.', 400);
        }
        $db->updateUser((string)$user['id'], [
            'password_hash' => Database::hashPassword($password),
            'is_active' => true,
            'onboarding_pending' => false,
            'onboarding_challenge_hash' => null,
            'onboarding_code_hash' => null,
            'onboarding_password_token_hash' => null,
            'onboarding_expires_at' => null,
            'onboarding_password_expires_at' => null,
            'onboarding_attempts' => null,
            'session_version' => (int)($user['session_version'] ?? 0) + 1,
        ]);
        Audit::logEvent((string)$user['id'], 'AUTH_ONBOARDING_COMPLETE', null, null, null, 'SUCCESS');
        Response::json(['message' => 'Akun aktif. Masuk dengan kata sandi baru Anda.']);
    }

    public static function setupMfa(array $body): void
    {
        $mfaToken = trim((string)($body['mfaToken'] ?? ''));
        $userId = self::getMfaTokenUserId($mfaToken);
        if (!$userId) {
            Response::error('Tantangan autentikasi kedaluwarsa. Silakan login ulang.', 400);
        }

        $db = Database::getInstance();
        $user = $db->getUserById($userId);
        if (!$user || empty($user['is_active'])) {
            Response::error('Akun tidak tersedia.', 403);
        }
        if (!empty($user['mfa_secret_encrypted'])) {
            Response::error('MFA sudah diaktifkan untuk akun ini.', 409);
        }

        $pending = (string)($user['mfa_secret_pending_encrypted'] ?? '');
        $secret = $pending !== '' ? Totp::decryptSecret($pending, $userId) : null;
        if (!is_string($secret) || $secret === '') {
            $secret = Totp::generateSecret();
            $pending = Totp::encryptSecret($secret, $userId);
            $db->updateUser($userId, ['mfa_secret_pending_encrypted' => $pending]);
        }

        Response::json([
            'secret' => $secret,
            'otpauthUri' => Totp::provisioningUri($secret, (string)$user['username']),
            'issuer' => 'Secure Vault',
            'message' => 'Tambahkan secret ini ke aplikasi authenticator, lalu masukkan kode 6 digit untuk mengaktifkannya.'
        ]);
    }

    public static function verifyMfa(array $body): void
    {
        $mfaToken = trim((string)($body['mfaToken'] ?? ''));
        $code = trim((string)($body['code'] ?? ''));
        $userId = self::getMfaTokenUserId($mfaToken);
        if (!$userId) {
            Response::error('Tantangan MFA kedaluwarsa atau terkunci. Silakan login ulang.', 400);
        }

        $db = Database::getInstance();
        $user = $db->getUserById($userId);
        if (!$user || empty($user['is_active'])) {
            Response::error('Akun tidak tersedia.', 403);
        }

        $mfaThrottleKey = self::throttleKey('mfa', $userId);
        if ($db->isRateLimited($mfaThrottleKey, self::MFA_MAX_ATTEMPTS, self::AUTH_WINDOW_SECONDS)) {
            Response::error('Terlalu banyak percobaan MFA. Coba kembali setelah 15 menit.', 429);
        }

        $isEnrollment = empty($user['mfa_secret_encrypted']);
        $encryptedSecret = $isEnrollment
            ? (string)($user['mfa_secret_pending_encrypted'] ?? '')
            : (string)$user['mfa_secret_encrypted'];
        $secret = $encryptedSecret !== '' ? Totp::decryptSecret($encryptedSecret, $userId) : null;
        if (!is_string($secret) || $secret === '') {
            Response::error('Pengaturan MFA belum dimulai. Silakan login ulang.', 400);
        }

        $matchedCounter = Totp::matchingCounter($secret, $code);
        $lastAcceptedCounter = isset($user['mfa_last_counter']) ? (int)$user['mfa_last_counter'] : -1;
        if ($matchedCounter === null || (!$isEnrollment && $matchedCounter <= $lastAcceptedCounter)) {
            $db->recordRateLimitFailure($mfaThrottleKey, self::AUTH_WINDOW_SECONDS);
            self::recordMfaFailure($mfaToken);
            Audit::logEvent($userId, 'AUTH_MFA_FAILED', null, null, null, 'FAILED');
            Response::error('Kode autentikator tidak valid atau sudah pernah digunakan. Periksa waktu perangkat dan coba lagi.', 400);
        }
        $db->clearRateLimit($mfaThrottleKey);

        $consumedUserId = self::consumeMfaToken($mfaToken);
        if ($consumedUserId !== $userId) {
            Response::error('Tantangan MFA sudah digunakan atau kedaluwarsa. Silakan login ulang.', 400);
        }

        $updates = ['mfa_last_counter' => $matchedCounter];
        if ($isEnrollment) {
            // Activate only after possession of the TOTP secret has been proven.
            $updates['mfa_secret_encrypted'] = $encryptedSecret;
            $updates['mfa_secret_pending_encrypted'] = null;
            $updates['mfa_enabled_at'] = gmdate('Y-m-d\\TH:i:s.000\\Z');
        }
        $db->updateUser($userId, $updates);
        if ($isEnrollment) {
            Audit::logEvent($userId, 'AUTH_MFA_ENROLLED', null, null, null, 'SUCCESS');
        }
        $user = $db->getUserById($userId) ?? $user;
        self::issueSession($user);
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
                'mfaEnabled' => !empty($user['mfa_secret_encrypted']),
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

        if (!self::validVaultMaterial($argon2Salt, $wrappedMasterKey, $verifierCiphertext, $verifierIv, $verifierWrappedDek)) {
            Response::error('Material kriptografis konfigurasi brankas tidak valid.', 400);
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

        if (!self::validVaultMaterial($argon2Salt, $wrappedMasterKey, $verifierCiphertext, $verifierIv, $verifierWrappedDek)) {
            Response::error('Material kriptografis untuk re-wrap tidak valid.', 400);
        }

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

    public static function logout(): void
    {
        $user = AuthMiddleware::authenticate();
        $db = Database::getInstance();
        $db->updateUser($user['id'], [
            'session_version' => (int)($user['session_version'] ?? 0) + 1,
        ]);
        Audit::logEvent($user['id'], 'AUTH_LOGOUT', null, null, null, 'SUCCESS');
        Response::json(['message' => 'Sesi berhasil dicabut.']);
    }
}
