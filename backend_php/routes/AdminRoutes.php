<?php
// backend_php/routes/AdminRoutes.php

require_once __DIR__ . '/../config.php';
require_once __DIR__ . '/../db/Database.php';
require_once __DIR__ . '/../utils/Response.php';
require_once __DIR__ . '/../utils/Audit.php';
require_once __DIR__ . '/../utils/SmtpMailer.php';
require_once __DIR__ . '/../utils/Activation.php';
require_once __DIR__ . '/../middleware/AuthMiddleware.php';

class AdminRoutes
{
    public static function createUser(array $body): void
    {
        $admin = AuthMiddleware::authenticate();
        AuthMiddleware::requireAdmin($admin);
        $username = trim((string)($body['username'] ?? ''));
        $email = strtolower(trim((string)($body['email'] ?? '')));
        if (!preg_match('/^[A-Za-z0-9_.-]{3,64}$/', $username) || strlen($email) > 254
            || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
            Response::error('Username (3–64 huruf/angka) atau email tidak valid.', 400);
        }
        $db = Database::getInstance();
        foreach ($db->getUsers() as $existing) {
            if (strcasecmp((string)$existing['username'], $username) === 0
                || strcasecmp((string)$existing['email'], $email) === 0) {
                Response::error('Username atau email sudah terdaftar.', 409);
            }
        }
        $activationToken = Activation::newToken();
        $now = time();
        $user = [
            'id' => Database::generateUuid(),
            'username' => $username,
            'email' => $email,
            'password_hash' => Database::hashPassword(bin2hex(random_bytes(32))),
            'role' => 'user',
            'is_active' => false,
            'onboarding_pending' => true,
            'email_verified_at' => null,
            'activation_token_hash' => Activation::tokenHash($activationToken),
            'activation_expires_at' => $now + Activation::TTL_SECONDS,
            'activation_sent_at' => $now,
            'storage_quota_bytes' => 5 * 1024 * 1024 * 1024,
            'storage_used_bytes' => 0,
            'mfa_secret_encrypted' => null,
            'mfa_secret_pending_encrypted' => null,
            'session_version' => 0,
            'created_at' => gmdate('Y-m-d\TH:i:s.000\Z'),
        ];
        try {
            Activation::send($user, $activationToken);
        } catch (Throwable $e) {
            error_log('[Secure Vault] Initial verification email delivery failed: ' . $e->getMessage());
            $detail = $e instanceof RuntimeException ? $e->getMessage() : 'Periksa log server dan konfigurasi SMTP.';
            Response::error('Akun belum dibuat karena email gagal dikirim. ' . $detail, 503);
        }
        $db->addUser($user);
        Audit::logEvent($admin['id'], 'ADMIN_CREATE_USER', null, null, null, 'SUCCESS');
        Audit::logEvent($user['id'], 'AUTH_ACTIVATION_LINK_SENT', null, null, null, 'SUCCESS');
        Response::json([
            'message' => 'Akun dibuat. Tautan aktivasi untuk membuat kata sandi dikirim ke email pengguna.',
            'username' => $username,
        ], 201);
    }

    public static function listUsers(): void
    {
        $admin = AuthMiddleware::authenticate();
        AuthMiddleware::requireAdmin($admin);

        $db = Database::getInstance();
        $users = $db->getUsers();
        usort($users, static function (array $left, array $right): int {
            $leftAdmin = ($left['role'] ?? '') === 'admin';
            $rightAdmin = ($right['role'] ?? '') === 'admin';
            if ($leftAdmin !== $rightAdmin) return $leftAdmin ? -1 : 1;
            return strcasecmp((string)$left['username'], (string)$right['username']);
        });

        $sanitized = array_map(function ($u) {
            return [
                'id' => $u['id'],
                'username' => $u['username'],
                'email' => $u['email'],
                'role' => $u['role'],
                'storage_quota_bytes' => $u['storage_quota_bytes'],
                'storage_used_bytes' => $u['storage_used_bytes'],
                'is_active' => (bool)$u['is_active'],
                'onboarding_pending' => !empty($u['onboarding_pending']),
                'email_verified_at' => $u['email_verified_at'] ?? null,
                'created_at' => $u['created_at'],
            ];
        }, $users);

        Response::json(['users' => $sanitized]);
    }

    public static function resendVerificationCode(string $targetUserId): void
    {
        $admin = AuthMiddleware::authenticate();
        AuthMiddleware::requireAdmin($admin);

        $db = Database::getInstance();
        $user = $db->getUserById($targetUserId);
        if (!$user) Response::error('Pengguna tidak ditemukan.', 404);
        if (($user['role'] ?? '') === 'admin') Response::error('Akun administrator tidak dapat diubah.', 403);
        if (empty($user['onboarding_pending']) || !empty($user['email_verified_at'])) {
            Response::error('Akun ini tidak menunggu verifikasi email.', 409);
        }
        $now = time();
        if ($now - (int)($user['activation_sent_at'] ?? $user['onboarding_sent_at'] ?? 0) < 60) {
            Response::error('Tunggu 1 menit sebelum mengirim ulang tautan.', 429);
        }

        $token = Activation::newToken();
        try {
            Activation::send($user, $token);
        } catch (Throwable $e) {
            error_log('[Secure Vault] Activation link resend failed: ' . $e->getMessage());
            Response::error('Tautan belum dikirim. Periksa konfigurasi SMTP lalu coba lagi.', 503);
        }
        $db->transaction(function (Database $tx) use ($admin, $user, $token, $now): void {
            $tx->updateUser((string)$user['id'], [
                'password_hash' => Database::hashPassword(bin2hex(random_bytes(32))),
                'activation_token_hash' => Activation::tokenHash($token),
                'activation_expires_at' => $now + Activation::TTL_SECONDS,
                'activation_sent_at' => $now,
                'onboarding_code_hash' => null,
                'onboarding_challenge_hash' => null,
                'onboarding_password_token_hash' => null,
            ]);
            Audit::logEvent((string)$admin['id'], 'ADMIN_RESEND_ACTIVATION_LINK', null, null, null, 'SUCCESS',
                'target_user_id=' . $user['id']);
        });
        Response::json(['message' => 'Tautan aktivasi baru diterima server email. Minta pengguna memeriksa Kotak Masuk dan Spam.']);
    }

    public static function getStats(): void
    {
        $admin = AuthMiddleware::authenticate();
        AuthMiddleware::requireAdmin($admin);

        $db = Database::getInstance();
        $users = $db->getUsers();
        $logs = $db->getAuditLogs();
        
        $allFiles = [];
        foreach ($users as $u) {
            $allFiles = array_merge($allFiles, $db->getFilesByOwner($u['id']));
        }

        $totalUsers = count($users);
        $totalFiles = count($allFiles);
        // Sum stored ciphertext chunk lengths (including each AES-GCM tag), not plaintext file sizes.
        $totalBytes = 0;
        foreach ($allFiles as $file) {
            foreach ($db->getChunksByFile((string)$file['id']) as $chunk) {
                $totalBytes += max(0, (int)($chunk['chunk_size_bytes'] ?? 0));
            }
        }
        $chainCheck = Audit::verifyChain();

        Response::json([
            'stats' => [
                'totalUsers' => $totalUsers,
                'totalFiles' => $totalFiles,
                'totalCiphertextBytes' => $totalBytes,
                'auditChainLength' => count($logs),
                'chainIntegrity' => $chainCheck['isValid']
            ]
        ]);
    }

    public static function updateQuota(string $targetUserId, array $body): void
    {
        $admin = AuthMiddleware::authenticate();
        AuthMiddleware::requireAdmin($admin);

        $quota = $body['storageQuotaBytes'] ?? null;
        if (!is_int($quota) || $quota < 1 || $quota > 5497558138880) {
            Response::error('storageQuotaBytes harus bilangan bulat antara 1 byte dan 5 TiB.', 400);
        }

        $db = Database::getInstance();
        $targetUser = $db->getUserById($targetUserId);
        if (!$targetUser) {
            Response::error('Pengguna tidak ditemukan.', 404);
        }
        if (($targetUser['role'] ?? '') === 'admin') Response::error('Akun administrator tidak dapat diubah.', 403);
        if ($quota < (int)$targetUser['storage_used_bytes']) {
            Response::error('Kuota baru tidak boleh lebih kecil daripada penggunaan penyimpanan saat ini.', 409);
        }

        $db->updateUser($targetUserId, ['storage_quota_bytes' => $quota]);
        Audit::logEvent($admin['id'], 'ADMIN_UPDATE_QUOTA', null, null, null, 'SUCCESS',
            "target_user_id={$targetUserId};quota_bytes={$quota}");

        Response::json(['message' => 'Alokasi kuota pengguna berhasil diperbarui.']);
    }

    public static function revokeUser(string $targetUserId): void
    {
        $admin = AuthMiddleware::authenticate();
        AuthMiddleware::requireAdmin($admin);

        $db = Database::getInstance();
        $targetUser = $db->getUserById($targetUserId);
        if (!$targetUser) {
            Response::error('Pengguna tidak ditemukan.', 404);
        }
        if (($targetUser['role'] ?? '') === 'admin') Response::error('Akun administrator tidak dapat diubah.', 403);
        if (empty($targetUser['is_active'])) {
            Response::error('Akun pengguna sudah tidak aktif.', 409);
        }

        // Keep the account and its files, but block login and all existing sessions.
        $db->updateUser($targetUserId, [
            'is_active' => false,
            'session_version' => (int)($targetUser['session_version'] ?? 0) + 1,
        ]);

        Audit::logEvent($admin['id'], 'ADMIN_ACCOUNT_DEACTIVATED', null, null, null, 'SUCCESS',
            "target_user_id={$targetUserId}");

        Response::json(['message' => 'Akun dinonaktifkan dan seluruh sesinya dicabut.']);
    }

    public static function reactivateUser(string $targetUserId): void
    {
        $admin = AuthMiddleware::authenticate();
        AuthMiddleware::requireAdmin($admin);

        $db = Database::getInstance();
        $targetUser = $db->getUserById($targetUserId);
        if (!$targetUser) {
            Response::error('Pengguna tidak ditemukan.', 404);
        }
        if (($targetUser['role'] ?? '') === 'admin') Response::error('Akun administrator tidak dapat diubah.', 403);
        if (!empty($targetUser['onboarding_pending'])) {
            Response::error('Akun ini harus menyelesaikan verifikasi email dan penggantian kata sandi terlebih dahulu.', 409);
        }
        if (!empty($targetUser['is_active'])) {
            Response::error('Akun pengguna sudah aktif.', 409);
        }

        $db->updateUser($targetUserId, ['is_active' => true]);
        Audit::logEvent($admin['id'], 'ADMIN_ACCOUNT_REACTIVATED', null, null, null, 'SUCCESS',
            "target_user_id={$targetUserId}");

        Response::json(['message' => 'Akun diaktifkan kembali. Pengguna dapat masuk dengan sesi baru.']);
    }

    public static function deleteUser(string $targetUserId, array $body): void
    {
        $admin = AuthMiddleware::authenticate();
        AuthMiddleware::requireAdmin($admin);

        $db = Database::getInstance();
        $target = $db->getUserById($targetUserId);
        if (!$target) Response::error('Pengguna tidak ditemukan.', 404);
        if (($target['role'] ?? '') === 'admin') Response::error('Akun administrator tidak dapat diubah.', 403);
        if (!empty($target['is_active'])) Response::error('Nonaktifkan akun terlebih dahulu sebelum menghapusnya.', 409);
        if (($body['confirmUsername'] ?? null) !== $target['username']) {
            Response::error('Konfirmasi username tidak cocok.', 400);
        }

        $entries = array_merge($db->getFilesByOwner($targetUserId, true), $db->getFoldersByOwner($targetUserId));
        foreach ($entries as $entry) {
            if (($entry['kind'] ?? 'file') === 'folder') continue;
            self::removeStoredFile((string)$entry['id']);
        }

        $fileCount = count(array_filter($entries, fn($entry) => ($entry['kind'] ?? 'file') !== 'folder'));
        $db->transaction(function (Database $tx) use ($admin, $targetUserId, $fileCount): void {
            $tx->deleteUserAndOwnedData($targetUserId);
            Audit::logEvent($admin['id'], 'ADMIN_DELETE_USER', null, null, null, 'SUCCESS',
                "target_user_id={$targetUserId};deleted_files={$fileCount}");
        });
        Response::json(['message' => 'Akun dan seluruh data brankas miliknya berhasil dihapus.']);
    }

    private static function removeStoredFile(string $fileId): void
    {
        if (!preg_match('/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i', $fileId)) {
            Response::error('ID berkas tidak valid; penghapusan akun dibatalkan.', 500);
        }
        $path = STORAGE_DIR . DIRECTORY_SEPARATOR . $fileId;
        if (is_link($path) || is_file($path)) {
            if (!@unlink($path)) Response::error('Pembersihan berkas gagal. Akun belum dihapus; periksa izin storage lalu coba lagi.', 500);
            return;
        }
        if (!is_dir($path)) return;
        $items = scandir($path);
        if (!is_array($items)) Response::error('Direktori berkas tidak dapat dibaca. Akun belum dihapus.', 500);
        foreach ($items as $item) {
            if ($item === '.' || $item === '..') continue;
            $child = $path . DIRECTORY_SEPARATOR . $item;
            if (is_dir($child) && !is_link($child)) {
                Response::error('Ada subdirektori tidak dikenal di storage. Akun belum dihapus.', 500);
            }
            if (!@unlink($child)) Response::error('Pembersihan berkas gagal. Akun belum dihapus; periksa izin storage lalu coba lagi.', 500);
        }
        if (!@rmdir($path)) Response::error('Pembersihan direktori gagal. Akun belum dihapus; coba lagi.', 500);
    }
}
