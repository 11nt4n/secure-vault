<?php
// backend_php/routes/AdminRoutes.php

require_once __DIR__ . '/../config.php';
require_once __DIR__ . '/../db/Database.php';
require_once __DIR__ . '/../utils/Response.php';
require_once __DIR__ . '/../utils/Audit.php';
require_once __DIR__ . '/../middleware/AuthMiddleware.php';

class AdminRoutes
{
    public static function listUsers(): void
    {
        $admin = AuthMiddleware::authenticate();
        AuthMiddleware::requireAdmin($admin);

        $db = Database::getInstance();
        $users = $db->getUsers();

        $sanitized = array_map(function ($u) {
            return [
                'id' => $u['id'],
                'username' => $u['username'],
                'email' => $u['email'],
                'role' => $u['role'],
                'storage_quota_bytes' => $u['storage_quota_bytes'],
                'storage_used_bytes' => $u['storage_used_bytes'],
                'is_active' => (bool)$u['is_active'],
                'created_at' => $u['created_at'],
            ];
        }, $users);

        Response::json(['users' => $sanitized]);
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

        if ($targetUser['id'] === $admin['id']) {
            Response::error('Administrator tidak dapat mencabut sesi dirinya sendiri.', 400);
        }

        // Revoke current bearer tokens without silently disabling the account.
        $db->updateUser($targetUserId, [
            'session_version' => (int)($targetUser['session_version'] ?? 0) + 1,
        ]);

        Audit::logEvent($admin['id'], 'ADMIN_REVOKE_USER_SESSION', null, null, null, 'SUCCESS');

        Response::json(['message' => 'Sesi aktif pengguna berhasil dicabut.']);
    }
}
