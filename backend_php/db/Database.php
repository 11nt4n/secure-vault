<?php
// backend_php/db/Database.php

class Database
{
    private static ?Database $instance = null;
    private array $data;

    private function __construct()
    {
        $this->load();
    }

    public static function getInstance(): Database
    {
        if (self::$instance === null) {
            self::$instance = new Database();
        }
        return self::$instance;
    }

    public static function hashPassword(string $password): string
    {
        return hash('sha256', "sv_salt_{$password}");
    }

    public static function generateUuid(): string
    {
        $data = random_bytes(16);
        $data[6] = chr(ord($data[6]) & 0x0f | 0x40); // set version to 0100
        $data[8] = chr(ord($data[8]) & 0x3f | 0x80); // set bits 6-7 to 10
        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
    }

    private function load(): void
    {
        if (file_exists(DB_FILE)) {
            $raw = file_get_contents(DB_FILE);
            $parsed = json_decode($raw, true);
            if (is_array($parsed)) {
                $this->data = $parsed;
                return;
            }
        }

        // Try to copy from existing Node backend database if it exists
        $nodeDbFile = dirname(BASE_DIR) . DIRECTORY_SEPARATOR . 'backend' . DIRECTORY_SEPARATOR . 'data' . DIRECTORY_SEPARATOR . 'database.json';
        if (file_exists($nodeDbFile)) {
            $raw = file_get_contents($nodeDbFile);
            $parsed = json_decode($raw, true);
            if (is_array($parsed)) {
                $this->data = $parsed;
                $this->save();
                
                // Also copy existing chunks if available
                $nodeStorage = dirname(BASE_DIR) . DIRECTORY_SEPARATOR . 'backend' . DIRECTORY_SEPARATOR . 'storage';
                if (is_dir($nodeStorage)) {
                    $this->copyDirectory($nodeStorage, STORAGE_DIR);
                }
                return;
            }
        }

        // Default schema & seed
        $this->data = [
            'users' => [],
            'vault_profiles' => [],
            'encrypted_files' => [],
            'file_chunks' => [],
            'audit_logs' => []
        ];
        $this->seed();
        $this->save();
    }

    private function copyDirectory(string $src, string $dst): void
    {
        $dir = opendir($src);
        @mkdir($dst, 0755, true);
        while (($file = readdir($dir)) !== false) {
            if ($file !== '.' && $file !== '..') {
                if (is_dir($src . '/' . $file)) {
                    $this->copyDirectory($src . '/' . $file, $dst . '/' . $file);
                } else if (!file_exists($dst . '/' . $file)) {
                    copy($src . '/' . $file, $dst . '/' . $file);
                }
            }
        }
        closedir($dir);
    }

    private function seed(): void
    {
        $adminId = self::generateUuid();
        $userId = self::generateUuid();

        $this->data['users'][] = [
            'id' => $adminId,
            'username' => 'admin',
            'password_hash' => self::hashPassword('admin123'),
            'email' => 'admin.cert@bssn.go.id',
            'role' => 'admin',
            'is_active' => true,
            'storage_quota_bytes' => 10 * 1024 * 1024 * 1024, // 10 GB
            'storage_used_bytes' => 0,
            'created_at' => gmdate('Y-m-d\TH:i:s.000\Z')
        ];

        $this->data['users'][] = [
            'id' => $userId,
            'username' => 'user',
            'password_hash' => self::hashPassword('user123'),
            'email' => 'sandiman.evaluator@bssn.go.id',
            'role' => 'user',
            'is_active' => true,
            'storage_quota_bytes' => 5 * 1024 * 1024 * 1024, // 5 GB
            'storage_used_bytes' => 0,
            'created_at' => gmdate('Y-m-d\TH:i:s.000\Z')
        ];

        // Seed Genesis Audit Record
        $genesisPrev = '0000000000000000000000000000000000000000000000000000000000000000';
        $timestamp = gmdate('Y-m-d\TH:i:s.000\Z');
        $action = 'SYSTEM_GENESIS';
        $status = 'SUCCESS';
        $genesisUserId = 'SYSTEM_BOOTSTRAP';
        $payload = "{$genesisPrev}:{$timestamp}:{$genesisUserId}:{$action}::{$status}";
        $genesisHash = hash('sha256', $payload);

        $this->data['audit_logs'][] = [
            'id' => self::generateUuid(),
            'sequence_number' => 1,
            'timestamp' => $timestamp,
            'user_id' => $genesisUserId,
            'action_type' => $action,
            'file_id' => null,
            'ip_address' => '127.0.0.1',
            'user_agent' => 'SecureVault/Bootstrap',
            'status' => 'SUCCESS',
            'previous_hash' => $genesisPrev,
            'current_hash' => $genesisHash
        ];
    }

    public function save(): void
    {
        file_put_contents(
            DB_FILE,
            json_encode($this->data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
            LOCK_EX
        );
    }

    // Users
    public function getUsers(): array
    {
        return $this->data['users'];
    }

    public function getUserById(string $id): ?array
    {
        foreach ($this->data['users'] as $u) {
            if ($u['id'] === $id) return $u;
        }
        return null;
    }

    public function getUserByUsername(string $username): ?array
    {
        foreach ($this->data['users'] as $u) {
            if ($u['username'] === $username) return $u;
        }
        return null;
    }

    public function getUserByEmail(string $email): ?array
    {
        foreach ($this->data['users'] as $u) {
            if ($u['email'] === $email) return $u;
        }
        return null;
    }

    public function addUser(array $user): void
    {
        $this->data['users'][] = $user;
        $this->save();
    }

    public function updateUser(string $id, array $updates): void
    {
        foreach ($this->data['users'] as &$u) {
            if ($u['id'] === $id) {
                $u = array_merge($u, $updates);
                break;
            }
        }
        $this->save();
    }

    // Vault Profiles
    public function getVaultProfile(string $userId): ?array
    {
        foreach ($this->data['vault_profiles'] as $vp) {
            if ($vp['user_id'] === $userId) return $vp;
        }
        return null;
    }

    public function setVaultProfile(array $profile): void
    {
        $found = false;
        foreach ($this->data['vault_profiles'] as &$vp) {
            if ($vp['user_id'] === $profile['user_id']) {
                $vp = $profile;
                $found = true;
                break;
            }
        }
        if (!$found) {
            $this->data['vault_profiles'][] = $profile;
        }
        $this->save();
    }

    // Encrypted Files
    public function getFilesByOwner(string $ownerId): array
    {
        $res = [];
        foreach ($this->data['encrypted_files'] as $f) {
            if ($f['owner_id'] === $ownerId) {
                $res[] = $f;
            }
        }
        return $res;
    }

    public function getFileById(string $fileId): ?array
    {
        foreach ($this->data['encrypted_files'] as $f) {
            if ($f['id'] === $fileId) return $f;
        }
        return null;
    }

    public function addFile(array $file): void
    {
        $this->data['encrypted_files'][] = $file;
        $this->save();
    }

    public function updateFile(string $fileId, array $updates): void
    {
        foreach ($this->data['encrypted_files'] as &$f) {
            if ($f['id'] === $fileId) {
                $f = array_merge($f, $updates);
                break;
            }
        }
        $this->save();
    }

    public function deleteFile(string $fileId): void
    {
        $this->data['encrypted_files'] = array_values(array_filter(
            $this->data['encrypted_files'],
            fn($f) => $f['id'] !== $fileId
        ));
        $this->deleteFileChunks($fileId);
        $this->save();
    }

    // File Chunks
    public function getChunk(string $fileId, int $chunkIndex): ?array
    {
        foreach ($this->data['file_chunks'] as $c) {
            if ($c['file_id'] === $fileId && (int)$c['chunk_index'] === $chunkIndex) {
                return $c;
            }
        }
        return null;
    }

    public function saveChunk(array $chunk): void
    {
        $this->data['file_chunks'] = array_values(array_filter(
            $this->data['file_chunks'],
            fn($c) => !($c['file_id'] === $chunk['file_id'] && (int)$c['chunk_index'] === (int)$chunk['chunk_index'])
        ));
        $this->data['file_chunks'][] = $chunk;
        $this->save();
    }

    public function deleteFileChunks(string $fileId): void
    {
        $this->data['file_chunks'] = array_values(array_filter(
            $this->data['file_chunks'],
            fn($c) => $c['file_id'] !== $fileId
        ));
        $this->save();
    }

    // Audit Logs
    public function getAuditLogs(): array
    {
        return $this->data['audit_logs'];
    }

    public function addAuditLog(array $log): void
    {
        $this->data['audit_logs'][] = $log;
        $this->save();
    }
}
