<?php
// backend_php/db/Database.php

class Database
{
    private static ?Database $instance = null;
    private array $data;
    private PDO $pdo;
    /** @var resource|null Serializes the request snapshot to avoid stale concurrent writes. */
    private $lockHandle = null;
    private int $transactionDepth = 0;
    private bool $transactionDirty = false;
    /** Last committed row snapshot; used to persist only changed records. */
    private array $baselineRows = [];

    private function __construct()
    {
        $lock = fopen(DB_LOCK_FILE, 'c');
        if ($lock === false || !flock($lock, LOCK_EX)) {
            if (is_resource($lock)) fclose($lock);
            throw new RuntimeException('Unable to acquire SQLite runtime lock.');
        }
        @chmod(DB_LOCK_FILE, 0600);
        $this->lockHandle = $lock;
        if (!extension_loaded('pdo_sqlite')) {
            throw new RuntimeException('Ekstensi PHP pdo_sqlite wajib diaktifkan untuk Secure Vault.');
        }
        $this->pdo = new PDO('sqlite:' . DB_FILE, null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
        $this->pdo->exec('PRAGMA journal_mode=WAL');
        $this->pdo->exec('PRAGMA synchronous=FULL');
        $this->pdo->exec('PRAGMA foreign_keys=ON');
        $this->migrateRelationalSchema();
        @chmod(DB_FILE, 0600);
        $this->load();
    }

    public function __destruct()
    {
        if (is_resource($this->lockHandle)) {
            flock($this->lockHandle, LOCK_UN);
            fclose($this->lockHandle);
        }
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
        $algo = defined('PASSWORD_ARGON2ID') ? PASSWORD_ARGON2ID : PASSWORD_DEFAULT;
        $hash = password_hash($password, $algo);
        if (!is_string($hash)) {
            throw new RuntimeException('Unable to hash password securely.');
        }
        return $hash;
    }

    public static function verifyPassword(string $password, string $storedHash): bool
    {
        // Temporary compatibility for data migrated from the former SHA-256 scheme.
        // Successful legacy logins are re-hashed with a password-hashing algorithm.
        if (preg_match('/^[a-f0-9]{64}$/i', $storedHash)) {
            return hash_equals(hash('sha256', "sv_salt_{$password}"), strtolower($storedHash));
        }
        return password_verify($password, $storedHash);
    }

    public static function isLegacyPasswordHash(string $storedHash): bool
    {
        return (bool)preg_match('/^[a-f0-9]{64}$/i', $storedHash);
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
        $collections = ['users', 'vault_profiles', 'encrypted_files', 'file_chunks', 'audit_logs', 'auth_rate_limits'];
        $this->data = array_fill_keys($collections, []);

        $tableByCollection = [
            'users' => 'users',
            'vault_profiles' => 'vault_profiles',
            'encrypted_files' => 'encrypted_files',
            'file_chunks' => 'file_chunks',
            'audit_logs' => 'audit_logs',
            'auth_rate_limits' => 'auth_rate_limits',
        ];
        foreach ($tableByCollection as $collection => $table) {
            $orderBy = $collection === 'auth_rate_limits' ? 'record_key' : 'rowid';
            $stmt = $this->pdo->query("SELECT record_key, payload FROM {$table} ORDER BY {$orderBy}");
            while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
                $record = json_decode((string)$row['payload'], true);
                if (!is_array($record)) {
                    throw new RuntimeException("SQLite table {$table} contains an invalid record.");
                }
                if ($collection === 'auth_rate_limits') {
                    $this->data[$collection][(string)$row['record_key']] = $record;
                } else {
                    $this->data[$collection][] = $record;
                }
            }
        }

        $hasData = false;
        foreach ($collections as $collection) {
            if (count($this->data[$collection]) > 0) { $hasData = true; break; }
        }
        if (!$hasData && is_file(LEGACY_JSON_DB_FILE)) {
            $raw = file_get_contents(LEGACY_JSON_DB_FILE);
            $legacy = is_string($raw) ? json_decode($raw, true) : null;
            if (!is_array($legacy)) throw new RuntimeException('Database JSON lama tidak valid; migrasi dibatalkan tanpa menghapus sumber.');
            foreach (['users','vault_profiles','encrypted_files','file_chunks','audit_logs'] as $required) {
                if (!isset($legacy[$required]) || !is_array($legacy[$required])) throw new RuntimeException("Koleksi JSON '{$required}' tidak valid.");
            }
            foreach ($collections as $collection) $this->data[$collection] = $legacy[$collection] ?? [];
            $this->save();
            // Keep the original JSON as a backup. It is never deleted automatically.
        }
        if (!$hasData && !is_file(LEGACY_JSON_DB_FILE)) {
            $this->seed();
            $this->save();
        }

        // Remove historic plaintext fingerprints from active runtime records.
        // The migration also strips these values when importing vault_records.
        $removedLegacyFingerprints = false;
        foreach ($this->data['encrypted_files'] as &$file) {
            if (array_key_exists('plaintext_sha256', $file)) {
                unset($file['plaintext_sha256']);
                $removedLegacyFingerprints = true;
            }
        }
        unset($file);
        if ($removedLegacyFingerprints) $this->save();
        $this->baselineRows = $this->serializeRows($this->data);
    }

    /** Upgrade the former generic JSON-record table to dedicated relational tables. */
    private function migrateRelationalSchema(): void
    {
        $version = (int)$this->pdo->query('PRAGMA user_version')->fetchColumn();
        if ($version > 2) {
            throw new RuntimeException('Database schema is newer than this Secure Vault build.');
        }
        if ($version === 2) return;

        $legacyTableExists = (bool)$this->pdo->query(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='vault_records'"
        )->fetchColumn();

        $schemaPath = __DIR__ . DIRECTORY_SEPARATOR . 'schema_sqlite.sql';
        $schemaSql = is_file($schemaPath) ? file_get_contents($schemaPath) : false;
        if (!is_string($schemaSql) || trim($schemaSql) === '') {
            throw new RuntimeException('SQLite relational schema file is missing or empty.');
        }

        // Preserve a consistent pre-migration database image before touching the
        // legacy table. The backup stays in the private data directory for operator
        // verification/retention and is never deleted automatically.
        if ($legacyTableExists) {
            $legacyCount = (int)$this->pdo->query('SELECT COUNT(*) FROM vault_records')->fetchColumn();
            if ($legacyCount > 0) $this->createRelationalMigrationBackup();
        }

        $this->pdo->beginTransaction();
        try {
            $this->pdo->exec($schemaSql);

            if ($legacyTableExists) {
                $typedCount = 0;
                foreach (['users','vault_profiles','encrypted_files','file_chunks','audit_logs','auth_rate_limits'] as $table) {
                    $typedCount += (int)$this->pdo->query("SELECT COUNT(*) FROM {$table}")->fetchColumn();
                }
                $legacyCount = (int)$this->pdo->query('SELECT COUNT(*) FROM vault_records')->fetchColumn();
                if ($typedCount > 0 && $legacyCount > 0) {
                    throw new RuntimeException('Ambiguous database state: both legacy and relational tables contain records.');
                }

                if ($legacyCount > 0) {
                    $legacyRows = $this->pdo->query(
                        "SELECT collection, record_key, payload FROM vault_records ORDER BY CASE collection WHEN 'users' THEN 1 WHEN 'vault_profiles' THEN 2 WHEN 'encrypted_files' THEN 3 WHEN 'file_chunks' THEN 4 WHEN 'audit_logs' THEN 5 WHEN 'auth_rate_limits' THEN 6 ELSE 99 END, rowid"
                    )->fetchAll(PDO::FETCH_ASSOC);
                    foreach ($legacyRows as $row) {
                        $collection = (string)$row['collection'];
                        $record = json_decode((string)$row['payload'], true);
                        if (!is_array($record) || !in_array($collection, [
                            'users','vault_profiles','encrypted_files','file_chunks','audit_logs','auth_rate_limits'
                        ], true)) {
                            throw new RuntimeException('Legacy vault_records contains an invalid collection or payload.');
                        }
                        if ($collection === 'encrypted_files') unset($record['plaintext_sha256']);
                        $key = (string)$row['record_key'];
                        $this->upsertRelationalRecord($collection, $key, $record);
                    }
                }
                // The typed tables are now authoritative. Drop the duplicate legacy
                // table only after every row has migrated inside this same transaction.
                $this->pdo->exec('DROP TABLE vault_records');
            }

            $this->pdo->exec('PRAGMA user_version = 2');
            $this->pdo->commit();
        } catch (Throwable $e) {
            if ($this->pdo->inTransaction()) $this->pdo->rollBack();
            throw $e;
        }
    }

    /** Create a consistent private SQLite snapshot before the V2 schema migration. */
    private function createRelationalMigrationBackup(): void
    {
        $backupPath = DATA_DIR . DIRECTORY_SEPARATOR
            . 'secure-vault.pre-relational-v2.' . gmdate('Ymd\THis\Z') . '.'
            . bin2hex(random_bytes(4)) . '.sqlite';
        $escaped = str_replace("'", "''", $backupPath);
        $this->pdo->exec("VACUUM INTO '{$escaped}'");
        @chmod($backupPath, 0600);
        if (!is_file($backupPath)) {
            throw new RuntimeException('Pre-migration SQLite backup was not created.');
        }
        $backup = new PDO('sqlite:' . $backupPath, null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
        $integrity = $backup->query('PRAGMA integrity_check')->fetchColumn();
        $foreignKeyViolations = $backup->query('PRAGMA foreign_key_check')->fetchAll(PDO::FETCH_ASSOC);
        if ($integrity !== 'ok' || count($foreignKeyViolations) > 0) {
            @unlink($backupPath);
            throw new RuntimeException('Pre-migration SQLite backup failed integrity or foreign-key validation.');
        }
    }

    /**
     * Group related in-memory mutations and audit entries into one durable SQLite commit.
     * Nested calls act as savepoints for the in-memory snapshot; SQLite is written once
     * when the outermost transaction completes.
     */
    public function transaction(callable $callback)
    {
        $outermost = $this->transactionDepth === 0;
        $snapshot = $this->data;
        $dirtyBefore = $this->transactionDirty;
        $this->transactionDepth++;

        try {
            $result = $callback($this);
            $this->transactionDepth--;

            if ($outermost && $this->transactionDirty) {
                $this->transactionDirty = false;
                try {
                    $this->persist();
                } catch (Throwable $e) {
                    $this->data = $snapshot;
                    $this->transactionDirty = false;
                    throw $e;
                }
            }
            return $result;
        } catch (Throwable $e) {
            // If persist() failed in the outermost branch, depth has already been
            // decremented. Otherwise this transaction still owns one nesting level.
            if ($this->transactionDepth > 0) $this->transactionDepth--;
            $this->data = $snapshot;
            $this->transactionDirty = $outermost ? false : $dirtyBefore;
            throw $e;
        }
    }

    public function save(): void
    {
        if ($this->transactionDepth > 0) {
            $this->transactionDirty = true;
            return;
        }
        $this->persist();
    }

    private function rowKey(string $collection, $index, array $record): string
    {
        return $collection === 'auth_rate_limits'
            ? (string)$index
            : (string)($record['id'] ?? $record['user_id'] ?? $record['key'] ?? $index);
    }

    /** Serialize current records keyed by collection + record key. */
    private function serializeRows(array $data): array
    {
        $rows = [];
        foreach ($data as $collection => $records) {
            foreach ($records as $index => $record) {
                if (!is_array($record)) throw new RuntimeException('SQLite record must be an array.');
                $key = $this->rowKey((string)$collection, $index, $record);
                if ($key === '') throw new RuntimeException("SQLite record key is missing for {$collection}.");
                $payload = json_encode($record, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
                if (!is_string($payload)) throw new RuntimeException('Unable to serialize SQLite record.');
                $compoundKey = (string)$collection . "\0" . $key;
                if (array_key_exists($compoundKey, $rows)) {
                    throw new RuntimeException("Duplicate record identity detected in {$collection}.");
                }
                $rows[$compoundKey] = [
                    'collection' => (string)$collection,
                    'record_key' => $key,
                    'payload' => $payload,
                    'record' => $record,
                ];
            }
        }
        return $rows;
    }

    /**
     * Insert or update one record in its dedicated relational table. The JSON payload
     * is retained temporarily for application compatibility; indexed/relational
     * columns enforce identity, relationships, uniqueness, and common query paths.
     */
    private function upsertRelationalRecord(string $collection, string $key, array $record): void
    {
        $payload = json_encode($record, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if (!is_string($payload)) throw new RuntimeException('Unable to serialize relational record.');

        switch ($collection) {
            case 'users':
                $stmt = $this->pdo->prepare(
                    'INSERT INTO users(record_key,id,username,email,role,is_active,storage_quota_bytes,storage_used_bytes,created_at,payload) '
                    . 'VALUES(:record_key,:id,:username,:email,:role,:is_active,:quota,:used,:created_at,:payload) '
                    . 'ON CONFLICT(id) DO UPDATE SET record_key=excluded.record_key,username=excluded.username,email=excluded.email,'
                    . 'role=excluded.role,is_active=excluded.is_active,storage_quota_bytes=excluded.storage_quota_bytes,'
                    . 'storage_used_bytes=excluded.storage_used_bytes,created_at=excluded.created_at,payload=excluded.payload'
                );
                $stmt->execute([
                    ':record_key' => $key, ':id' => (string)($record['id'] ?? $key),
                    ':username' => $record['username'] ?? null, ':email' => $record['email'] ?? null,
                    ':role' => $record['role'] ?? 'user', ':is_active' => (int)($record['is_active'] ?? 1),
                    ':quota' => max(0, (int)($record['storage_quota_bytes'] ?? 0)),
                    ':used' => max(0, (int)($record['storage_used_bytes'] ?? 0)),
                    ':created_at' => $record['created_at'] ?? null, ':payload' => $payload,
                ]);
                return;

            case 'vault_profiles':
                $stmt = $this->pdo->prepare(
                    'INSERT INTO vault_profiles(record_key,user_id,created_at,updated_at,payload) '
                    . 'VALUES(:record_key,:user_id,:created_at,:updated_at,:payload) '
                    . 'ON CONFLICT(user_id) DO UPDATE SET record_key=excluded.record_key,created_at=excluded.created_at,'
                    . 'updated_at=excluded.updated_at,payload=excluded.payload'
                );
                $stmt->execute([
                    ':record_key' => $key, ':user_id' => (string)($record['user_id'] ?? $key),
                    ':created_at' => $record['created_at'] ?? null,
                    ':updated_at' => $record['updated_at'] ?? null, ':payload' => $payload,
                ]);
                return;

            case 'encrypted_files':
                $stmt = $this->pdo->prepare(
                    'INSERT INTO encrypted_files(record_key,id,owner_id,upload_status,deletion_pending,file_size_bytes,total_chunks,created_at,payload) '
                    . 'VALUES(:record_key,:id,:owner_id,:status,:deleting,:size,:chunks,:created_at,:payload) '
                    . 'ON CONFLICT(id) DO UPDATE SET record_key=excluded.record_key,owner_id=excluded.owner_id,'
                    . 'upload_status=excluded.upload_status,deletion_pending=excluded.deletion_pending,file_size_bytes=excluded.file_size_bytes,'
                    . 'total_chunks=excluded.total_chunks,created_at=excluded.created_at,payload=excluded.payload'
                );
                $stmt->execute([
                    ':record_key' => $key, ':id' => (string)($record['id'] ?? $key),
                    ':owner_id' => (string)($record['owner_id'] ?? ''),
                    ':status' => (string)($record['upload_status'] ?? 'completed'),
                    ':deleting' => (int)(!empty($record['deletion_pending'])),
                    ':size' => max(0, (int)($record['file_size_bytes'] ?? 0)),
                    ':chunks' => max(0, (int)($record['total_chunks'] ?? 0)),
                    ':created_at' => $record['created_at'] ?? null, ':payload' => $payload,
                ]);
                return;

            case 'file_chunks':
                $stmt = $this->pdo->prepare(
                    'INSERT INTO file_chunks(record_key,id,file_id,chunk_index,chunk_size_bytes,storage_path,sha256_ciphertext,created_at,payload) '
                    . 'VALUES(:record_key,:id,:file_id,:chunk_index,:size,:path,:hash,:created_at,:payload) '
                    . 'ON CONFLICT(id) DO UPDATE SET record_key=excluded.record_key,file_id=excluded.file_id,'
                    . 'chunk_index=excluded.chunk_index,chunk_size_bytes=excluded.chunk_size_bytes,storage_path=excluded.storage_path,'
                    . 'sha256_ciphertext=excluded.sha256_ciphertext,created_at=excluded.created_at,payload=excluded.payload'
                );
                $stmt->execute([
                    ':record_key' => $key, ':id' => (string)($record['id'] ?? $key),
                    ':file_id' => (string)($record['file_id'] ?? ''),
                    ':chunk_index' => max(0, (int)($record['chunk_index'] ?? 0)),
                    ':size' => max(0, (int)($record['chunk_size_bytes'] ?? 0)),
                    ':path' => (string)($record['storage_path'] ?? ''),
                    ':hash' => $record['sha256_ciphertext'] ?? null,
                    ':created_at' => $record['created_at'] ?? null, ':payload' => $payload,
                ]);
                return;

            case 'audit_logs':
                $stmt = $this->pdo->prepare(
                    'INSERT INTO audit_logs(record_key,id,sequence_number,timestamp,user_id,action_type,file_id,status,previous_hash,current_hash,payload) '
                    . 'VALUES(:record_key,:id,:sequence,:timestamp,:user_id,:action,:file_id,:status,:previous_hash,:current_hash,:payload) '
                    . 'ON CONFLICT(id) DO UPDATE SET record_key=excluded.record_key,sequence_number=excluded.sequence_number,'
                    . 'timestamp=excluded.timestamp,user_id=excluded.user_id,action_type=excluded.action_type,file_id=excluded.file_id,'
                    . 'status=excluded.status,previous_hash=excluded.previous_hash,current_hash=excluded.current_hash,payload=excluded.payload'
                );
                $stmt->execute([
                    ':record_key' => $key, ':id' => (string)($record['id'] ?? $key),
                    ':sequence' => isset($record['sequence_number']) ? (int)$record['sequence_number'] : null,
                    ':timestamp' => $record['timestamp'] ?? null, ':user_id' => $record['user_id'] ?? null,
                    ':action' => $record['action_type'] ?? null, ':file_id' => $record['file_id'] ?? null,
                    ':status' => $record['status'] ?? null, ':previous_hash' => $record['previous_hash'] ?? null,
                    ':current_hash' => $record['current_hash'] ?? null, ':payload' => $payload,
                ]);
                return;

            case 'auth_rate_limits':
                $stmt = $this->pdo->prepare(
                    'INSERT INTO auth_rate_limits(record_key,window_started_at,attempts,payload) '
                    . 'VALUES(:record_key,:window_started_at,:attempts,:payload) '
                    . 'ON CONFLICT(record_key) DO UPDATE SET window_started_at=excluded.window_started_at,'
                    . 'attempts=excluded.attempts,payload=excluded.payload'
                );
                $stmt->execute([
                    ':record_key' => $key,
                    ':window_started_at' => (int)($record['window_started_at'] ?? 0),
                    ':attempts' => max(0, (int)($record['attempts'] ?? 0)), ':payload' => $payload,
                ]);
                return;

            default:
                throw new RuntimeException('Unknown SQLite collection: ' . $collection);
        }
    }

    /** Persist only changed rows, in FK-safe order, inside one SQLite transaction. */
    private function persist(): void
    {
        $currentRows = $this->serializeRows($this->data);
        $this->pdo->beginTransaction();
        try {
            $deleteOrder = ['file_chunks','encrypted_files','vault_profiles','users','audit_logs','auth_rate_limits'];
            foreach ($deleteOrder as $collection) {
                foreach ($this->baselineRows as $compoundKey => $oldRow) {
                    if ($oldRow['collection'] !== $collection || isset($currentRows[$compoundKey])) continue;
                    $tableAndKey = [
                        'users' => ['users', 'id'],
                        'vault_profiles' => ['vault_profiles', 'user_id'],
                        'encrypted_files' => ['encrypted_files', 'id'],
                        'file_chunks' => ['file_chunks', 'id'],
                        'audit_logs' => ['audit_logs', 'id'],
                        'auth_rate_limits' => ['auth_rate_limits', 'record_key'],
                    ][$collection];
                    $stmt = $this->pdo->prepare('DELETE FROM ' . $tableAndKey[0] . ' WHERE ' . $tableAndKey[1] . ' = :record_key');
                    $stmt->execute([':record_key' => $oldRow['record_key']]);
                }
            }

            // Parent records are inserted before their dependants to satisfy FKs.
            $insertOrder = ['users','vault_profiles','encrypted_files','file_chunks','audit_logs','auth_rate_limits'];
            foreach ($insertOrder as $collection) {
                foreach ($currentRows as $compoundKey => $row) {
                    if ($row['collection'] !== $collection) continue;
                    $old = $this->baselineRows[$compoundKey] ?? null;
                    if (is_array($old) && hash_equals($old['payload'], $row['payload'])) continue;
                    $this->upsertRelationalRecord($collection, $row['record_key'], $row['record']);
                }
            }

            $this->pdo->commit();
            $this->baselineRows = $currentRows;
            @chmod(DB_FILE, 0600);
        } catch (Throwable $e) {
            if ($this->pdo->inTransaction()) $this->pdo->rollBack();
            throw $e;
        }
    }

    public function getSchemaVersion(): int
    {
        return (int)$this->pdo->query('PRAGMA user_version')->fetchColumn();
    }

    private function seed(): void
    {
        // A fresh installation starts with no users and no built-in credentials.
        // The genesis entry uses the full v3 audit payload with SHA3-512 from the first record.
        $genesisPrev = str_repeat('0', 128);
        $timestamp = gmdate('Y-m-d\TH:i:s.000\Z');
        $action = 'SYSTEM_GENESIS';
        $status = 'SUCCESS';
        $genesisUserId = 'SYSTEM_BOOTSTRAP';
        $entry = [
            'id' => self::generateUuid(),
            'sequence_number' => 1,
            'timestamp' => $timestamp,
            'user_id' => $genesisUserId,
            'action_type' => $action,
            'file_id' => null,
            'ip_address' => '127.0.0.1',
            'user_agent' => 'SecureVault/Bootstrap',
            'status' => $status,
            'details' => null,
            'hash_version' => 3,
            'previous_hash' => $genesisPrev,
        ];
        $payload = [
            'version' => 3,
            'id' => $entry['id'],
            'sequence_number' => $entry['sequence_number'],
            'timestamp' => $entry['timestamp'],
            'user_id' => $entry['user_id'],
            'action_type' => $entry['action_type'],
            'file_id' => $entry['file_id'],
            'status' => $entry['status'],
            'ip_address' => $entry['ip_address'],
            'user_agent' => $entry['user_agent'],
            'details' => $entry['details'],
            'previous_hash' => $entry['previous_hash'],
        ];
        $encoded = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if (!is_string($encoded)) throw new RuntimeException('Unable to create the audit genesis entry.');
        $entry['current_hash'] = hash('sha3-512', $encoded);
        $this->data['audit_logs'][] = $entry;
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

    /** Remove an account and its owned vault data in the caller's transaction. */
    public function deleteUserAndOwnedData(string $userId): void
    {
        $ownedIds = [];
        foreach ($this->data['encrypted_files'] as $entry) {
            if (($entry['owner_id'] ?? null) === $userId) $ownedIds[(string)$entry['id']] = true;
        }
        $this->data['file_chunks'] = array_values(array_filter($this->data['file_chunks'],
            fn($chunk) => !isset($ownedIds[(string)($chunk['file_id'] ?? '')])));
        $this->data['encrypted_files'] = array_values(array_filter($this->data['encrypted_files'],
            fn($entry) => ($entry['owner_id'] ?? null) !== $userId));
        $this->data['vault_profiles'] = array_values(array_filter($this->data['vault_profiles'],
            fn($profile) => ($profile['user_id'] ?? null) !== $userId));
        $this->data['users'] = array_values(array_filter($this->data['users'],
            fn($user) => ($user['id'] ?? null) !== $userId));
        $this->save();
    }

    /** Fixed-window authentication throttle, guarded by the database lock. */
    public function isRateLimited(string $key, int $maxAttempts, int $windowSeconds): bool
    {
        $entry = $this->data['auth_rate_limits'][$key] ?? null;
        if (!is_array($entry)) return false;
        $now = time();
        if ((int)($entry['window_started_at'] ?? 0) + $windowSeconds <= $now) {
            unset($this->data['auth_rate_limits'][$key]);
            $this->save();
            return false;
        }
        return (int)($entry['attempts'] ?? 0) >= $maxAttempts;
    }

    public function recordRateLimitFailure(string $key, int $windowSeconds): void
    {
        $now = time();
        $entry = $this->data['auth_rate_limits'][$key] ?? null;
        if (!is_array($entry) || (int)($entry['window_started_at'] ?? 0) + $windowSeconds <= $now) {
            $this->data['auth_rate_limits'][$key] = ['window_started_at' => $now, 'attempts' => 1];
        } else {
            $this->data['auth_rate_limits'][$key]['attempts'] = (int)($entry['attempts'] ?? 0) + 1;
        }
        $this->save();
    }

    public function clearRateLimit(string $key): void
    {
        if (isset($this->data['auth_rate_limits'][$key])) {
            unset($this->data['auth_rate_limits'][$key]);
            $this->save();
        }
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
    public function getFilesByOwner(string $ownerId, bool $includeIncomplete = false): array
    {
        $res = [];
        foreach ($this->data['encrypted_files'] as $f) {
            // Rows from the previous format did not have a status and are treated as completed.
            $status = $f['upload_status'] ?? 'completed';
            if ($f['owner_id'] === $ownerId && ($f['kind'] ?? 'file') === 'file'
                && ($includeIncomplete || $status === 'completed')) {
                $res[] = $f;
            }
        }
        return $res;
    }

    public function getFoldersByOwner(string $ownerId): array
    {
        return array_values(array_filter($this->data['encrypted_files'],
            fn($entry) => $entry['owner_id'] === $ownerId && ($entry['kind'] ?? 'file') === 'folder'));
    }

    public function folderHasChildren(string $folderId, string $ownerId): bool
    {
        foreach ($this->data['encrypted_files'] as $entry) {
            if ($entry['owner_id'] === $ownerId && ($entry['parent_folder_id'] ?? null) === $folderId) return true;
        }
        return false;
    }

    public function getChunksByFile(string $fileId): array
    {
        $chunks = array_values(array_filter(
            $this->data['file_chunks'],
            fn($chunk) => $chunk['file_id'] === $fileId
        ));
        usort($chunks, fn($a, $b) => (int)$a['chunk_index'] <=> (int)$b['chunk_index']);
        return $chunks;
    }

    /** Atomically checks quota, reserves bytes, and creates an uploading record. */
    public function addFileWithQuotaReservation(string $ownerId, array $file): bool
    {
        foreach ($this->data['users'] as $index => $user) {
            if ($user['id'] !== $ownerId) continue;
            $used = max(0, (int)($user['storage_used_bytes'] ?? 0));
            $quota = max(0, (int)($user['storage_quota_bytes'] ?? 0));
            $size = (int)($file['file_size_bytes'] ?? 0);
            if ($size < 1 || $size > ($quota - min($used, $quota))) return false;
            $this->data['users'][$index]['storage_used_bytes'] = $used + $size;
            $file['owner_id'] = $ownerId;
            $file['upload_status'] = 'uploading';
            $file['quota_accounted'] = true;
            $file['created_at'] = $file['created_at'] ?? gmdate('Y-m-d\TH:i:s.000\Z');
            $this->data['encrypted_files'][] = $file;
            $this->save();
            return true;
        }
        return false;
    }

    /** Mark an upload as complete exactly once. Returns completed, already_completed, or missing. */
    public function markUploadComplete(string $fileId, string $ownerId): string
    {
        foreach ($this->data['encrypted_files'] as &$file) {
            if ($file['id'] !== $fileId || $file['owner_id'] !== $ownerId) continue;
            $status = $file['upload_status'] ?? 'completed';
            if ($status === 'completed') return 'already_completed';
            if ($status !== 'uploading') return 'missing';
            $file['upload_status'] = 'completed';
            $file['completed_at'] = gmdate('Y-m-d\TH:i:s.000\Z');
            unset($file);
            $this->save();
            return 'completed';
        }
        unset($file);
        return 'missing';
    }

    /** Mark a file unavailable before touching the filesystem; retries can resume cleanup. */
    public function markFileDeletionPending(string $fileId): bool
    {
        foreach ($this->data['encrypted_files'] as &$file) {
            if (($file['id'] ?? null) !== $fileId) continue;
            if (!empty($file['deletion_pending'])) {
                unset($file);
                return false;
            }
            $file['deletion_pending'] = true;
            $file['deletion_started_at'] = gmdate('Y-m-d\TH:i:s.000\Z');
            unset($file);
            $this->save();
            return true;
        }
        unset($file);
        throw new RuntimeException('File record disappeared before deletion could be scheduled.');
    }

    /** Delete a file record/chunk metadata and release its quota charge in one transaction. */
    public function deleteFileAndReleaseQuota(string $fileId): void
    {
        $target = null;
        foreach ($this->data['encrypted_files'] as $file) {
            if ($file['id'] === $fileId) { $target = $file; break; }
        }
        if ($target === null) return;

        $charge = (bool)($target['quota_accounted'] ?? (($target['upload_status'] ?? 'completed') === 'completed'));
        if ($charge) {
            foreach ($this->data['users'] as &$user) {
                if ($user['id'] === $target['owner_id']) {
                    $user['storage_used_bytes'] = max(0, (int)($user['storage_used_bytes'] ?? 0) - (int)$target['file_size_bytes']);
                    break;
                }
            }
            unset($user);
        }
        $this->data['encrypted_files'] = array_values(array_filter(
            $this->data['encrypted_files'], fn($file) => $file['id'] !== $fileId
        ));
        $this->data['file_chunks'] = array_values(array_filter(
            $this->data['file_chunks'], fn($chunk) => $chunk['file_id'] !== $fileId
        ));
        $this->save();
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

    /** Replace audit records only for an explicit operator-run integrity migration. */
    public function replaceAuditLogs(array $logs): void
    {
        foreach ($logs as $entry) {
            if (!is_array($entry) || !isset($entry['id'], $entry['current_hash'], $entry['previous_hash'])) {
                throw new InvalidArgumentException('Invalid audit record supplied to migration.');
            }
        }
        $this->data['audit_logs'] = array_values($logs);
        $this->save();
    }
}
