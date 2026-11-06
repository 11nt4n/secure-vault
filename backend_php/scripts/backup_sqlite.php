<?php
// Create a consistent online SQLite backup using VACUUM INTO.
require_once __DIR__ . '/../config.php';

if (PHP_SAPI !== 'cli') { fwrite(STDERR, "CLI only.\n"); exit(2); }
if (!extension_loaded('pdo_sqlite')) { fwrite(STDERR, "BLOCKED: pdo_sqlite is required.\n"); exit(3); }
if (!is_file(DB_FILE)) { fwrite(STDERR, "Database does not exist: " . DB_FILE . "\n"); exit(4); }
$destination = $argv[1] ?? '';
if ($destination === '') { fwrite(STDERR, "Usage: php backup_sqlite.php /secure/backup/secure-vault-YYYYmmdd-HHMMSS.sqlite\n"); exit(2); }
$destination = str_replace('\\', '/', $destination);
$parent = dirname($destination);
if (!is_dir($parent) || !is_writable($parent)) { fwrite(STDERR, "Backup directory must exist and be writable.\n"); exit(5); }
if (realpath($destination) === realpath(DB_FILE) || file_exists($destination)) { fwrite(STDERR, "Destination already exists or points to the active database.\n"); exit(6); }
$escaped = str_replace("'", "''", $destination);
try {
    $pdo = new PDO('sqlite:' . DB_FILE, null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
    $pdo->exec("VACUUM INTO '{$escaped}'");
    @chmod($destination, 0600);
    $check = new PDO('sqlite:' . $destination, null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
    $result = $check->query('PRAGMA integrity_check')->fetchColumn();
    $schemaVersion = (int)$check->query('PRAGMA user_version')->fetchColumn();
    $foreign = $check->query('PRAGMA foreign_key_check')->fetchAll(PDO::FETCH_ASSOC);
    $required = ['users','vault_profiles','encrypted_files','file_chunks','audit_logs','auth_rate_limits'];
    $tables = $check->query("SELECT name FROM sqlite_master WHERE type='table'")->fetchAll(PDO::FETCH_COLUMN);
    if ($result !== 'ok' || $schemaVersion !== 2 || count($foreign) > 0 || count(array_diff($required, $tables)) > 0) {
        @unlink($destination);
        throw new RuntimeException('Backup failed relational schema, integrity, or foreign-key validation.');
    }
    fwrite(STDOUT, "BACKUP_OK\nPath: {$destination}\nBytes: " . filesize($destination) . "\nSchema: {$schemaVersion}\nIntegrity: ok\nForeign key violations: 0\n");
} catch (Throwable $e) {
    fwrite(STDERR, "BACKUP_FAILED: " . $e->getMessage() . "\n");
    exit(1);
}
