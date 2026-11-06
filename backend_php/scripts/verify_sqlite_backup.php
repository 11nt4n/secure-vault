<?php
// Read-only validation of a SQLite backup; does not modify the source.
if (PHP_SAPI !== 'cli') { fwrite(STDERR, "CLI only.\n"); exit(2); }
if (!extension_loaded('pdo_sqlite')) { fwrite(STDERR, "BLOCKED: pdo_sqlite is required.\n"); exit(3); }
$path = $argv[1] ?? '';
if ($path === '' || !is_file($path) || !is_readable($path)) { fwrite(STDERR, "Usage: php verify_sqlite_backup.php /path/to/backup.sqlite\n"); exit(2); }
try {
    $pdo = new PDO('sqlite:file:' . str_replace(['?', '#'], ['%3F', '%23'], realpath($path)) . '?mode=ro', null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
    $integrity = $pdo->query('PRAGMA integrity_check')->fetchColumn();
    $foreign = $pdo->query('PRAGMA foreign_key_check')->fetchAll(PDO::FETCH_ASSOC);
    $tables = $pdo->query("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")->fetchAll(PDO::FETCH_COLUMN);
    $schemaVersion = (int)$pdo->query('PRAGMA user_version')->fetchColumn();
    $required = ['users','vault_profiles','encrypted_files','file_chunks','audit_logs','auth_rate_limits'];
    if ($integrity !== 'ok' || count($foreign) > 0 || $schemaVersion !== 2 || count(array_diff($required, $tables)) > 0) {
        throw new RuntimeException('Integrity, schema version, relational table, or foreign-key check failed.');
    }
    fwrite(STDOUT, "BACKUP_VALID\nSchema version: {$schemaVersion}\nIntegrity: ok\nForeign key violations: 0\nTables: " . implode(', ', $tables) . "\n");
} catch (Throwable $e) {
    fwrite(STDERR, "BACKUP_INVALID: " . $e->getMessage() . "\n");
    exit(1);
}
