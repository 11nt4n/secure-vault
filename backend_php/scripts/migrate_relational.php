<?php
// Explicit operator entry point for the V9 relational SQLite migration.
// Database::getInstance() performs the versioned migration transactionally.
if (PHP_SAPI !== 'cli') { fwrite(STDERR, "CLI only.\n"); exit(2); }

try {
    require_once __DIR__ . '/../config.php';
    require_once __DIR__ . '/../db/Database.php';
    $db = Database::getInstance();
    $users = count($db->getUsers());
    $files = 0;
    foreach ($db->getUsers() as $user) {
        $files += count($db->getFilesByOwner((string)$user['id'], true));
    }
    fwrite(STDOUT, "Relational SQLite schema ready (version {$db->getSchemaVersion()})." . PHP_EOL);
    fwrite(STDOUT, "Users: {$users}; file records: {$files}" . PHP_EOL);
    fwrite(STDOUT, "Database: " . DB_FILE . PHP_EOL);
    fwrite(STDOUT, "Pre-migration SQLite snapshots are retained in the private data directory." . PHP_EOL);
} catch (Throwable $e) {
    fwrite(STDERR, "Relational migration blocked/failed: " . $e->getMessage() . PHP_EOL);
    exit(1);
}
