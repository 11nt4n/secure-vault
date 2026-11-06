<?php
// Explicit operator entry point. Database::getInstance() imports legacy JSON
// into SQLite on first open and deliberately preserves the source JSON backup.
require_once __DIR__ . '/../config.php';
require_once __DIR__ . '/../db/Database.php';

try {
    $db = Database::getInstance();
    $users = count($db->getUsers());
    $files = 0;
    foreach ($db->getUsers() as $user) {
        $files += count($db->getFilesByOwner((string)$user['id'], true));
    }
    fwrite(STDOUT, "SQLite database ready (schema version " . $db->getSchemaVersion() . "): " . DB_FILE . PHP_EOL);
    fwrite(STDOUT, "Users: {$users}; file records: {$files}" . PHP_EOL);
    if (is_file(LEGACY_JSON_DB_FILE)) {
        fwrite(STDOUT, "Legacy JSON retained as backup: " . LEGACY_JSON_DB_FILE . PHP_EOL);
    }
} catch (Throwable $e) {
    fwrite(STDERR, "Migration failed: " . $e->getMessage() . PHP_EOL);
    exit(1);
}
