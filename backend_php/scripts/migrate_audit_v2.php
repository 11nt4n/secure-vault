<?php
/**
 * Explicitly re-chain legacy Stage 1 audit entries using the full Stage 2 v2 payload.
 * IMPORTANT: v1 did not protect IP/user-agent/id/sequence. This migration cannot prove
 * those historical attributes were never altered; take and externally anchor a backup first.
 */
if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit("Not found.\n");
}

require_once __DIR__ . '/../config.php';
require_once __DIR__ . '/../db/Database.php';
require_once __DIR__ . '/../utils/Audit.php';

$db = Database::getInstance();
$logs = $db->getAuditLogs();
$verification = Audit::verifyChain();
if (!$verification['isValid']) {
    fwrite(STDERR, "Existing audit chain fails current verification; refusing to rewrite it.\n");
    fwrite(STDERR, (string)$verification['message'] . "\n");
    exit(2);
}
$legacyCount = count(array_filter($logs, fn($entry) => (int)($entry['hash_version'] ?? 1) === 1));
if ($legacyCount === 0) {
    echo "Audit chain already uses v2. No changes made.\n";
    exit(0);
}

echo "This will re-hash {$legacyCount} legacy record(s) using their currently stored metadata.\n";
echo "Stage 1 did not protect IP/user-agent/id/sequence, so historical integrity of those fields cannot be proven by this tool.\n";
echo "Create an external backup and record its SHA-256 before continuing.\n";
echo "Type MIGRATE-AUDIT-V2 to proceed: ";
$confirmation = trim((string)fgets(STDIN));
if ($confirmation !== 'MIGRATE-AUDIT-V2') {
    echo "Cancelled; no changes made.\n";
    exit(1);
}

$previousHash = str_repeat('0', 64);
$converted = [];
foreach ($logs as $index => $entry) {
    $entry['sequence_number'] = $index + 1;
    $entry['ip_address'] = (string)($entry['ip_address'] ?? 'unknown');
    $entry['user_agent'] = (string)($entry['user_agent'] ?? 'unknown');
    $entry['details'] = $entry['details'] ?? null;
    $entry['hash_version'] = 2;
    $entry['previous_hash'] = $previousHash;
    $entry['current_hash'] = Audit::computeEntryHash($entry);
    $previousHash = $entry['current_hash'];
    $converted[] = $entry;
}
$db->replaceAuditLogs($converted);
Audit::logEvent('SYSTEM_OPERATOR', 'AUDIT_CHAIN_MIGRATED_V2', null, null, null, 'SUCCESS',
    "legacy_records_rehashed={$legacyCount};hash_version=2");
$result = Audit::verifyChain();
if (!$result['isValid']) {
    fwrite(STDERR, "Post-migration verification failed: {$result['message']}\n");
    exit(3);
}
echo "Migration completed. " . $result['message'] . "\n";
