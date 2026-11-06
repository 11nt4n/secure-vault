<?php
// CLI-only: verify the HMAC and confirm the saved audit chain still contains the checkpointed prefix.
if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

require_once __DIR__ . '/../config.php';
require_once __DIR__ . '/../utils/Audit.php';

$path = $argv[1] ?? '';
if ($path === '' || !is_file($path) || !is_readable($path)) {
    fwrite(STDERR, "Gunakan: php backend_php/scripts/verify_audit_anchor.php PATH_CHECKPOINT.json\n");
    exit(2);
}
$keyB64 = getenv('AUDIT_ANCHOR_HMAC_KEY');
$key = is_string($keyB64) ? base64_decode($keyB64, true) : false;
if (!is_string($key) || strlen($key) !== 32) {
    fwrite(STDERR, "AUDIT_ANCHOR_HMAC_KEY wajib berisi Base64 dari 32 byte acak dan hanya tersedia pada sesi CLI tepercaya.\n");
    exit(3);
}
$document = json_decode((string)file_get_contents($path), true);
$payload = is_array($document) ? ($document['payload'] ?? null) : null;
$signature = is_array($document) ? ($document['hmac_sha256'] ?? null) : null;
if (!is_array($payload) || ($payload['format'] ?? '') !== 'secure-vault-audit-anchor-v1' || !is_string($signature)) {
    fwrite(STDERR, "Format checkpoint tidak valid.\n");
    exit(4);
}
$canonical = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
$expected = is_string($canonical) ? hash_hmac('sha256', $canonical, $key) : '';
if ($expected === '' || !hash_equals($expected, $signature)) {
    fwrite(STDERR, "TANDA TANGAN CHECKPOINT TIDAK VALID.\n");
    exit(5);
}
$chain = Audit::verifyChain();
if (empty($chain['isValid'])) {
    fwrite(STDERR, "Rantai audit lokal tidak valid: " . ($chain['message'] ?? 'unknown') . "\n");
    exit(6);
}
$sequence = (int)($payload['latest_sequence'] ?? 0);
$logs = Database::getInstance()->getAuditLogs();
$anchored = $sequence > 0 ? ($logs[$sequence - 1] ?? null) : null;
if (!$anchored || (int)($anchored['sequence_number'] ?? 0) !== $sequence
    || !hash_equals((string)($payload['head_hash'] ?? ''), (string)($anchored['current_hash'] ?? ''))
    || (int)($payload['record_count'] ?? -1) !== $sequence) {
    fwrite(STDERR, "CHECKPOINT TIDAK COCOK DENGAN PREFIX RANTAI AUDIT SAAT INI.\n");
    exit(7);
}
echo "CHECKPOINT VALID. Anchored sequence {$sequence} masih cocok dengan rantai audit lokal.\n";
