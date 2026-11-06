<?php
// CLI-only: create a signed checkpoint for storage outside the application host.
if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

require_once __DIR__ . '/../config.php';
require_once __DIR__ . '/../utils/Audit.php';

$keyB64 = getenv('AUDIT_ANCHOR_HMAC_KEY');
$key = is_string($keyB64) ? base64_decode($keyB64, true) : false;
if (!is_string($key) || strlen($key) !== 32) {
    fwrite(STDERR, "AUDIT_ANCHOR_HMAC_KEY wajib berisi Base64 dari 32 byte acak dan hanya tersedia pada sesi CLI tepercaya.\n");
    exit(2);
}

$verification = Audit::verifyChain();
if (empty($verification['isValid'])) {
    fwrite(STDERR, "Rantai audit tidak valid: " . ($verification['message'] ?? 'unknown') . "\n");
    exit(3);
}
$logs = Database::getInstance()->getAuditLogs();
if (!$logs) {
    fwrite(STDERR, "Rantai audit kosong; checkpoint tidak dibuat.\n");
    exit(4);
}
$last = $logs[count($logs) - 1];
$payload = [
    'format' => 'secure-vault-audit-anchor-v1',
    'created_at' => gmdate('Y-m-d\\TH:i:s.000\\Z'),
    'record_count' => count($logs),
    'latest_sequence' => (int)$last['sequence_number'],
    'head_hash' => (string)$last['current_hash'],
];
$canonical = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
if (!is_string($canonical)) {
    fwrite(STDERR, "Gagal membuat payload checkpoint.\n");
    exit(5);
}
$document = [
    'payload' => $payload,
    'hmac_sha256' => hash_hmac('sha256', $canonical, $key),
];
$encoded = json_encode($document, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . PHP_EOL;
$output = $argv[1] ?? (PRIVATE_DIR . DIRECTORY_SEPARATOR . 'audit-anchors' . DIRECTORY_SEPARATOR . 'anchor-' . gmdate('Ymd-His') . '.json');
$directory = dirname($output);
if (!is_dir($directory) && !mkdir($directory, 0700, true) && !is_dir($directory)) {
    fwrite(STDERR, "Direktori output checkpoint tidak dapat dibuat.\n");
    exit(6);
}
$temp = $output . '.tmp-' . bin2hex(random_bytes(6));
if (file_put_contents($temp, $encoded, LOCK_EX) === false) {
    fwrite(STDERR, "Checkpoint tidak dapat ditulis.\n");
    exit(7);
}
@chmod($temp, 0600);
if (!rename($temp, $output)) {
    @unlink($temp);
    fwrite(STDERR, "Checkpoint tidak dapat dipasang secara atomik.\n");
    exit(8);
}
@chmod($output, 0600);
echo "Audit checkpoint created: {$output}\n";
echo "Sequence: {$payload['latest_sequence']} | Records: {$payload['record_count']} | Head: {$payload['head_hash']}\n";
echo "COPY THIS FILE TO AN OFF-HOST / WORM / OFFLINE LOCATION.\n";
