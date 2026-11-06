<?php
// Non-destructive CLI preflight. Does not claim certification or full security.
if (PHP_SAPI !== 'cli') { fwrite(STDERR, "CLI only.\n"); exit(2); }
$projectDir = dirname(__DIR__, 2);
$privateDir = $projectDir . DIRECTORY_SEPARATOR . 'var' . DIRECTORY_SEPARATOR . 'secure-vault';
$secrets = [];
$secretsFile = $privateDir . DIRECTORY_SEPARATOR . 'secrets.php';
if (is_file($secretsFile) && is_readable($secretsFile)) { $loaded = require $secretsFile; if (is_array($loaded)) $secrets = $loaded; }
$jwtCandidate = getenv('JWT_SECRET');
if ($jwtCandidate === false || $jwtCandidate === '') $jwtCandidate = (string)($secrets['JWT_SECRET'] ?? '');
$mfaCandidate = getenv('MFA_ENCRYPTION_KEY');
if ($mfaCandidate === false || $mfaCandidate === '') $mfaCandidate = (string)($secrets['MFA_ENCRYPTION_KEY'] ?? '');
$mfaDecoded = base64_decode($mfaCandidate, true);
$checks = [];
$checks['jwt_secret_minimum_length'] = is_string($jwtCandidate) && strlen($jwtCandidate) >= 32;
$checks['mfa_key_32_bytes'] = is_string($mfaDecoded) && strlen($mfaDecoded) === 32;
if (!$checks['jwt_secret_minimum_length'] || !$checks['mfa_key_32_bytes']) {
    fwrite(STDOUT, json_encode(['status' => 'BLOCKED', 'checks' => $checks, 'next_step' => 'Set JWT_SECRET and MFA_ENCRYPTION_KEY or run backend_php/scripts/init_local_secrets.php for local development.'], JSON_PRETTY_PRINT) . PHP_EOL);
    exit(3);
}
require_once __DIR__ . '/../config.php';
$checks['pdo_sqlite'] = extension_loaded('pdo_sqlite');
$checks['database_exists'] = is_file(DB_FILE);
$checks['private_data_outside_webroot'] = !str_starts_with((string)realpath(DATA_DIR), (string)realpath(BASE_DIR));
$checks['private_storage_outside_webroot'] = !str_starts_with((string)realpath(STORAGE_DIR), (string)realpath(BASE_DIR));
$checks['data_dir_not_world_writable'] = (fileperms(DATA_DIR) & 0002) === 0;
$checks['storage_dir_not_world_writable'] = (fileperms(STORAGE_DIR) & 0002) === 0;
if ($checks['pdo_sqlite'] && $checks['database_exists']) {
    try {
        $pdo = new PDO('sqlite:' . DB_FILE, null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
        $checks['database_integrity'] = $pdo->query('PRAGMA integrity_check')->fetchColumn() === 'ok';
        $checks['database_wal_mode'] = strtolower((string)$pdo->query('PRAGMA journal_mode')->fetchColumn()) === 'wal';
        $checks['relational_schema_version'] = (int)$pdo->query('PRAGMA user_version')->fetchColumn() === 2;
        $checks['foreign_key_violations'] = count($pdo->query('PRAGMA foreign_key_check')->fetchAll(PDO::FETCH_ASSOC)) === 0;
        $requiredTables = ['users','vault_profiles','encrypted_files','file_chunks','audit_logs','auth_rate_limits'];
        $actualTables = $pdo->query("SELECT name FROM sqlite_master WHERE type='table'")->fetchAll(PDO::FETCH_COLUMN);
        $checks['required_relational_tables'] = count(array_diff($requiredTables, $actualTables)) === 0;
        $checks['legacy_generic_table_absent'] = !in_array('vault_records', $actualTables, true);
    } catch (Throwable $e) { $checks['database_integrity'] = false; }
} else {
    $checks['database_integrity'] = null;
    $checks['database_wal_mode'] = null;
    $checks['relational_schema_version'] = null;
    $checks['foreign_key_violations'] = null;
    $checks['required_relational_tables'] = null;
    $checks['legacy_generic_table_absent'] = null;
}
$hardFailures = [];
foreach (['private_data_outside_webroot', 'private_storage_outside_webroot', 'data_dir_not_world_writable', 'storage_dir_not_world_writable', 'jwt_secret_minimum_length', 'mfa_key_32_bytes'] as $name) { if (($checks[$name] ?? null) === false) $hardFailures[$name] = false; }
$blockers = [];
foreach (['pdo_sqlite', 'database_exists', 'database_integrity', 'database_wal_mode', 'relational_schema_version', 'foreign_key_violations', 'required_relational_tables', 'legacy_generic_table_absent'] as $name) { if (($checks[$name] ?? null) !== true) $blockers[$name] = $checks[$name] ?? false; }
$status = $hardFailures ? 'FAIL' : ($blockers ? 'BLOCKED' : 'PASS');
fwrite(STDOUT, json_encode(['status' => $status, 'checks' => $checks, 'blockers' => $blockers], JSON_PRETTY_PRINT) . PHP_EOL);
exit($hardFailures ? 1 : ($blockers ? 3 : 0));
