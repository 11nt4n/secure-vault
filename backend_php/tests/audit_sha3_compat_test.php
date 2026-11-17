<?php
/**
 * Test Suite: audit_sha3_compat_test.php
 * Verifies SHA3-512 V3 hash-chain, backward compatibility for V1/V2,
 * strict genesis rules, transition integrity, tampering detection, and audit anchoring.
 *
 * Uses an isolated temporary runtime directory to guarantee zero side effects on operational data.
 */

$testRootDir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'sv_audit_test_' . bin2hex(random_bytes(8));
$dataDir = $testRootDir . DIRECTORY_SEPARATOR . 'data';
$storageDir = $testRootDir . DIRECTORY_SEPARATOR . 'storage';

mkdir($dataDir, 0700, true);
mkdir($storageDir, 0700, true);

// Set test environment variables
putenv("SECURE_VAULT_DATA_DIR={$dataDir}");
putenv("SECURE_VAULT_STORAGE_DIR={$storageDir}");
putenv("JWT_SECRET=" . bin2hex(random_bytes(32)));
putenv("MFA_ENCRYPTION_KEY=" . base64_encode(random_bytes(32)));
$anchorKey = random_bytes(32);
putenv("AUDIT_ANCHOR_HMAC_KEY=" . base64_encode($anchorKey));

require_once dirname(__DIR__) . '/config.php';
require_once dirname(__DIR__) . '/db/Database.php';
require_once dirname(__DIR__) . '/utils/Audit.php';

$passedTests = 0;
$failedTests = 0;

function assertCondition(bool $condition, string $testName, string $detail = ''): void
{
    global $passedTests, $failedTests;
    if ($condition) {
        $passedTests++;
        echo "  [PASS] {$testName}\n";
    } else {
        $failedTests++;
        echo "  [FAIL] {$testName} - {$detail}\n";
    }
}

function runCliScript(string $scriptRelativePath, array $args = []): array
{
    global $dataDir, $storageDir;
    // Lepas handle SQLite di proses parent agar tidak lock pada Windows
    $ref = new ReflectionProperty(Database::class, 'instance');
    $ref->setValue(null, null);
    unset($GLOBALS['db']);
    gc_collect_cycles();

    $root = dirname(dirname(__DIR__));
    $script = $root . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $scriptRelativePath);
    $cmd = array_merge([PHP_BINARY, $script], $args);
    $env = [
        'JWT_SECRET' => (string)getenv('JWT_SECRET'),
        'MFA_ENCRYPTION_KEY' => (string)getenv('MFA_ENCRYPTION_KEY'),
        'AUDIT_ANCHOR_HMAC_KEY' => (string)getenv('AUDIT_ANCHOR_HMAC_KEY'),
        'SECURE_VAULT_DATA_DIR' => $dataDir,
        'SECURE_VAULT_STORAGE_DIR' => $storageDir,
        'SystemRoot' => getenv('SystemRoot') ?: (getenv('SYSTEMROOT') ?: 'C:\\Windows'),
        'PATH' => getenv('PATH') ?: '',
    ];
    $descriptors = [
        0 => ['pipe', 'r'],
        1 => ['pipe', 'w'],
        2 => ['pipe', 'w'],
    ];
    $process = proc_open($cmd, $descriptors, $pipes, $root, $env);
    if (!is_resource($process)) {
        $GLOBALS['db'] = Database::getInstance();
        return ['code' => -1, 'stdout' => '', 'stderr' => 'proc_open failed'];
    }
    fclose($pipes[0]);
    $stdout = stream_get_contents($pipes[1]);
    fclose($pipes[1]);
    $stderr = stream_get_contents($pipes[2]);
    fclose($pipes[2]);
    $code = proc_close($process);

    // Re-acquire database instance untuk proses parent
    $GLOBALS['db'] = Database::getInstance();

    return ['code' => $code, 'stdout' => $stdout, 'stderr' => $stderr];
}

try {
    echo "========================================================\n";
    echo "  SECURE VAULT AUDIT HASH-CHAIN (SHA3-512) COMPAT TEST  \n";
    echo "========================================================\n\n";

    // Preflight Check: Runtime SHA3-512 support
    assertCondition(in_array('sha3-512', hash_algos(), true), "Preflight: PHP native sha3-512 algorithm support");

    $db = Database::getInstance();

    // ----------------------------------------------------
    // Scenario 1: Pure V1 Chain Verification
    // ----------------------------------------------------
    echo "\n--- Skenario 1: Rantai Murni V1 ---\n";
    $v1_genesisPrev = str_repeat('0', 64);
    $v1_time1 = '2026-10-01T00:00:00.000Z';
    $v1_hash1 = Audit::computeLogHash($v1_genesisPrev, $v1_time1, 'SYSTEM', 'BOOTSTRAP_V1', null, 'SUCCESS');
    assertCondition(strlen($v1_hash1) === 64, "V1 hash is 64 hex characters");

    $v1_time2 = '2026-10-01T00:01:00.000Z';
    $v1_hash2 = Audit::computeLogHash($v1_hash1, $v1_time2, 'admin', 'LOGIN', null, 'SUCCESS');

    $v1_logs = [
        [
            'id' => Database::generateUuid(),
            'sequence_number' => 1,
            'timestamp' => $v1_time1,
            'user_id' => 'SYSTEM',
            'action_type' => 'BOOTSTRAP_V1',
            'status' => 'SUCCESS',
            'previous_hash' => $v1_genesisPrev,
            'current_hash' => $v1_hash1,
            // Notice: hash_version omitted or 1
        ],
        [
            'id' => Database::generateUuid(),
            'sequence_number' => 2,
            'timestamp' => $v1_time2,
            'user_id' => 'admin',
            'action_type' => 'LOGIN',
            'status' => 'SUCCESS',
            'previous_hash' => $v1_hash1,
            'current_hash' => $v1_hash2,
            'hash_version' => 1,
        ]
    ];
    $db->replaceAuditLogs($v1_logs);
    $checkV1 = Audit::verifyChain();
    assertCondition($checkV1['isValid'] === true && $checkV1['legacyRecords'] === 2, "1. Rantai murni V1 terverifikasi valid (legacyRecords: 2)");

    // ----------------------------------------------------
    // Scenario 2: Pure V2 Chain Verification
    // ----------------------------------------------------
    echo "\n--- Skenario 2: Rantai Murni V2 ---\n";
    $v2_genesisPrev = str_repeat('0', 64);
    $v2_time1 = '2026-10-10T00:00:00.000Z';
    $v2_entry1 = [
        'id' => Database::generateUuid(),
        'sequence_number' => 1,
        'timestamp' => $v2_time1,
        'user_id' => 'SYSTEM',
        'action_type' => 'BOOTSTRAP_V2',
        'file_id' => null,
        'ip_address' => '127.0.0.1',
        'user_agent' => 'TestAgent/2.0',
        'status' => 'SUCCESS',
        'details' => null,
        'hash_version' => 2,
        'previous_hash' => $v2_genesisPrev,
    ];
    $v2_entry1['current_hash'] = Audit::computeEntryHashV2($v2_entry1);
    assertCondition(strlen($v2_entry1['current_hash']) === 64, "V2 hash is 64 hex characters (SHA-256)");

    $v2_time2 = '2026-10-10T00:05:00.000Z';
    $v2_entry2 = [
        'id' => Database::generateUuid(),
        'sequence_number' => 2,
        'timestamp' => $v2_time2,
        'user_id' => 'admin',
        'action_type' => 'ADMIN_CREATE_USER',
        'file_id' => null,
        'ip_address' => '127.0.0.1',
        'user_agent' => 'TestAgent/2.0',
        'status' => 'SUCCESS',
        'details' => 'target=alice',
        'hash_version' => 2,
        'previous_hash' => $v2_entry1['current_hash'],
    ];
    $v2_entry2['current_hash'] = Audit::computeEntryHashV2($v2_entry2);

    $v2_logs = [$v2_entry1, $v2_entry2];
    $db->replaceAuditLogs($v2_logs);
    $checkV2 = Audit::verifyChain();
    assertCondition($checkV2['isValid'] === true && $checkV2['v2Records'] === 2 && $checkV2['legacyRecords'] === 0, "2. Rantai murni V2 terverifikasi valid (v2Records: 2)");

    // ----------------------------------------------------
    // Scenario 3: Genesis Baru V3 (Fresh Installation)
    // ----------------------------------------------------
    echo "\n--- Skenario 3: Genesis Baru V3 ---\n";
    $v3_genesisPrev = str_repeat('0', 128);
    $v3_time1 = '2026-11-17T00:00:00.000Z';
    $v3_genesis = [
        'id' => Database::generateUuid(),
        'sequence_number' => 1,
        'timestamp' => $v3_time1,
        'user_id' => 'SYSTEM_BOOTSTRAP',
        'action_type' => 'SYSTEM_GENESIS',
        'file_id' => null,
        'ip_address' => '127.0.0.1',
        'user_agent' => 'SecureVault/Bootstrap',
        'status' => 'SUCCESS',
        'details' => null,
        'hash_version' => 3,
        'previous_hash' => $v3_genesisPrev,
    ];
    $v3_genesis['current_hash'] = Audit::computeEntryHashV3($v3_genesis);
    assertCondition(strlen($v3_genesis['current_hash']) === 128, "V3 hash length is 128 hex characters (SHA3-512)");
    assertCondition((bool)preg_match('/^[a-f0-9]{128}$/', $v3_genesis['current_hash']), "V3 hash format is valid hex 128");

    $db->replaceAuditLogs([$v3_genesis]);
    $checkGenesisV3 = Audit::verifyChain();
    assertCondition($checkGenesisV3['isValid'] === true && $checkGenesisV3['v3Records'] === 1, "3. Genesis baru V3 terverifikasi valid");

    // ----------------------------------------------------
    // Scenario 4: Transisi V2 ke V3
    // ----------------------------------------------------
    echo "\n--- Skenario 4: Transisi V2 ke V3 ---\n";
    // Mulai dari rantai V2 (2 records)
    $transitionLogs = $v2_logs;
    $v3_transTime = '2026-11-17T01:00:00.000Z';
    $v3_transEntry = [
        'id' => Database::generateUuid(),
        'sequence_number' => 3,
        'timestamp' => $v3_transTime,
        'user_id' => 'alice',
        'action_type' => 'AUTH_EMAIL_VERIFIED',
        'file_id' => null,
        'ip_address' => '127.0.0.1',
        'user_agent' => 'Mozilla/5.0',
        'status' => 'SUCCESS',
        'details' => null,
        'hash_version' => 3,
        'previous_hash' => $v2_entry2['current_hash'], // Mengambil hash V2 (64 hex)
    ];
    $v3_transEntry['current_hash'] = Audit::computeEntryHashV3($v3_transEntry);
    assertCondition(strlen($v3_transEntry['previous_hash']) === 64, "Transition previous_hash preserves V2 64-hex format");
    assertCondition(strlen($v3_transEntry['current_hash']) === 128, "Transition current_hash produces V3 128-hex format");

    $transitionLogs[] = $v3_transEntry;
    $db->replaceAuditLogs($transitionLogs);
    $checkTransition = Audit::verifyChain();
    assertCondition($checkTransition['isValid'] === true && $checkTransition['totalRecords'] === 3 && $checkTransition['v2Records'] === 2 && $checkTransition['v3Records'] === 1,
        "4. Transisi V2 -> V3 terverifikasi valid tanpa menghitung ulang data lama");

    // ----------------------------------------------------
    // Scenario 5: Rantai V3 Berkelanjutan
    // ----------------------------------------------------
    echo "\n--- Skenario 5: Rantai V3 Berkelanjutan ---\n";
    // Gunakan Audit::logEvent() langsung untuk membuktikan behaviour operasional baru
    $eventResult = Audit::logEvent('alice', 'VAULT_SETUP', null, '127.0.0.1', 'Mozilla/5.0', 'SUCCESS', 'vault_init=1');
    assertCondition($eventResult['sequence_number'] === 4, "New logEvent gets sequence 4");
    assertCondition($eventResult['hash_version'] === 3, "New logEvent produces hash_version = 3");
    assertCondition(strlen($eventResult['previous_hash']) === 128, "Continuous V3 previous_hash is 128 hex");
    assertCondition(strlen($eventResult['current_hash']) === 128, "Continuous V3 current_hash is 128 hex");

    $checkContinuous = Audit::verifyChain();
    assertCondition($checkContinuous['isValid'] === true && $checkContinuous['v3Records'] === 2, "5. Rantai V3 berkelanjutan via logEvent() terverifikasi valid");

    // ----------------------------------------------------
    // Scenario 6: Penolakan Genesis V3 yang Salah
    // ----------------------------------------------------
    echo "\n--- Skenario 6: Penolakan Genesis V3 yang Salah ---\n";
    $badV3Genesis = $v3_genesis;
    $badV3Genesis['previous_hash'] = str_repeat('0', 64); // Salah: V3 mencoba memakai 64 nol
    $badV3Genesis['current_hash'] = Audit::computeEntryHashV3($badV3Genesis);
    $db->replaceAuditLogs([$badV3Genesis]);
    $checkBadGenesisV3 = Audit::verifyChain();
    assertCondition($checkBadGenesisV3['isValid'] === false && str_contains($checkBadGenesisV3['message'], 'Format genesis hash tidak valid'),
        "6. Penolakan genesis V3 yang salah memakai 64 nol");

    // ----------------------------------------------------
    // Scenario 7: Penolakan Genesis V2 yang Salah
    // ----------------------------------------------------
    echo "\n--- Skenario 7: Penolakan Genesis V2 yang Salah ---\n";
    $badV2Genesis = $v2_entry1;
    $badV2Genesis['previous_hash'] = str_repeat('0', 128); // Salah: V2 mencoba memakai 128 nol
    $badV2Genesis['current_hash'] = Audit::computeEntryHashV2($badV2Genesis);
    $db->replaceAuditLogs([$badV2Genesis]);
    $checkBadGenesisV2 = Audit::verifyChain();
    assertCondition($checkBadGenesisV2['isValid'] === false && str_contains($checkBadGenesisV2['message'], 'Format genesis hash tidak valid'),
        "7. Penolakan genesis V2 yang salah memakai 128 nol");

    // ----------------------------------------------------
    // Scenario 8: Deteksi Manipulasi Entri Historis (V1/V2)
    // ----------------------------------------------------
    echo "\n--- Skenario 8: Deteksi Manipulasi Entri Historis (V1/V2) ---\n";
    $tamperedV2Logs = $db->getAuditLogs();
    // Kembalikan dulu ke rantai valid transisi (4 records)
    $db->replaceAuditLogs(array_merge($transitionLogs, [$eventResult]));
    $activeLogs = $db->getAuditLogs();
    assertCondition(Audit::verifyChain()['isValid'] === true, "Pre-tamper baseline valid");

    // Manipulasi record #2 (V2): ganti user_agent
    $activeLogs[1]['user_agent'] = 'MaliciousAgent/1.0';
    $db->replaceAuditLogs($activeLogs);
    $checkTamperV2 = Audit::verifyChain();
    assertCondition($checkTamperV2['isValid'] === false && str_contains($checkTamperV2['message'], 'Manipulasi data terdeteksi pada sequence #2'),
        "8. Deteksi manipulasi metadata pada entri historis V2 berhasil");

    // ----------------------------------------------------
    // Scenario 9: Deteksi Manipulasi Entri V3
    // ----------------------------------------------------
    echo "\n--- Skenario 9: Deteksi Manipulasi Entri V3 ---\n";
    // Kembalikan baseline
    $activeLogs[1]['user_agent'] = 'TestAgent/2.0';
    // Manipulasi record #3 (V3): ubah action_type
    $activeLogs[2]['action_type'] = 'UNAUTHORIZED_PROMOTION';
    $db->replaceAuditLogs($activeLogs);
    $checkTamperV3 = Audit::verifyChain();
    assertCondition($checkTamperV3['isValid'] === false && str_contains($checkTamperV3['message'], 'Manipulasi data terdeteksi pada sequence #3'),
        "9. Deteksi manipulasi payload pada entri V3 berhasil");

    // ----------------------------------------------------
    // Scenario 10: Deteksi Manipulasi Titik Transisi
    // ----------------------------------------------------
    echo "\n--- Skenario 10: Deteksi Manipulasi Titik Transisi ---\n";
    // Kembalikan action_type
    $activeLogs[2]['action_type'] = 'AUTH_EMAIL_VERIFIED';
    // Manipulasi previous_hash pada batas sambungan V2->V3 (sequence 3)
    $curPrev = (string)$activeLogs[2]['previous_hash'];
    $activeLogs[2]['previous_hash'] = ($curPrev[0] === '0' ? '1' : '0') . substr($curPrev, 1);
    $db->replaceAuditLogs($activeLogs);
    $checkTamperTrans = Audit::verifyChain();
    assertCondition($checkTamperTrans['isValid'] === false && str_contains($checkTamperTrans['message'], 'Rantai audit terputus pada sequence #3'),
        "10. Deteksi pemutusan rantai pada titik transisi V2->V3 berhasil");

    // ----------------------------------------------------
    // Scenario 11 & 12: Audit Anchor Lintas Versi & Kepala V3 (Skrip Aktual)
    // ----------------------------------------------------
    echo "\n--- Skenario 11 & 12: Audit Anchor Aktual (V2 & V3) ---\n";
    // 1. Set database kembali ke 2 record V2
    $v2Logs = [$v2_entry1, $v2_entry2];
    $db->replaceAuditLogs($v2Logs);
    $anchorV2File = $dataDir . DIRECTORY_SEPARATOR . 'anchor-v2.json';
    $anchorV3File = $dataDir . DIRECTORY_SEPARATOR . 'anchor-v3.json';

    // Export anchor V2 menggunakan skrip aktual
    $resExportV2 = runCliScript('backend_php/scripts/export_audit_anchor.php', [$anchorV2File]);
    assertCondition($resExportV2['code'] === 0, "11a. Ekspor anchor V2 via skrip aktual berhasil (exit 0)", $resExportV2['stderr']);

    // Verifikasi anchor V2 menggunakan skrip aktual pada kondisi 2 record
    $resVerV2 = runCliScript('backend_php/scripts/verify_audit_anchor.php', [$anchorV2File]);
    assertCondition($resVerV2['code'] === 0, "11b. Verifikasi anchor V2 via skrip aktual berhasil (exit 0)", $resVerV2['stderr']);

    // 2. Sekarang perluas rantai dengan menambahkan record V3 (sequence 3 dan 4)
    $valid4Records = array_merge($transitionLogs, [$eventResult]);
    $db->replaceAuditLogs($valid4Records);
    assertCondition(Audit::verifyChain()['isValid'] === true, "Full 4-record chain valid");

    // Verifikasi kembali checkpoint V2 lama pada rantai yang SUDAH bertambah entri V3
    $resVerV2After = runCliScript('backend_php/scripts/verify_audit_anchor.php', [$anchorV2File]);
    assertCondition($resVerV2After['code'] === 0, "11c. Checkpoint V2 lama tetap valid pada rantai yang bertambah V3", $resVerV2After['stderr']);

    // 3. Export anchor V3 baru menggunakan skrip aktual pada rantai 4 record (head V3)
    $resExportV3 = runCliScript('backend_php/scripts/export_audit_anchor.php', [$anchorV3File]);
    assertCondition($resExportV3['code'] === 0, "12a. Ekspor anchor V3 via skrip aktual berhasil (exit 0)", $resExportV3['stderr']);

    $v3Doc = json_decode((string)file_get_contents($anchorV3File), true);
    assertCondition(isset($v3Doc['payload']['head_hash']) && strlen($v3Doc['payload']['head_hash']) === 128,
        "12b. Head hash pada dokumen anchor V3 memiliki panjang 128 karakter (SHA3-512)");

    // Verifikasi anchor V3 baru menggunakan skrip aktual
    $resVerV3 = runCliScript('backend_php/scripts/verify_audit_anchor.php', [$anchorV3File]);
    assertCondition($resVerV3['code'] === 0, "12c. Verifikasi anchor V3 via skrip aktual berhasil (exit 0)", $resVerV3['stderr']);

    echo "\n========================================================\n";
    echo "  RINGKASAN HASIL TEST: {$passedTests} PASSED, {$failedTests} FAILED  \n";
    echo "========================================================\n";

} finally {
    // Bersihkan direktori runtime temporer
    if (is_dir($testRootDir)) {
        $files = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($testRootDir, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::CHILD_FIRST
        );
        foreach ($files as $fileinfo) {
            $fileinfo->isDir() ? @rmdir($fileinfo->getRealPath()) : @unlink($fileinfo->getRealPath());
        }
        @rmdir($testRootDir);
    }
}

if ($failedTests > 0) {
    exit(1);
}
exit(0);
