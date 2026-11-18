<?php
// backend_php/tests/persistent_storage_recovery_test.php
// Comprehensive test suite for Perbaikan 4: Persistent Local Storage & Automatic Recovery.
// Covers 14 specific scenarios mandated by the project requirements.

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit(1);
}

require_once dirname(__DIR__) . '/utils/PersistentStorage.php';

$totalAssertions = 0;
$passedAssertions = 0;

function assertCondition(bool $condition, string $message): void
{
    global $totalAssertions, $passedAssertions;
    $totalAssertions++;
    if ($condition) {
        $passedAssertions++;
        echo "  [PASS] {$message}\n";
    } else {
        echo "  [FAIL] {$message}\n";
        throw new RuntimeException("Assertion failed: {$message}");
    }
}

function createTempDir(string $prefix = 'sv-test-'): string
{
    $dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . $prefix . bin2hex(random_bytes(6));
    if (!mkdir($dir, 0700, true)) {
        throw new RuntimeException("Cannot create temp directory: {$dir}");
    }
    return $dir;
}

function removeDirRecursive(string $dir): void
{
    if (!is_dir($dir)) return;
    $items = scandir($dir) ?: [];
    foreach ($items as $item) {
        if ($item === '.' || $item === '..') continue;
        $path = $dir . DIRECTORY_SEPARATOR . $item;
        if (is_dir($path) && !is_link($path)) {
            removeDirRecursive($path);
        } else {
            @unlink($path);
        }
    }
    @rmdir($dir);
}

echo "========================================================\n";
echo "  SECURE VAULT - PERSISTENT STORAGE & RECOVERY TESTS    \n";
echo "========================================================\n\n";

$tempRoots = [];

try {
    // ---------------------------------------------------------
    // Skenario 1: Instalasi baru tanpa database
    // ---------------------------------------------------------
    echo "--- Skenario 1: Instalasi baru tanpa database ---\n";
    $testSandbox1 = createTempDir('sv-scen1-');
    $tempRoots[] = $testSandbox1;
    $targetDir1 = $testSandbox1 . DIRECTORY_SEPARATOR . 'persistent';
    $projectDir1 = $testSandbox1 . DIRECTORY_SEPARATOR . 'project';
    mkdir($projectDir1, 0700, true);

    $res1 = PersistentStorage::bootstrap($projectDir1, $targetDir1, false);
    assertCondition($res1['status'] === PersistentStorage::STATUS_NEW_INSTALLATION, 'Status adalah NEW_INSTALLATION');
    assertCondition(is_dir($targetDir1 . DIRECTORY_SEPARATOR . 'data'), 'Direktori data baru disiapkan');
    assertCondition(!is_file($targetDir1 . DIRECTORY_SEPARATOR . 'data' . DIRECTORY_SEPARATOR . 'secure-vault.sqlite'), 'Database belum dibuat sebelum ada proses init resmi');

    // ---------------------------------------------------------
    // Skenario 2 & 3 & 4 & 5: Upgrade dari project lama ke ZIP baru
    // Database lama ditemukan, akun lama dan password lama tetap ada
    // ---------------------------------------------------------
    echo "\n--- Skenario 2, 3, 4, 5: Upgrade folder & Pemulihan Akun/Password ---\n";
    $testSandbox2 = createTempDir('sv-scen2-');
    $tempRoots[] = $testSandbox2;

    $oldProjectDir = $testSandbox2 . DIRECTORY_SEPARATOR . 'old-install' . DIRECTORY_SEPARATOR . 'secure-vault-main';
    $oldVarDir = $oldProjectDir . DIRECTORY_SEPARATOR . 'var' . DIRECTORY_SEPARATOR . 'secure-vault';
    $oldDataDir = $oldVarDir . DIRECTORY_SEPARATOR . 'data';
    $oldStorageDir = $oldVarDir . DIRECTORY_SEPARATOR . 'storage';
    mkdir($oldDataDir, 0700, true);
    mkdir($oldStorageDir, 0700, true);

    $oldDbFile = $oldDataDir . DIRECTORY_SEPARATOR . 'secure-vault.sqlite';

    // Seed mock SQLite database with relational schema and sample user
    $pdo = new PDO('sqlite:' . $oldDbFile, null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
    $schemaPath = dirname(__DIR__) . DIRECTORY_SEPARATOR . 'db' . DIRECTORY_SEPARATOR . 'schema_sqlite.sql';
    $pdo->exec(file_get_contents($schemaPath));
    $pdo->exec('PRAGMA user_version = 2');

    // Create user and password hash
    $rawPassword = 'Password-Rahasia-Lama-123!';
    $pwdHash = password_hash($rawPassword, PASSWORD_DEFAULT);
    $userId = 'test-user-uuid-1';
    $stmt = $pdo->prepare("INSERT INTO users (id, record_key, username, email, role, is_active, storage_quota_bytes, storage_used_bytes, payload) VALUES (?, ?, ?, ?, ?, 1, 1000, 0, ?)");
    $userPayload = [
        'id' => $userId,
        'username' => 'alice_old',
        'email' => 'alice@securevault.test',
        'password_hash' => $pwdHash,
        'role' => 'admin',
        'is_active' => true,
        'session_version' => 0,
        'storage_quota_bytes' => 1000,
        'storage_used_bytes' => 0,
    ];
    $stmt->execute([$userId, $userId, 'alice_old', 'alice@securevault.test', 'admin', json_encode($userPayload)]);

    // Insert SHA3-512 V3 audit genesis
    $genesisHash = str_repeat('a', 128);
    $auditStmt = $pdo->prepare("INSERT INTO audit_logs (id, record_key, sequence_number, timestamp, user_id, action_type, status, previous_hash, current_hash, payload) VALUES (?, ?, 1, ?, 'SYSTEM_GENESIS', 'SYSTEM_GENESIS', 'SUCCESS', ?, ?, ?)");
    $auditStmt->execute(['audit-1', 'audit-1', gmdate('Y-m-d\TH:i:s.000\Z'), str_repeat('0', 128), $genesisHash, json_encode(['version' => 3])]);

    // Create secrets.php in old installation
    $oldSecrets = ['JWT_SECRET' => bin2hex(random_bytes(32)), 'MFA_ENCRYPTION_KEY' => base64_encode(random_bytes(32))];
    file_put_contents($oldVarDir . DIRECTORY_SEPARATOR . 'secrets.php', "<?php return " . var_export($oldSecrets, true) . ";\n");

    // Create mock encrypted chunk file
    $chunkDir = $oldStorageDir . DIRECTORY_SEPARATOR . 'file-uuid-101';
    mkdir($chunkDir, 0700, true);
    file_put_contents($chunkDir . DIRECTORY_SEPARATOR . 'chunk_0.bin', 'ENCRYPTED_CIPHERTEXT_SAMPLE_DATA_12345');

    unset($pdo);

    // New extraction folder simulating fresh ZIP extraction
    $newProjectDir = $testSandbox2 . DIRECTORY_SEPARATOR . 'new-zip-extract' . DIRECTORY_SEPARATOR . 'secure-vault-v2';
    mkdir($newProjectDir, 0700, true);
    $persistentDir2 = $testSandbox2 . DIRECTORY_SEPARATOR . 'appdata-securevault';

    // Run bootstrap from new ZIP project pointing to persistent location
    $res2 = PersistentStorage::bootstrap($newProjectDir, $persistentDir2, false);
    if ($res2['status'] !== PersistentStorage::STATUS_RECOVERED) {
        print_r($res2);
    }
    assertCondition($res2['status'] === PersistentStorage::STATUS_RECOVERED, 'Skenario 2 & 3: Status adalah RECOVERED');
    assertCondition(is_file($persistentDir2 . DIRECTORY_SEPARATOR . 'data' . DIRECTORY_SEPARATOR . 'secure-vault.sqlite'), 'Database berhasil disalin ke persistent directory');

    // Skenario 4: Akun pengguna lama tetap tersedia
    $recovPdo = new PDO('sqlite:' . $persistentDir2 . DIRECTORY_SEPARATOR . 'data' . DIRECTORY_SEPARATOR . 'secure-vault.sqlite');
    $uRow = $recovPdo->query("SELECT payload FROM users WHERE username = 'alice_old'")->fetch(PDO::FETCH_ASSOC);
    assertCondition(!empty($uRow), 'Skenario 4: Akun pengguna lama "alice_old" ditemukan');
    $uData = json_decode($uRow['payload'], true);

    // Skenario 5: Password lama tetap dapat diverifikasi
    require_once dirname(__DIR__) . '/db/Database.php';
    $pwdVerified = Database::verifyPassword($rawPassword, $uData['password_hash']);
    assertCondition($pwdVerified === true, 'Skenario 5: Password lama berhasil diverifikasi dengan password hash asli');

    // Skenario 7: Storage dan chunk terenkripsi tetap dapat dibaca
    $recovChunkFile = $persistentDir2 . DIRECTORY_SEPARATOR . 'storage' . DIRECTORY_SEPARATOR . 'file-uuid-101' . DIRECTORY_SEPARATOR . 'chunk_0.bin';
    assertCondition(is_file($recovChunkFile), 'Skenario 7: Berkas chunk terenkripsi berhasil dipulihkan');
    assertCondition(file_get_contents($recovChunkFile) === 'ENCRYPTED_CIPHERTEXT_SAMPLE_DATA_12345', 'Skenario 7: Isi chunk terenkripsi 100% utuh');

    // Skenario 8: Secret dan konfigurasi MFA tetap tersedia
    $recovSecretsFile = $persistentDir2 . DIRECTORY_SEPARATOR . 'secrets.php';
    assertCondition(is_file($recovSecretsFile), 'Skenario 8: secrets.php dipulihkan');
    $loadedSec = require $recovSecretsFile;
    assertCondition($loadedSec['MFA_ENCRYPTION_KEY'] === $oldSecrets['MFA_ENCRYPTION_KEY'], 'Skenario 8: MFA_ENCRYPTION_KEY cocok persis dengan instalasi lama');

    unset($recovPdo);

    // ---------------------------------------------------------
    // Skenario 6: Database lama dengan WAL
    // ---------------------------------------------------------
    echo "\n--- Skenario 6: Database lama dengan WAL aktif ---\n";
    $testSandbox6 = createTempDir('sv-scen6-');
    $tempRoots[] = $testSandbox6;
    $walDbDir = $testSandbox6 . DIRECTORY_SEPARATOR . 'wal-data';
    mkdir($walDbDir, 0700, true);
    $walDbFile = $walDbDir . DIRECTORY_SEPARATOR . 'secure-vault.sqlite';

    $walPdo = new PDO('sqlite:' . $walDbFile, null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
    $walPdo->exec('PRAGMA journal_mode=WAL');
    $walPdo->exec(file_get_contents($schemaPath));
    $walPdo->exec('PRAGMA user_version = 2');
    $walPdo->exec("INSERT INTO users (id, record_key, username, email, role, is_active, storage_quota_bytes, storage_used_bytes, payload) VALUES ('u2', 'u2', 'bob_wal', 'bob@test.test', 'user', 1, 100, 0, '{}')");
    $walPdo->exec("INSERT INTO audit_logs (id, record_key, sequence_number, timestamp, user_id, action_type, status, previous_hash, current_hash, payload) VALUES ('a1', 'a1', 1, '2026-01-01', 'SYS', 'ACT', 'SUCCESS', '0', '1', '{}')");
    // Ensure WAL file exists on disk
    assertCondition(is_file($walDbFile), 'Database file dibuat');

    file_put_contents($walDbDir . DIRECTORY_SEPARATOR . 'secrets.php', "<?php return ['JWT_SECRET' => str_repeat('w', 32), 'MFA_ENCRYPTION_KEY' => base64_encode(random_bytes(32))];\n");

    $persistentDir6 = $testSandbox6 . DIRECTORY_SEPARATOR . 'persistent6';
    $cand6 = PersistentStorage::inspectCandidate($walDbFile);
    assertCondition($cand6 !== null, 'Kandidat WAL lolos verifikasi inspectCandidate');
    $recReceipt = PersistentStorage::recover($cand6, $persistentDir6);
    assertCondition($recReceipt['user_count'] === 1, 'Skenario 6: Pemulihan database dengan WAL berhasil');
    unset($walPdo);

    // ---------------------------------------------------------
    // Skenario 9: Dua kandidat database lama yang ambigu
    // ---------------------------------------------------------
    echo "\n--- Skenario 9: Dua kandidat database lama ambigu ---\n";
    $testSandbox9 = createTempDir('sv-scen9-');
    $tempRoots[] = $testSandbox9;

    $candDirA = $testSandbox9 . DIRECTORY_SEPARATOR . 'install-a' . DIRECTORY_SEPARATOR . 'var' . DIRECTORY_SEPARATOR . 'secure-vault' . DIRECTORY_SEPARATOR . 'data';
    $candDirB = $testSandbox9 . DIRECTORY_SEPARATOR . 'install-b' . DIRECTORY_SEPARATOR . 'var' . DIRECTORY_SEPARATOR . 'secure-vault' . DIRECTORY_SEPARATOR . 'data';
    mkdir($candDirA, 0700, true);
    mkdir($candDirB, 0700, true);

    $dbA = $candDirA . DIRECTORY_SEPARATOR . 'secure-vault.sqlite';
    $dbB = $candDirB . DIRECTORY_SEPARATOR . 'secure-vault.sqlite';

    foreach ([$dbA, $dbB] as $idx => $dbPath) {
        $p = new PDO('sqlite:' . $dbPath, null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
        $p->exec(file_get_contents($schemaPath));
        $p->exec('PRAGMA user_version = 2');
        $p->exec("INSERT INTO users (id, record_key, username, email, role, is_active, storage_quota_bytes, storage_used_bytes, payload) VALUES ('u-{$idx}', 'u-{$idx}', 'user_{$idx}', 'u{$idx}@test.test', 'user', 1, 100, 0, '{}')");
        $p->exec("INSERT INTO audit_logs (id, record_key, sequence_number, timestamp, user_id, action_type, status, previous_hash, current_hash, payload) VALUES ('a-{$idx}', 'a-{$idx}', 1, '2026-01-01', 'SYS', 'ACT', 'SUCCESS', '0', '1', '{}')");
        unset($p);
    }

    $proj9 = $testSandbox9 . DIRECTORY_SEPARATOR . 'active-proj';
    mkdir($proj9, 0700, true);
    $target9 = $testSandbox9 . DIRECTORY_SEPARATOR . 'target9';

    $res9 = PersistentStorage::bootstrap($proj9, $target9, false);
    assertCondition($res9['status'] === PersistentStorage::STATUS_AMBIGUOUS_CANDIDATES, 'Skenario 9: Deteksi ambiguitas berhasil (STATUS_AMBIGUOUS_CANDIDATES)');
    assertCondition(count($res9['candidates']) >= 2, 'Skenario 9: Daftar kandidat menampilkan kedua database');

    // ---------------------------------------------------------
    // Skenario 10 & Skenario H: Kegagalan pemulihan di tengah proses dan rollback bersih
    // ---------------------------------------------------------
    echo "\n--- Skenario 10 & H: Penolakan file korup & Rollback jika gagal di tengah proses ---\n";
    $testSandbox10 = createTempDir('sv-scen10-');
    $tempRoots[] = $testSandbox10;
    $corruptDb = $testSandbox10 . DIRECTORY_SEPARATOR . 'secure-vault.sqlite';
    file_put_contents($corruptDb, 'CORRUPT_NOT_A_SQLITE_FILE_CONTENT_XYZ');
    $cand10 = PersistentStorage::inspectCandidate($corruptDb);
    assertCondition($cand10 === null, 'Skenario 10: Berkas korup ditolak oleh inspectCandidate (return null)');

    // Skenario H: Simulasi kegagalan di tengah proses (secrets.php unreadable / copy fail)
    $testSandboxH = createTempDir('sv-scenH-');
    $tempRoots[] = $testSandboxH;
    $hDbDir = $testSandboxH . DIRECTORY_SEPARATOR . 'old' . DIRECTORY_SEPARATOR . 'var' . DIRECTORY_SEPARATOR . 'secure-vault' . DIRECTORY_SEPARATOR . 'data';
    $hVarDir = dirname($hDbDir);
    mkdir($hDbDir, 0700, true);
    $hDbFile = $hDbDir . DIRECTORY_SEPARATOR . 'secure-vault.sqlite';

    $pH = new PDO('sqlite:' . $hDbFile, null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
    $pH->exec(file_get_contents($schemaPath));
    $pH->exec('PRAGMA user_version = 2');
    $pH->exec("INSERT INTO users (id, record_key, username, email, role, is_active, storage_quota_bytes, storage_used_bytes, payload) VALUES ('uh', 'uh', 'user_h', 'h@test.test', 'user', 1, 100, 0, '{}')");
    $pH->exec("INSERT INTO audit_logs (id, record_key, sequence_number, timestamp, user_id, action_type, status, previous_hash, current_hash, payload) VALUES ('ah', 'ah', 1, '2026-01-01', 'SYS', 'ACT', 'SUCCESS', '0', '1', '{}')");
    unset($pH);

    // Create candidate with has_secrets metadata, but secrets.php is made unreadable / missing at copy time
    $candH = PersistentStorage::inspectCandidate($hDbFile);
    $candH['has_secrets'] = true; // force secrets requirement
    // no secrets.php exists in hVarDir, so recover() will fail safely

    $targetH = $testSandboxH . DIRECTORY_SEPARATOR . 'persistentH';
    $failedSafely = false;
    try {
        PersistentStorage::recover($candH, $targetH);
    } catch (Throwable $e) {
        $failedSafely = true;
    }
    assertCondition($failedSafely === true, 'Skenario H: Kegagalan pemulihan secret melempar exception secara aman');
    assertCondition(!is_file($targetH . DIRECTORY_SEPARATOR . 'data' . DIRECTORY_SEPARATOR . 'secure-vault.sqlite'), 'Skenario H: Database sementara dibersihkan, tidak ada berkas korup tersisa');
    assertCondition(!is_file($targetH . DIRECTORY_SEPARATOR . 'secrets.php'), 'Skenario H: Tidak ada secrets.php palsu yang tertinggal');

    // ---------------------------------------------------------
    // Skenario 11 & 12: Instalasi kedua kali & restart tidak menduplikasi data
    // ---------------------------------------------------------
    echo "\n--- Skenario 11 & 12: Idempotensi dan restart tanpa duplikasi ---\n";
    $testSandbox11 = createTempDir('sv-scen11-');
    $tempRoots[] = $testSandbox11;
    $target11 = $testSandbox11 . DIRECTORY_SEPARATOR . 'persistent11';
    $proj11 = $testSandbox11 . DIRECTORY_SEPARATOR . 'project11';
    mkdir($proj11, 0700, true);

    // First bootstrap -> NEW_INSTALLATION
    $res11a = PersistentStorage::bootstrap($proj11, $target11, false);
    assertCondition($res11a['status'] === PersistentStorage::STATUS_NEW_INSTALLATION, 'Init pertama menghasilkan NEW_INSTALLATION');

    // Create database in persistent target
    $db11 = $target11 . DIRECTORY_SEPARATOR . 'data' . DIRECTORY_SEPARATOR . 'secure-vault.sqlite';
    $pdo11 = new PDO('sqlite:' . $db11, null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
    $pdo11->exec(file_get_contents($schemaPath));
    $pdo11->exec('PRAGMA user_version = 2');
    $pdo11->exec("INSERT INTO users (id, record_key, username, email, role, is_active, storage_quota_bytes, storage_used_bytes, payload) VALUES ('u11', 'u11', 'user11', 'u11@test.test', 'admin', 1, 100, 0, '{}')");
    $pdo11->exec("INSERT INTO audit_logs (id, record_key, sequence_number, timestamp, user_id, action_type, status, previous_hash, current_hash, payload) VALUES ('a11', 'a11', 1, '2026-01-01', 'SYS', 'ACT', 'SUCCESS', '0', '1', '{}')");
    unset($pdo11);

    // Second bootstrap -> ALREADY_EXISTS
    $res11b = PersistentStorage::bootstrap($proj11, $target11, false);
    assertCondition($res11b['status'] === PersistentStorage::STATUS_ALREADY_EXISTS, 'Skenario 11 & 12: Bootstrap kedua mendeteksi ALREADY_EXISTS');
    assertCondition($res11b['info']['user_count'] === 1, 'Data tidak terduplikasi (user_count tetap 1)');

    // Third bootstrap (simulating application restart)
    $res11c = PersistentStorage::bootstrap($proj11, $target11, false);
    assertCondition($res11c['status'] === PersistentStorage::STATUS_ALREADY_EXISTS, 'Restart aplikasi menggunakan kembali database tanpa reset');

    // ---------------------------------------------------------
    // Skenario 13: Audit SHA3-512 V3 tetap valid pada database dipulihkan
    // ---------------------------------------------------------
    echo "\n--- Skenario 13: Integritas rantai audit SHA3-512 V3 ---\n";
    require_once dirname(__DIR__) . '/utils/Audit.php';
    // Create chain with V3 in recovered db
    $testSandbox13 = createTempDir('sv-scen13-');
    $tempRoots[] = $testSandbox13;
    $dbFile13 = $testSandbox13 . DIRECTORY_SEPARATOR . 'data' . DIRECTORY_SEPARATOR . 'secure-vault.sqlite';
    mkdir(dirname($dbFile13), 0700, true);

    $pdo13 = new PDO('sqlite:' . $dbFile13, null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
    $pdo13->exec(file_get_contents($schemaPath));
    $pdo13->exec('PRAGMA user_version = 2');

    // Build genuine SHA3-512 chain
    $genId = 'gen-13';
    $genTime = gmdate('Y-m-d\TH:i:s.000\Z');
    $genPayload = [
        'version' => 3,
        'id' => $genId,
        'sequence_number' => 1,
        'timestamp' => $genTime,
        'user_id' => 'SYS',
        'action_type' => 'SYSTEM_GENESIS',
        'file_id' => null,
        'status' => 'SUCCESS',
        'ip_address' => '127.0.0.1',
        'user_agent' => 'Test/13',
        'details' => null,
        'previous_hash' => str_repeat('0', 128),
    ];
    $genHash = Audit::computeEntryHashV3($genPayload);
    $pdo13->exec("INSERT INTO audit_logs (id, record_key, sequence_number, timestamp, user_id, action_type, status, previous_hash, current_hash, payload) VALUES ('{$genId}', '{$genId}', 1, '{$genTime}', 'SYS', 'SYSTEM_GENESIS', 'SUCCESS', '" . str_repeat('0', 128) . "', '{$genHash}', '" . json_encode($genPayload) . "')");
    $pdo13->exec("INSERT INTO users (id, record_key, username, email, role, is_active, storage_quota_bytes, storage_used_bytes, payload) VALUES ('u13', 'u13', 'admin13', 'admin13@test.test', 'admin', 1, 100, 0, '{}')");
    unset($pdo13);
    file_put_contents($testSandbox13 . DIRECTORY_SEPARATOR . 'secrets.php', "<?php return ['JWT_SECRET' => str_repeat('k', 32), 'MFA_ENCRYPTION_KEY' => base64_encode(random_bytes(32))];\n");

    // Recover this database
    $target13 = $testSandbox13 . DIRECTORY_SEPARATOR . 'persistent13';
    $cand13 = PersistentStorage::inspectCandidate($dbFile13);
    PersistentStorage::recover($cand13, $target13);

    // Verify chain on recovered database directly
    $recoveredDb13 = $target13 . DIRECTORY_SEPARATOR . 'data' . DIRECTORY_SEPARATOR . 'secure-vault.sqlite';
    $pRec13 = new PDO('sqlite:' . $recoveredDb13);
    $row13 = $pRec13->query('SELECT * FROM audit_logs WHERE sequence_number = 1')->fetch(PDO::FETCH_ASSOC);
    $pay13 = json_decode($row13['payload'], true);
    $recomputed13 = Audit::computeEntryHashV3($pay13);
    assertCondition(hash_equals($recomputed13, $row13['current_hash']), 'Skenario 13: Hash entri genesis V3 cocok persis (SHA3-512)');
    assertCondition(strlen($row13['current_hash']) === 128, 'Skenario 13: Panjang hash adalah 128 karakter heksadesimal');
    unset($pRec13);

    // ---------------------------------------------------------
    // Skenario 14: Database tidak berubah ketika source code diperbarui
    // ---------------------------------------------------------
    echo "\n--- Skenario 14: Integritas database tetap utuh saat source code diperbarui ---\n";
    $testSandbox14 = createTempDir('sv-scen14-');
    $tempRoots[] = $testSandbox14;
    $target14 = $testSandbox14 . DIRECTORY_SEPARATOR . 'persistent14';
    $projV1 = $testSandbox14 . DIRECTORY_SEPARATOR . 'project-v1';
    $projV2 = $testSandbox14 . DIRECTORY_SEPARATOR . 'project-v2';
    mkdir($projV1, 0700, true);
    mkdir($projV2, 0700, true);

    // Setup initial persistent DB
    PersistentStorage::bootstrap($projV1, $target14, false);
    $db14 = $target14 . DIRECTORY_SEPARATOR . 'data' . DIRECTORY_SEPARATOR . 'secure-vault.sqlite';
    $p14 = new PDO('sqlite:' . $db14, null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
    $p14->exec(file_get_contents($schemaPath));
    $p14->exec('PRAGMA user_version = 2');
    $p14->exec("INSERT INTO users (id, record_key, username, email, role, is_active, storage_quota_bytes, storage_used_bytes, payload) VALUES ('u14', 'u14', 'stable_user', 'stable@test.test', 'admin', 1, 100, 0, '{}')");
    $p14->exec("INSERT INTO audit_logs (id, record_key, sequence_number, timestamp, user_id, action_type, status, previous_hash, current_hash, payload) VALUES ('a14', 'a14', 1, '2026-01-01', 'SYS', 'ACT', 'SUCCESS', '0', '1', '{}')");
    $p14->exec('PRAGMA wal_checkpoint(TRUNCATE)');
    unset($p14);

    $hashBefore = hash_file('sha256', $db14);

    // Simulating project-v2 running bootstrap
    $res14 = PersistentStorage::bootstrap($projV2, $target14, false);
    assertCondition($res14['status'] === PersistentStorage::STATUS_ALREADY_EXISTS, 'Project baru langsung mendeteksi database persisten yang ada');

    $hashAfter = hash_file('sha256', $db14);
    assertCondition($hashBefore === $hashAfter, 'Skenario 14: Hash file database identik sebelum dan setelah source code diperbarui');

    // ---------------------------------------------------------
    // Skenario Tambahan: Initial Administrator Setup (init_admin.php)
    // ---------------------------------------------------------
    echo "\n--- Pengujian Initial Administrator Setup (init_admin.php) ---\n";
    $testSandboxAdmin = createTempDir('sv-scenAdmin-');
    $tempRoots[] = $testSandboxAdmin;
    $targetAdmin = $testSandboxAdmin . DIRECTORY_SEPARATOR . 'persistentAdmin';
    $projAdmin = $testSandboxAdmin . DIRECTORY_SEPARATOR . 'projectAdmin';
    mkdir($projAdmin, 0700, true);

    // Bootstrap fresh target
    PersistentStorage::bootstrap($projAdmin, $targetAdmin, false);
    $adminDbPath = $targetAdmin . DIRECTORY_SEPARATOR . 'data' . DIRECTORY_SEPARATOR . 'secure-vault.sqlite';

    // Seed empty relational DB
    $pAdmin = new PDO('sqlite:' . $adminDbPath, null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
    $pAdmin->exec(file_get_contents($schemaPath));
    $pAdmin->exec('PRAGMA user_version = 2');
    unset($pAdmin);

    $phpBin = PHP_BINARY;
    $cmd1 = "\"{$phpBin}\" backend_php/scripts/init_admin.php testadmin \"StrongAdminPassphrase123!\" admin@test.local";
    $stringEnv = array_filter($_SERVER, 'is_string');
    $envAdmin = array_merge($stringEnv, [
        'SECURE_VAULT_DATA_DIR' => $targetAdmin . DIRECTORY_SEPARATOR . 'data',
        'SECURE_VAULT_PERSISTENT_DIR' => $targetAdmin
    ]);
    $proc1 = proc_open($cmd1, [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes1, dirname(__DIR__, 2), $envAdmin);
    $out1 = stream_get_contents($pipes1[1]);
    $err1 = stream_get_contents($pipes1[2]);
    fclose($pipes1[1]); fclose($pipes1[2]);
    $exit1 = proc_close($proc1);
    if ($exit1 !== 0) {
        echo "proc1 out: " . $out1 . "\n";
        echo "proc1 err: " . $err1 . "\n";
    }
    assertCondition($exit1 === 0, 'init_admin.php berhasil membuat admin pertama pada database kosong (exit code 0)');

    // Verify user was inserted
    $pAdminCheck = new PDO('sqlite:' . $adminDbPath);
    $uCount = (int)$pAdminCheck->query('SELECT COUNT(*) FROM users')->fetchColumn();
    assertCondition($uCount === 1, 'Jumlah pengguna bertambah tepat 1');
    $admRow = $pAdminCheck->query("SELECT * FROM users WHERE username = 'testadmin'")->fetch(PDO::FETCH_ASSOC);
    assertCondition($admRow['role'] === 'admin', 'Role pengguna baru adalah admin');
    $admAudit = $pAdminCheck->query("SELECT * FROM audit_logs WHERE action_type = 'ADMIN_INITIAL_SETUP'")->fetch(PDO::FETCH_ASSOC);
    assertCondition(!empty($admAudit), 'Audit log ADMIN_INITIAL_SETUP tercatat di audit trail');
    unset($pAdminCheck);

    // Second run must be rejected
    $cmd2 = "\"{$phpBin}\" backend_php/scripts/init_admin.php secondadmin \"AnotherPassword123!\" second@test.local";
    $proc2 = proc_open($cmd2, [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes2, dirname(__DIR__, 2), $envAdmin);
    $out2 = stream_get_contents($pipes2[1]);
    $err2 = stream_get_contents($pipes2[2]);
    fclose($pipes2[1]); fclose($pipes2[2]);
    $exit2 = proc_close($proc2);
    assertCondition($exit2 === 1, 'init_admin.php menolak pembuatan admin kedua (exit code 1)');

} finally {
    foreach ($tempRoots as $root) {
        removeDirRecursive($root);
    }
}

echo "\n========================================================\n";
echo "  HASIL AKHIR PENGUJIAN: {$passedAssertions} / {$totalAssertions} ASSERTIONS PASSED\n";
echo "========================================================\n";
exit(0);
