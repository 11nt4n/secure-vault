<?php
// backend_php/tests/legacy_structure_simulation_test.php
// Dedicated simulation test for legacy bd43a46 installation structures and failure scenarios.

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit(1);
}

require_once dirname(__DIR__) . '/utils/PersistentStorage.php';
require_once dirname(__DIR__) . '/utils/Audit.php';

$totalChecks = 0;
$passedChecks = 0;

function check(bool $condition, string $label): void
{
    global $totalChecks, $passedChecks;
    $totalChecks++;
    if ($condition) {
        $passedChecks++;
        echo "  [PASS] {$label}\n";
    } else {
        echo "  [FAIL] {$label}\n";
        throw new RuntimeException("Check failed: {$label}");
    }
}

function makeTemp(string $prefix = 'legacy-sim-'): string
{
    $dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . $prefix . bin2hex(random_bytes(6));
    mkdir($dir, 0700, true);
    return $dir;
}

function cleanTemp(string $dir): void
{
    if (!is_dir($dir)) return;
    $items = scandir($dir) ?: [];
    foreach ($items as $item) {
        if ($item === '.' || $item === '..') continue;
        $path = $dir . DIRECTORY_SEPARATOR . $item;
        if (is_dir($path) && !is_link($path)) {
            cleanTemp($path);
        } else {
            @unlink($path);
        }
    }
    @rmdir($dir);
}

echo "========================================================\n";
echo "  LEGACY bd43a46 COMPATIBILITY & FAILURE SCENARIOS TEST \n";
echo "========================================================\n\n";

$schemaPath = dirname(__DIR__) . DIRECTORY_SEPARATOR . 'db' . DIRECTORY_SEPARATOR . 'schema_sqlite.sql';
$sandboxes = [];

try {
    // -------------------------------------------------------------
    // PART 1: Real ZIP Extraction Simulation with bd43a46 Layout
    // -------------------------------------------------------------
    echo "--- 1. Simulasi Migrasi Struktur Riil bd43a46 ---\n";
    $root = makeTemp('sv-zip-sim-');
    $sandboxes[] = $root;

    $oldProjectDir = $root . DIRECTORY_SEPARATOR . 'OldProject';
    $newProjectDir = $root . DIRECTORY_SEPARATOR . 'NewProject';
    $mockLocalAppData = $root . DIRECTORY_SEPARATOR . 'LocalUserData' . DIRECTORY_SEPARATOR . 'AppData' . DIRECTORY_SEPARATOR . 'Local';
    $persistentDir = $mockLocalAppData . DIRECTORY_SEPARATOR . 'SecureVault';

    mkdir($oldProjectDir, 0700, true);
    mkdir($newProjectDir, 0700, true);
    mkdir($mockLocalAppData, 0700, true);

    // Setup bd43a46 historical directory layout
    $oldVar = $oldProjectDir . DIRECTORY_SEPARATOR . 'var' . DIRECTORY_SEPARATOR . 'secure-vault';
    $oldData = $oldVar . DIRECTORY_SEPARATOR . 'data';
    $oldStorage = $oldVar . DIRECTORY_SEPARATOR . 'storage'; // Verified from bd43a46 config.php!
    mkdir($oldData, 0700, true);
    mkdir($oldStorage, 0700, true);

    // 1. Database with users, files, chunks, and audit chain
    $oldDbFile = $oldData . DIRECTORY_SEPARATOR . 'secure-vault.sqlite';
    $pdo = new PDO('sqlite:' . $oldDbFile, null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
    $pdo->exec(file_get_contents($schemaPath));
    $pdo->exec('PRAGMA user_version = 2');

    $uid = 'legacy-user-uuid-1';
    $rawPwd = 'OldSecurePassword2026!';
    $pwdHash = password_hash($rawPwd, PASSWORD_DEFAULT);
    $userPayload = [
        'id' => $uid,
        'username' => 'legacy_admin',
        'email' => 'admin@legacy.vault',
        'password_hash' => $pwdHash,
        'role' => 'admin',
        'is_active' => true,
    ];
    $pdo->prepare("INSERT INTO users (id, record_key, username, email, role, is_active, storage_quota_bytes, storage_used_bytes, payload) VALUES (?, ?, ?, ?, ?, 1, 1000000, 500, ?)")
        ->execute([$uid, $uid, 'legacy_admin', 'admin@legacy.vault', 'admin', json_encode($userPayload)]);

    // Genesis audit record (V3 SHA3-512)
    $genId = 'gen-uuid-1';
    $genTime = '2026-11-01T10:00:00.000Z';
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
        'user_agent' => 'LegacyAgent/1.0',
        'details' => null,
        'previous_hash' => str_repeat('0', 128),
    ];
    $genHash = Audit::computeEntryHashV3($genPayload);
    $pdo->prepare("INSERT INTO audit_logs (id, record_key, sequence_number, timestamp, user_id, action_type, status, previous_hash, current_hash, payload) VALUES (?, ?, 1, ?, 'SYS', 'SYSTEM_GENESIS', 'SUCCESS', ?, ?, ?)")
        ->execute([$genId, $genId, $genTime, str_repeat('0', 128), $genHash, json_encode($genPayload)]);

    // Encrypted file and chunk records
    $fid = 'file-legacy-999';
    $pdo->prepare("INSERT INTO encrypted_files (id, record_key, owner_id, upload_status, deletion_pending, file_size_bytes, total_chunks, created_at, payload) VALUES (?, ?, ?, 'completed', 0, 100, 1, ?, '{}')")
        ->execute([$fid, $fid, $uid, $genTime]);

    $cid = 'chunk-legacy-999-0';
    $chunkDir = $oldStorage . DIRECTORY_SEPARATOR . $fid;
    mkdir($chunkDir, 0700, true);
    $chunkFile = $chunkDir . DIRECTORY_SEPARATOR . 'chunk_0.bin';
    $chunkCiphertext = 'ENCRYPTED_VAULT_CHUNK_DATA_AES_GCM_256_TEST_VECTOR';
    file_put_contents($chunkFile, $chunkCiphertext);
    $chunkSha = hash('sha256', $chunkCiphertext);

    $pdo->prepare("INSERT INTO file_chunks (id, record_key, file_id, chunk_index, chunk_size_bytes, storage_path, sha256_ciphertext, created_at, payload) VALUES (?, ?, ?, 0, ?, ?, ?, ?, '{}')")
        ->execute([$cid, $cid, $fid, strlen($chunkCiphertext), $chunkFile, $chunkSha, $genTime]);

    unset($pdo);

    // 2. secrets.php in var/secure-vault/
    $mockSecrets = [
        'JWT_SECRET' => 'jwt_secret_legacy_32bytes_value_1234567890',
        'MFA_ENCRYPTION_KEY' => base64_encode(random_bytes(32)),
    ];
    file_put_contents($oldVar . DIRECTORY_SEPARATOR . 'secrets.php', "<?php return " . var_export($mockSecrets, true) . ";\n");

    // 3. smtp.json in var/secure-vault/
    $mockSmtp = [
        'HOST' => 'smtp.gmail.com',
        'PORT' => '465',
        'ENCRYPTION' => 'ssl',
        'FROM' => 'vault@gmail.com',
        'USER' => 'vault@gmail.com',
        'PASSWORD' => 'apppass123456789',
    ];
    file_put_contents($oldVar . DIRECTORY_SEPARATOR . 'smtp.json', json_encode($mockSmtp, JSON_PRETTY_PRINT));

    // Run bootstrap from NewProject pointing to persistent directory
    $bootRes = PersistentStorage::bootstrap($newProjectDir, $persistentDir, false);
    check($bootRes['status'] === PersistentStorage::STATUS_RECOVERED, 'Status pemulihan instalasi bd43a46 adalah RECOVERED');

    // Verify database recovery
    $targetDb = $persistentDir . DIRECTORY_SEPARATOR . 'data' . DIRECTORY_SEPARATOR . 'secure-vault.sqlite';
    check(is_file($targetDb), 'Database secure-vault.sqlite ada di direktori persisten');

    // Verify user accounts preserved
    $recPdo = new PDO('sqlite:' . $targetDb);
    $uRow = $recPdo->query("SELECT * FROM users WHERE username = 'legacy_admin'")->fetch(PDO::FETCH_ASSOC);
    check(!empty($uRow), 'Akun legacy_admin ditemukan di database persisten');
    $uData = json_decode($uRow['payload'], true);
    check(password_verify($rawPwd, $uData['password_hash']), 'Password lama berhasil diverifikasi dengan password hash di database persisten');

    // Verify physical chunk recovery
    $recChunk = $persistentDir . DIRECTORY_SEPARATOR . 'storage' . DIRECTORY_SEPARATOR . $fid . DIRECTORY_SEPARATOR . 'chunk_0.bin';
    check(is_file($recChunk), 'Berkas chunk fisik chunk_0.bin berhasil dipulihkan ke storage persisten');
    check(file_get_contents($recChunk) === $chunkCiphertext, 'Konten berkas chunk terenkripsi 100% identik');
    check(hash_file('sha256', $recChunk) === $chunkSha, 'Checksum SHA-256 berkas chunk cocok persis');

    // Verify secrets.php recovery
    $recSecFile = $persistentDir . DIRECTORY_SEPARATOR . 'secrets.php';
    check(is_file($recSecFile), 'secrets.php berhasil dipulihkan ke direktori persisten');
    $recSecData = require $recSecFile;
    check($recSecData['JWT_SECRET'] === $mockSecrets['JWT_SECRET'], 'JWT_SECRET cocok persis dengan instalasi lama');
    check($recSecData['MFA_ENCRYPTION_KEY'] === $mockSecrets['MFA_ENCRYPTION_KEY'], 'MFA_ENCRYPTION_KEY cocok persis dengan instalasi lama');

    // Verify smtp.json recovery
    $recSmtpFile = $persistentDir . DIRECTORY_SEPARATOR . 'smtp.json';
    check(is_file($recSmtpFile), 'smtp.json berhasil dipulihkan ke direktori persisten');
    $recSmtpData = json_decode(file_get_contents($recSmtpFile), true);
    check($recSmtpData['HOST'] === 'smtp.gmail.com', 'Konfigurasi SMTP berhasil dipulihkan');

    // Verify audit hash-chain integrity
    $aRow = $recPdo->query("SELECT * FROM audit_logs WHERE sequence_number = 1")->fetch(PDO::FETCH_ASSOC);
    check(!empty($aRow), 'Log audit genesis ditemukan');
    $aPay = json_decode($aRow['payload'], true);
    $recalculatedHash = Audit::computeEntryHashV3($aPay);
    check(hash_equals($recalculatedHash, $aRow['current_hash']), 'Hash entri audit genesis V3 valid dan tidak terputus');

    unset($recPdo);

    // Verify second bootstrap is idempotent (ALREADY_EXISTS, zero duplicates)
    $boot2 = PersistentStorage::bootstrap($newProjectDir, $persistentDir, false);
    check($boot2['status'] === PersistentStorage::STATUS_ALREADY_EXISTS, 'Bootstrap kedua mengembalikan ALREADY_EXISTS');
    check($boot2['info']['user_count'] === 1, 'Data tidak terduplikasi (user_count tetap 1)');

    // -------------------------------------------------------------
    // PART 2: Failure Scenarios (Must Stop Safely, No Empty DB Fallback)
    // -------------------------------------------------------------
    echo "\n--- 2. Pengujian Skenario Kegagalan & Proteksi Fallback Kosong ---\n";

    // Failure Scenario 1: Database has chunk records, but old storage folder is missing
    echo "  [Test F1] Storage fisik hilang padahal database mencatat chunk\n";
    $sbF1 = makeTemp('sv-fail1-');
    $sandboxes[] = $sbF1;
    $f1Var = $sbF1 . DIRECTORY_SEPARATOR . 'old' . DIRECTORY_SEPARATOR . 'var' . DIRECTORY_SEPARATOR . 'secure-vault';
    $f1Data = $f1Var . DIRECTORY_SEPARATOR . 'data';
    mkdir($f1Data, 0700, true);
    // Note: NOT creating $f1Var/storage !

    $f1Db = $f1Data . DIRECTORY_SEPARATOR . 'secure-vault.sqlite';
    $pF1 = new PDO('sqlite:' . $f1Db, null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
    $pF1->exec(file_get_contents($schemaPath));
    $pF1->exec("INSERT INTO users (id, record_key, username, email, role, is_active, storage_quota_bytes, storage_used_bytes, payload) VALUES ('u1', 'u1', 'u1', 'u1@test.com', 'user', 1, 100, 0, '{}')");
    $pF1->exec("INSERT INTO encrypted_files (id, record_key, owner_id, upload_status, deletion_pending, file_size_bytes, total_chunks, created_at, payload) VALUES ('f1', 'f1', 'u1', 'completed', 0, 10, 1, '2026-01-01', '{}')");
    $pF1->exec("INSERT INTO file_chunks (id, record_key, file_id, chunk_index, chunk_size_bytes, storage_path, sha256_ciphertext, created_at, payload) VALUES ('c1', 'c1', 'f1', 0, 10, 'path', 'hash', '2026-01-01', '{}')");
    $pF1->exec("INSERT INTO audit_logs (id, record_key, sequence_number, timestamp, user_id, action_type, status, previous_hash, current_hash, payload) VALUES ('a1', 'a1', 1, '2026-01-01', 'SYS', 'ACT', 'SUCCESS', '0', '1', '{}')");
    unset($pF1);
    file_put_contents($f1Var . DIRECTORY_SEPARATOR . 'secrets.php', "<?php return ['JWT_SECRET' => str_repeat('s', 32), 'MFA_ENCRYPTION_KEY' => base64_encode(random_bytes(32))];\n");

    $targetF1 = $sbF1 . DIRECTORY_SEPARATOR . 'targetF1';
    $resF1 = PersistentStorage::bootstrap($sbF1 . DIRECTORY_SEPARATOR . 'new', $targetF1, false);
    check($resF1['status'] === PersistentStorage::STATUS_ERROR, 'F1: Bootstrap mengembalikan STATUS_ERROR saat storage chunk fisik tidak ditemukan');
    check(!is_file($targetF1 . DIRECTORY_SEPARATOR . 'data' . DIRECTORY_SEPARATOR . 'secure-vault.sqlite'), 'F1: Database sementara dibersihkan, tidak ada berkas setengah pulih');

    // Failure Scenario 2: Candidate has users, but secrets.php is missing
    echo "  [Test F2] secrets.php hilang pada instalasi lama yang memiliki akun\n";
    $sbF2 = makeTemp('sv-fail2-');
    $sandboxes[] = $sbF2;
    $f2Var = $sbF2 . DIRECTORY_SEPARATOR . 'old' . DIRECTORY_SEPARATOR . 'var' . DIRECTORY_SEPARATOR . 'secure-vault';
    $f2Data = $f2Var . DIRECTORY_SEPARATOR . 'data';
    mkdir($f2Data, 0700, true);
    // Note: NOT creating secrets.php !

    $f2Db = $f2Data . DIRECTORY_SEPARATOR . 'secure-vault.sqlite';
    $pF2 = new PDO('sqlite:' . $f2Db, null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
    $pF2->exec(file_get_contents($schemaPath));
    $pF2->exec("INSERT INTO users (id, record_key, username, email, role, is_active, storage_quota_bytes, storage_used_bytes, payload) VALUES ('u2', 'u2', 'u2', 'u2@test.com', 'admin', 1, 100, 0, '{}')");
    $pF2->exec("INSERT INTO audit_logs (id, record_key, sequence_number, timestamp, user_id, action_type, status, previous_hash, current_hash, payload) VALUES ('a2', 'a2', 1, '2026-01-01', 'SYS', 'ACT', 'SUCCESS', '0', '1', '{}')");
    unset($pF2);

    $targetF2 = $sbF2 . DIRECTORY_SEPARATOR . 'targetF2';
    $resF2 = PersistentStorage::bootstrap($sbF2 . DIRECTORY_SEPARATOR . 'new', $targetF2, false);
    check($resF2['status'] === PersistentStorage::STATUS_ERROR, 'F2: Bootstrap mengembalikan STATUS_ERROR saat secrets.php hilang pada database ber-user');
    check(!is_file($targetF2 . DIRECTORY_SEPARATOR . 'data' . DIRECTORY_SEPARATOR . 'secure-vault.sqlite'), 'F2: Database sementara dibersihkan');
    check(!is_file($targetF2 . DIRECTORY_SEPARATOR . 'secrets.php'), 'F2: Tidak membuat secrets.php palsu yang menggantikan kunci');

    // Failure Scenario 3: Corrupt database candidate
    echo "  [Test F3] Database kandidat korup / rusak\n";
    $sbF3 = makeTemp('sv-fail3-');
    $sandboxes[] = $sbF3;
    $f3Var = $sbF3 . DIRECTORY_SEPARATOR . 'old' . DIRECTORY_SEPARATOR . 'var' . DIRECTORY_SEPARATOR . 'secure-vault';
    $f3Data = $f3Var . DIRECTORY_SEPARATOR . 'data';
    mkdir($f3Data, 0700, true);
    file_put_contents($f3Data . DIRECTORY_SEPARATOR . 'secure-vault.sqlite', "GARBAGE_CORRUPTED_NON_SQLITE_BYTES_12345");

    $targetF3 = $sbF3 . DIRECTORY_SEPARATOR . 'targetF3';
    putenv("SECURE_VAULT_SOURCE_DIR={$f3Data}");
    $resF3 = PersistentStorage::bootstrap($sbF3 . DIRECTORY_SEPARATOR . 'new', $targetF3, false);
    putenv("SECURE_VAULT_SOURCE_DIR"); // clear env
    check($resF3['status'] === PersistentStorage::STATUS_ERROR, 'F3: SECURE_VAULT_SOURCE_DIR menunjuk berkas korup menghasilkan STATUS_ERROR');
    check(!is_file($targetF3 . DIRECTORY_SEPARATOR . 'data' . DIRECTORY_SEPARATOR . 'secure-vault.sqlite'), 'F3: Tidak membuat database baru sebagai fallback');

    // Failure Scenario 4: Multiple ambiguous candidates
    echo "  [Test F4] Dua kandidat database valid ambigu\n";
    $sbF4 = makeTemp('sv-fail4-');
    $sandboxes[] = $sbF4;
    $f4A = $sbF4 . DIRECTORY_SEPARATOR . 'instA' . DIRECTORY_SEPARATOR . 'var' . DIRECTORY_SEPARATOR . 'secure-vault' . DIRECTORY_SEPARATOR . 'data';
    $f4B = $sbF4 . DIRECTORY_SEPARATOR . 'instB' . DIRECTORY_SEPARATOR . 'var' . DIRECTORY_SEPARATOR . 'secure-vault' . DIRECTORY_SEPARATOR . 'data';
    mkdir($f4A, 0700, true);
    mkdir($f4B, 0700, true);

    foreach ([$f4A, $f4B] as $dir) {
        $p = new PDO('sqlite:' . $dir . DIRECTORY_SEPARATOR . 'secure-vault.sqlite', null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
        $p->exec(file_get_contents($schemaPath));
        $p->exec("INSERT INTO users (id, record_key, username, email, role, is_active, storage_quota_bytes, storage_used_bytes, payload) VALUES ('u', 'u', 'u', 'u@test.com', 'user', 1, 100, 0, '{}')");
        $p->exec("INSERT INTO audit_logs (id, record_key, sequence_number, timestamp, user_id, action_type, status, previous_hash, current_hash, payload) VALUES ('a', 'a', 1, '2026-01-01', 'SYS', 'ACT', 'SUCCESS', '0', '1', '{}')");
        unset($p);
        file_put_contents(dirname($dir) . DIRECTORY_SEPARATOR . 'secrets.php', "<?php return ['JWT_SECRET' => str_repeat('x', 32), 'MFA_ENCRYPTION_KEY' => base64_encode(random_bytes(32))];\n");
    }

    $targetF4 = $sbF4 . DIRECTORY_SEPARATOR . 'targetF4';
    $resF4 = PersistentStorage::bootstrap($sbF4 . DIRECTORY_SEPARATOR . 'active', $targetF4, false);
    check($resF4['status'] === PersistentStorage::STATUS_AMBIGUOUS_CANDIDATES, 'F4: Deteksi ambiguitas berhasil (STATUS_AMBIGUOUS_CANDIDATES)');
    check(!is_file($targetF4 . DIRECTORY_SEPARATOR . 'data' . DIRECTORY_SEPARATOR . 'secure-vault.sqlite'), 'F4: Tidak membuat database baru atau memilih salah satu secara acak');

    // -------------------------------------------------------------
    // PART 3: Cross-Folder Simulation (Documents/Old to Downloads/New)
    // -------------------------------------------------------------
    echo "\n--- 3. Simulasi Lintas Folder: Documents ke Downloads ---\n";
    $sbCross = makeTemp('sv-cross-');
    $sandboxes[] = $sbCross;

    $simUserProfile = $sbCross . DIRECTORY_SEPARATOR . 'UserProfile';
    $simDocs = $simUserProfile . DIRECTORY_SEPARATOR . 'Documents';
    $simDownloads = $simUserProfile . DIRECTORY_SEPARATOR . 'Downloads';
    $simDesktop = $simUserProfile . DIRECTORY_SEPARATOR . 'Desktop';
    $simLocalAppData = $simUserProfile . DIRECTORY_SEPARATOR . 'AppData' . DIRECTORY_SEPARATOR . 'Local';
    $simTargetPersistent = $simLocalAppData . DIRECTORY_SEPARATOR . 'SecureVault';

    mkdir($simDocs, 0700, true);
    mkdir($simDownloads, 0700, true);
    mkdir($simDesktop, 0700, true);
    mkdir($simLocalAppData, 0700, true);

    // Old installation in Documents/SecureVault-Old
    $crossOldProject = $simDocs . DIRECTORY_SEPARATOR . 'SecureVault-Old';
    $crossOldVar = $crossOldProject . DIRECTORY_SEPARATOR . 'var' . DIRECTORY_SEPARATOR . 'secure-vault';
    $crossOldData = $crossOldVar . DIRECTORY_SEPARATOR . 'data';
    $crossOldStorage = $crossOldVar . DIRECTORY_SEPARATOR . 'storage';
    mkdir($crossOldData, 0700, true);
    mkdir($crossOldStorage, 0700, true);

    $crossOldDb = $crossOldData . DIRECTORY_SEPARATOR . 'secure-vault.sqlite';
    $pCross = new PDO('sqlite:' . $crossOldDb, null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
    $pCross->exec(file_get_contents($schemaPath));
    $pCross->exec('PRAGMA user_version = 2');

    $crossUid = 'cross-user-uuid-888';
    $crossRawPwd = 'CrossFolderSecret2026!';
    $crossPwdHash = password_hash($crossRawPwd, PASSWORD_DEFAULT);
    $crossPayload = [
        'id' => $crossUid,
        'username' => 'budi_cross_docs',
        'email' => 'budi@documents.local',
        'password_hash' => $crossPwdHash,
        'role' => 'user',
        'is_active' => true,
    ];
    $pCross->prepare("INSERT INTO users (id, record_key, username, email, role, is_active, storage_quota_bytes, storage_used_bytes, payload) VALUES (?, ?, ?, ?, ?, 1, 500000, 100, ?)")
        ->execute([$crossUid, $crossUid, 'budi_cross_docs', 'budi@documents.local', 'user', json_encode($crossPayload)]);

    // Audit genesis SHA3-512 V3
    $crossGenId = 'cross-gen-888';
    $crossGenTime = '2026-11-18T10:00:00.000Z';
    $crossGenPay = [
        'version' => 3,
        'id' => $crossGenId,
        'sequence_number' => 1,
        'timestamp' => $crossGenTime,
        'user_id' => 'SYS',
        'action_type' => 'SYSTEM_GENESIS',
        'file_id' => null,
        'status' => 'SUCCESS',
        'ip_address' => '127.0.0.1',
        'user_agent' => 'CrossTestAgent/1.0',
        'details' => null,
        'previous_hash' => str_repeat('0', 128),
    ];
    $crossGenHash = Audit::computeEntryHashV3($crossGenPay);
    $pCross->prepare("INSERT INTO audit_logs (id, record_key, sequence_number, timestamp, user_id, action_type, status, previous_hash, current_hash, payload) VALUES (?, ?, 1, ?, 'SYS', 'SYSTEM_GENESIS', 'SUCCESS', ?, ?, ?)")
        ->execute([$crossGenId, $crossGenId, $crossGenTime, str_repeat('0', 128), $crossGenHash, json_encode($crossGenPay)]);

    // Encrypted chunk
    $crossFid = 'file-cross-777';
    $pCross->prepare("INSERT INTO encrypted_files (id, record_key, owner_id, upload_status, deletion_pending, file_size_bytes, total_chunks, created_at, payload) VALUES (?, ?, ?, 'completed', 0, 80, 1, ?, '{}')")
        ->execute([$crossFid, $crossFid, $crossUid, $crossGenTime]);

    $crossCid = 'chunk-cross-777-0';
    $crossChunkDir = $crossOldStorage . DIRECTORY_SEPARATOR . $crossFid;
    mkdir($crossChunkDir, 0700, true);
    $crossChunkFile = $crossChunkDir . DIRECTORY_SEPARATOR . 'chunk_0.bin';
    $crossCipher = 'CROSS_FOLDER_CIPHERTEXT_PAYLOAD_ENCRYPTED_DATA_BYTES';
    file_put_contents($crossChunkFile, $crossCipher);
    $crossChunkSha = hash('sha256', $crossCipher);

    $pCross->prepare("INSERT INTO file_chunks (id, record_key, file_id, chunk_index, chunk_size_bytes, storage_path, sha256_ciphertext, created_at, payload) VALUES (?, ?, ?, 0, ?, ?, ?, ?, '{}')")
        ->execute([$crossCid, $crossCid, $crossFid, strlen($crossCipher), $crossChunkFile, $crossChunkSha, $crossGenTime]);

    unset($pCross);

    // Old secrets & smtp
    $crossOldSecrets = [
        'JWT_SECRET' => 'jwt_cross_folder_legacy_secret_32bytes_value',
        'MFA_ENCRYPTION_KEY' => base64_encode(random_bytes(32)),
    ];
    file_put_contents($crossOldVar . DIRECTORY_SEPARATOR . 'secrets.php', "<?php return " . var_export($crossOldSecrets, true) . ";\n");

    // New ZIP extracted into Downloads/SecureVault-New
    $crossNewProject = $simDownloads . DIRECTORY_SEPARATOR . 'SecureVault-New';
    mkdir($crossNewProject, 0700, true);

    // Run bootstrap from Downloads/SecureVault-New with simulated UserProfile
    $crossBootRes = PersistentStorage::bootstrap($crossNewProject, $simTargetPersistent, true, $simUserProfile);
    check($crossBootRes['status'] === PersistentStorage::STATUS_RECOVERED, 'Cross-Folder: Status pemulihan dari Downloads ke Documents adalah RECOVERED');

    // 1. Database lama ditemukan di Documents
    $crossRecDb = $simTargetPersistent . DIRECTORY_SEPARATOR . 'data' . DIRECTORY_SEPARATOR . 'secure-vault.sqlite';
    check(is_file($crossRecDb), 'Cross-Folder 1: Database lama di Documents berhasil dipulihkan ke persistent target');

    // 2. Akun pengguna lama tersedia
    $pCrossRec = new PDO('sqlite:' . $crossRecDb);
    $crossUserRow = $pCrossRec->query("SELECT * FROM users WHERE username = 'budi_cross_docs'")->fetch(PDO::FETCH_ASSOC);
    check(!empty($crossUserRow), 'Cross-Folder 2: Akun pengguna lama budi_cross_docs tersedia');
    $crossUserData = json_decode($crossUserRow['payload'], true);
    check(password_verify($crossRawPwd, $crossUserData['password_hash']), 'Cross-Folder 2: Password pengguna lama berhasil diverifikasi');

    // 3. Storage dan chunk terenkripsi ikut pulih
    $crossRecChunk = $simTargetPersistent . DIRECTORY_SEPARATOR . 'storage' . DIRECTORY_SEPARATOR . $crossFid . DIRECTORY_SEPARATOR . 'chunk_0.bin';
    check(is_file($crossRecChunk), 'Cross-Folder 3: Berkas chunk fisik berhasil dipulihkan');
    check(file_get_contents($crossRecChunk) === $crossCipher, 'Cross-Folder 3: Isi chunk terenkripsi identik');
    check(hash_file('sha256', $crossRecChunk) === $crossChunkSha, 'Cross-Folder 3: Checksum chunk cocok');

    // 4. Secret lama tetap dipertahankan
    $crossRecSec = $simTargetPersistent . DIRECTORY_SEPARATOR . 'secrets.php';
    check(is_file($crossRecSec), 'Cross-Folder 4: secrets.php lama dipulihkan');
    $crossLoadedSec = require $crossRecSec;
    check($crossLoadedSec['JWT_SECRET'] === $crossOldSecrets['JWT_SECRET'], 'Cross-Folder 4: JWT_SECRET identik dengan instalasi lama di Documents');
    check($crossLoadedSec['MFA_ENCRYPTION_KEY'] === $crossOldSecrets['MFA_ENCRYPTION_KEY'], 'Cross-Folder 4: MFA_ENCRYPTION_KEY identik');

    // 5. Hash-chain audit historis valid
    $crossAuditRow = $pCrossRec->query("SELECT * FROM audit_logs WHERE sequence_number = 1")->fetch(PDO::FETCH_ASSOC);
    check(!empty($crossAuditRow), 'Cross-Folder 5: Log audit genesis ditemukan');
    $crossAuditPay = json_decode($crossAuditRow['payload'], true);
    $crossRecalcHash = Audit::computeEntryHashV3($crossAuditPay);
    check(hash_equals($crossRecalcHash, $crossAuditRow['current_hash']), 'Cross-Folder 5: Hash-chain audit V3 valid dan tidak terputus');
    unset($pCrossRec);

    // 6. Tidak ada database kosong yang menggantikan database lama
    check(is_file($crossRecDb) && filesize($crossRecDb) > 0, 'Cross-Folder 6: Database persisten berisi data asli, bukan database kosong');

    // 7. Peluncuran berikutnya idempotent
    $crossBoot2 = PersistentStorage::bootstrap($crossNewProject, $simTargetPersistent, true, $simUserProfile);
    check($crossBoot2['status'] === PersistentStorage::STATUS_ALREADY_EXISTS, 'Cross-Folder 7: Bootstrap kedua mengembalikan ALREADY_EXISTS (idempotent)');
    check($crossBoot2['info']['user_count'] === 1, 'Cross-Folder 7: Jumlah user tetap 1, tidak ada duplikasi');

} finally {
    foreach ($sandboxes as $sb) {
        cleanTemp($sb);
    }
}

echo "\n========================================================\n";
echo "  HASIL AKHIR: {$passedChecks} / {$totalChecks} CHECKS PASSED\n";
echo "========================================================\n";
exit(0);
