<?php
// Full PHP/PDO migration test. Exit code 77 means the environment lacks PDO_SQLite.
if (PHP_SAPI !== 'cli') { fwrite(STDERR, "CLI only.\n"); exit(2); }
if (!in_array('sqlite', PDO::getAvailableDrivers(), true)) {
    fwrite(STDOUT, "BLOCKED: PDO SQLite driver is not installed; PHP migration adapter was not executed.\n");
    exit(77);
}

$tmp = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'sv-relational-' . bin2hex(random_bytes(8));
$dataDir = $tmp . DIRECTORY_SEPARATOR . 'data';
$storageDir = $tmp . DIRECTORY_SEPARATOR . 'storage';
if (!mkdir($dataDir, 0700, true) || !mkdir($storageDir, 0700, true)) {
    fwrite(STDERR, "Unable to create temporary test directories.\n"); exit(1);
}
putenv('JWT_SECRET=' . bin2hex(random_bytes(32)));
putenv('MFA_ENCRYPTION_KEY=' . base64_encode(random_bytes(32)));
putenv('SECURE_VAULT_DATA_DIR=' . $dataDir);
putenv('SECURE_VAULT_STORAGE_DIR=' . $storageDir);

try {
    require_once __DIR__ . '/../config.php';
    $legacy = new PDO('sqlite:' . DB_FILE, null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
    $legacy->exec('CREATE TABLE vault_records(collection TEXT NOT NULL, record_key TEXT NOT NULL, payload TEXT NOT NULL, PRIMARY KEY(collection, record_key))');

    $uid = 'test-user'; $fid = 'test-file'; $cid = 'test-chunk'; $aid = 'test-audit';
    $records = [
        ['users', $uid, ['id'=>$uid,'username'=>'migration-user','email'=>'migration@example.test','role'=>'user','is_active'=>1,'password_hash'=>'test-hash','storage_quota_bytes'=>1000,'storage_used_bytes'=>10]],
        ['vault_profiles', $uid, ['user_id'=>$uid,'argon2_salt'=>'salt','wrapped_master_key'=>'wrapped','created_at'=>'2026-11-04T00:00:00Z']],
        ['encrypted_files', $fid, ['id'=>$fid,'owner_id'=>$uid,'encrypted_file_name'=>'cipher','file_size_bytes'=>10,'total_chunks'=>1,'wrapped_dek'=>'wrapped','upload_status'=>'uploading','plaintext_sha256'=>str_repeat('a',64)]],
        ['file_chunks', $cid, ['id'=>$cid,'file_id'=>$fid,'chunk_index'=>0,'chunk_size_bytes'=>26,'storage_path'=>$storageDir . '/chunk.bin','iv_base64'=>'a','aad_string'=>'file-0']],
        ['audit_logs', $aid, ['id'=>$aid,'sequence_number'=>1,'timestamp'=>'2026-11-04T00:00:00Z','user_id'=>$uid,'action_type'=>'MIGRATION_TEST','status'=>'SUCCESS','previous_hash'=>str_repeat('0',64),'current_hash'=>str_repeat('1',64)]],
        ['auth_rate_limits', 'ip:test', ['window_started_at'=>time(),'attempts'=>2]],
    ];
    $insert = $legacy->prepare('INSERT INTO vault_records(collection,record_key,payload) VALUES(?,?,?)');
    foreach ($records as [$collection,$key,$record]) {
        $insert->execute([$collection,$key,json_encode($record, JSON_UNESCAPED_SLASHES)]);
    }
    $legacy = null;

    require_once __DIR__ . '/../db/Database.php';
    $db = Database::getInstance();
    if ($db->getSchemaVersion() !== 2) throw new RuntimeException('Schema version is not 2.');
    if (count($db->getUsers()) !== 1) throw new RuntimeException('User did not migrate.');
    if ($db->getVaultProfile($uid) === null) throw new RuntimeException('Vault profile did not migrate.');
    $file = $db->getFileById($fid);
    if ($file === null || array_key_exists('plaintext_sha256', $file)) throw new RuntimeException('File migration or fingerprint cleanup failed.');
    if ($db->getChunk($fid, 0) === null) throw new RuntimeException('Chunk did not migrate.');
    if (count($db->getAuditLogs()) !== 1) throw new RuntimeException('Audit record did not migrate.');
    if (!$db->isRateLimited('ip:test', 2, 600)) throw new RuntimeException('Rate-limit record did not migrate.');

    $pdo = new PDO('sqlite:' . DB_FILE, null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
    if ($pdo->query("SELECT 1 FROM sqlite_master WHERE type='table' AND name='vault_records'")->fetchColumn()) {
        throw new RuntimeException('Legacy generic table was not removed after successful migration.');
    }
    if (count($pdo->query('PRAGMA foreign_key_check')->fetchAll(PDO::FETCH_ASSOC)) !== 0) {
        throw new RuntimeException('Foreign-key check failed after migration.');
    }
    fwrite(STDOUT, "PHP RELATIONAL MIGRATION INTEGRATION TEST: PASS\n");
} catch (Throwable $e) {
    fwrite(STDERR, "PHP RELATIONAL MIGRATION INTEGRATION TEST: FAIL: " . $e->getMessage() . "\n");
    exit(1);
} finally {
    // Remove only the disposable test data. The project private directory is not touched.
    $files = glob($dataDir . DIRECTORY_SEPARATOR . '*') ?: [];
    foreach ($files as $file) if (is_file($file)) @unlink($file);
    @rmdir($dataDir); @rmdir($storageDir); @rmdir($tmp);
}
