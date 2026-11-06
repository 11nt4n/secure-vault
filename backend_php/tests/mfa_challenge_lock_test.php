<?php
declare(strict_types=1);
/**
 * Focused regression test for atomic MFA challenge state transitions.
 * Run with: php backend_php/tests/mfa_challenge_lock_test.php
 * Does not require pdo_sqlite because it tests only the challenge store.
 */

$root = dirname(__DIR__, 2);
$temp = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'secure-vault-mfa-test-' . bin2hex(random_bytes(6));
$dataDir = $temp . DIRECTORY_SEPARATOR . 'data';
$storageDir = $temp . DIRECTORY_SEPARATOR . 'storage';
mkdir($dataDir, 0700, true);
mkdir($storageDir, 0700, true);

putenv('JWT_SECRET=' . bin2hex(random_bytes(32)));
putenv('MFA_ENCRYPTION_KEY=' . base64_encode(random_bytes(32)));
putenv('SECURE_VAULT_DATA_DIR=' . $dataDir);
putenv('SECURE_VAULT_STORAGE_DIR=' . $storageDir);

require_once $root . '/backend_php/routes/AuthRoutes.php';

try {
    $token = bin2hex(random_bytes(24));
    $userId = 'mfa-regression-user';

    $invoke = static function (string $method, array $arguments = []) {
        $reflection = new ReflectionMethod(AuthRoutes::class, $method);
        $reflection->setAccessible(true);
        return $reflection->invokeArgs(null, $arguments);
    };

    $invoke('saveMfaToken', [$token, $userId]);
    if ($invoke('getMfaTokenUserId', [$token]) !== $userId) {
        throw new RuntimeException('MFA challenge could not be read after creation.');
    }

    $invoke('recordMfaFailure', [$token]);
    $records = json_decode((string)file_get_contents($dataDir . DIRECTORY_SEPARATOR . 'mfa_tokens.json'), true);
    if (!is_array($records) || (int)($records[$token]['attempts'] ?? -1) !== 1) {
        throw new RuntimeException('MFA failed-attempt counter was not persisted.');
    }

    if ($invoke('consumeMfaToken', [$token]) !== $userId) {
        throw new RuntimeException('MFA challenge was not consumed.');
    }
    if ($invoke('consumeMfaToken', [$token]) !== null) {
        throw new RuntimeException('MFA challenge was consumed more than once.');
    }
    if ($invoke('getMfaTokenUserId', [$token]) !== null) {
        throw new RuntimeException('Consumed MFA challenge remained readable.');
    }

    if (function_exists('pcntl_fork')) {
        $concurrentToken = bin2hex(random_bytes(24));
        $invoke('saveMfaToken', [$concurrentToken, $userId]);
        $children = [];
        for ($i = 0; $i < 4; $i++) {
            $pid = pcntl_fork();
            if ($pid === -1) throw new RuntimeException('Unable to fork MFA concurrency test worker.');
            if ($pid === 0) {
                $consumed = $invoke('consumeMfaToken', [$concurrentToken]);
                file_put_contents($dataDir . DIRECTORY_SEPARATOR . 'worker-' . $i . '.result', $consumed ?? 'NULL');
                exit(0);
            }
            $children[] = $pid;
        }
        foreach ($children as $pid) pcntl_waitpid($pid, $status);
        $successCount = 0;
        for ($i = 0; $i < 4; $i++) {
            $resultPath = $dataDir . DIRECTORY_SEPARATOR . 'worker-' . $i . '.result';
            $result = is_file($resultPath) ? file_get_contents($resultPath) : false;
            if ($result === $userId) $successCount++;
            if ($result === false) throw new RuntimeException('MFA concurrency worker did not persist its result.');
        }
        if ($successCount !== 1) {
            throw new RuntimeException('Concurrent MFA challenge consumption was not single-winner; successes=' . $successCount);
        }
    }

    echo "PASS: MFA challenge state transitions are serialized and single-use, including concurrent consumption.\n";
} finally {
    foreach (glob($dataDir . DIRECTORY_SEPARATOR . '*') ?: [] as $path) {
        if (is_file($path)) unlink($path);
    }
    @rmdir($dataDir);
    @rmdir($storageDir);
    @rmdir($temp);
}
