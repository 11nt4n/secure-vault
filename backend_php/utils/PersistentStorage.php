<?php
// backend_php/utils/PersistentStorage.php
// Manages persistent local data directories, automatic legacy data discovery, and safe WAL-aware recovery.

class PersistentStorage
{
    public const STATUS_ALREADY_EXISTS = 'ALREADY_EXISTS';
    public const STATUS_RECOVERED = 'RECOVERED';
    public const STATUS_NEW_INSTALLATION = 'NEW_INSTALLATION';
    public const STATUS_AMBIGUOUS_CANDIDATES = 'AMBIGUOUS_CANDIDATES';
    public const STATUS_ERROR = 'ERROR';

    /**
     * Resolve the persistent base directory independent of ZIP extraction location.
     */
    public static function resolvePersistentDirectory(?string $overrideDir = null): string
    {
        if ($overrideDir !== null && trim($overrideDir) !== '') {
            return rtrim(trim($overrideDir), DIRECTORY_SEPARATOR);
        }

        $envPersistent = getenv('SECURE_VAULT_PERSISTENT_DIR') ?: getenv('SECURE_VAULT_HOME');
        if ($envPersistent !== false && trim($envPersistent) !== '') {
            return rtrim(trim($envPersistent), DIRECTORY_SEPARATOR);
        }

        $envDataDir = getenv('SECURE_VAULT_DATA_DIR');
        if ($envDataDir !== false && trim($envDataDir) !== '') {
            return dirname(rtrim(trim($envDataDir), DIRECTORY_SEPARATOR));
        }

        if (PHP_OS_FAMILY === 'Windows') {
            $localAppData = getenv('LOCALAPPDATA');
            if ($localAppData === false || trim($localAppData) === '') {
                $userProfile = getenv('USERPROFILE') ?: '';
                $localAppData = ($userProfile !== '') ? $userProfile . DIRECTORY_SEPARATOR . 'AppData' . DIRECTORY_SEPARATOR . 'Local' : '';
            }
            if ($localAppData !== '') {
                return $localAppData . DIRECTORY_SEPARATOR . 'SecureVault';
            }
        } elseif (PHP_OS_FAMILY === 'Darwin') {
            $home = getenv('HOME') ?: '';
            if ($home !== '') {
                return $home . '/Library/Application Support/SecureVault';
            }
        } else {
            $xdg = getenv('XDG_DATA_HOME') ?: '';
            if ($xdg === '') {
                $home = getenv('HOME') ?: '';
                $xdg = ($home !== '') ? $home . '/.local/share' : '';
            }
            if ($xdg !== '') {
                return $xdg . '/secure-vault';
            }
        }

        $projectDir = dirname(__DIR__, 2);
        return $projectDir . DIRECTORY_SEPARATOR . 'var' . DIRECTORY_SEPARATOR . 'secure-vault';
    }

    /**
     * Ensure a directory exists with private permissions.
     */
    public static function ensureDirectory(string $path, int $mode = 0700): bool
    {
        if (!is_dir($path)) {
            if (!mkdir($path, $mode, true) && !is_dir($path)) {
                return false;
            }
        }
        @chmod($path, $mode);
        return true;
    }

    /**
     * Validate whether a SQLite database file exists, is readable, passes integrity check,
     * and contains the required Secure Vault relational tables.
     */
    public static function isDatabaseValid(string $dbPath): bool
    {
        if (!is_file($dbPath) || !is_readable($dbPath)) {
            return false;
        }

        $size = filesize($dbPath);
        if ($size === false || $size < 100) {
            return false;
        }

        // Check SQLite magic header (first 16 bytes)
        $fh = @fopen($dbPath, 'rb');
        if ($fh === false) {
            return false;
        }
        $header = fread($fh, 16);
        fclose($fh);
        if ($header !== "SQLite format 3\0") {
            return false;
        }

        try {
            $pdo = new PDO('sqlite:' . $dbPath, null, null, [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_TIMEOUT => 3,
            ]);

            $check = $pdo->query('PRAGMA integrity_check')->fetchColumn();
            if ($check !== 'ok') {
                return false;
            }

            // Verify essential tables exist
            $tablesStmt = $pdo->query("SELECT name FROM sqlite_master WHERE type='table'");
            $tables = $tablesStmt->fetchAll(PDO::FETCH_COLUMN);
            $required = ['users', 'audit_logs', 'encrypted_files', 'file_chunks'];
            foreach ($required as $req) {
                if (!in_array($req, $tables, true)) {
                    return false;
                }
            }
            return true;
        } catch (Throwable $e) {
            return false;
        }
    }

    /**
     * Inspect a candidate SQLite database and return detailed metadata.
     */
    public static function inspectCandidate(string $dbPath): ?array
    {
        if (!self::isDatabaseValid($dbPath)) {
            return null;
        }

        try {
            $pdo = new PDO('sqlite:' . $dbPath, null, null, [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_TIMEOUT => 3,
            ]);

            $userCount = (int)$pdo->query('SELECT COUNT(*) FROM users')->fetchColumn();
            $auditCount = (int)$pdo->query('SELECT COUNT(*) FROM audit_logs')->fetchColumn();
            $fileCount = (int)$pdo->query('SELECT COUNT(*) FROM encrypted_files')->fetchColumn();
            $chunkCount = (int)$pdo->query('SELECT COUNT(*) FROM file_chunks')->fetchColumn();

            // Find private directory of candidate
            $candidateDir = dirname($dbPath);
            $candidatePrivateDir = basename($candidateDir) === 'data' ? dirname($candidateDir) : $candidateDir;

            $possibleSecrets = [
                $candidatePrivateDir . DIRECTORY_SEPARATOR . 'secrets.php',
                $candidatePrivateDir . DIRECTORY_SEPARATOR . 'private' . DIRECTORY_SEPARATOR . 'secrets.php',
                dirname($candidatePrivateDir) . DIRECTORY_SEPARATOR . 'backend_php' . DIRECTORY_SEPARATOR . 'secrets.php',
            ];
            $hasSecrets = false;
            foreach ($possibleSecrets as $sec) {
                if (is_file($sec)) {
                    $hasSecrets = true;
                    break;
                }
            }

            $possibleStorage = [
                $candidatePrivateDir . DIRECTORY_SEPARATOR . 'storage',
                dirname($candidatePrivateDir) . DIRECTORY_SEPARATOR . 'backend_php' . DIRECTORY_SEPARATOR . 'storage',
                dirname($dbPath) . DIRECTORY_SEPARATOR . 'storage',
                $candidatePrivateDir . DIRECTORY_SEPARATOR . 'data' . DIRECTORY_SEPARATOR . 'storage',
                $candidatePrivateDir . DIRECTORY_SEPARATOR . 'data' . DIRECTORY_SEPARATOR . 'files',
                $candidatePrivateDir . DIRECTORY_SEPARATOR . 'files',
            ];
            $hasStorage = false;
            foreach ($possibleStorage as $st) {
                if (is_dir($st)) {
                    $hasStorage = true;
                    break;
                }
            }

            $possibleSmtp = [
                $candidatePrivateDir . DIRECTORY_SEPARATOR . 'smtp.json',
                $candidatePrivateDir . DIRECTORY_SEPARATOR . 'private' . DIRECTORY_SEPARATOR . 'smtp.json',
            ];
            $hasSmtp = false;
            foreach ($possibleSmtp as $sm) {
                if (is_file($sm)) {
                    $hasSmtp = true;
                    break;
                }
            }

            $hasMfaTokens = is_file($candidateDir . DIRECTORY_SEPARATOR . 'mfa_tokens.json');

            return [
                'db_path' => $dbPath,
                'private_dir' => $candidatePrivateDir,
                'mtime' => filemtime($dbPath) ?: 0,
                'size' => filesize($dbPath) ?: 0,
                'user_count' => $userCount,
                'audit_count' => $auditCount,
                'file_count' => $fileCount,
                'chunk_count' => $chunkCount,
                'has_secrets' => $hasSecrets,
                'has_storage' => $hasStorage,
                'has_smtp' => $hasSmtp,
                'has_mfa_tokens' => $hasMfaTokens,
            ];
        } catch (Throwable $e) {
            return null;
        }
    }

    /**
     * Scan constrained, relevant locations for candidate previous Secure Vault installations.
     * Searches are strictly bounded to avoid unbounded filesystem recursion.
     */
    public static function findCandidates(
        string $projectDir,
        string $persistentDir,
        ?string $manualSourceDir = null,
        bool $searchUserDocs = true,
        ?string $userProfileDir = null
    ): array {
        $candidatePaths = [];
        $normalizedPersistent = self::normalizePath($persistentDir);
        $visitedDirs = [];
        $dirCount = 0;

        // 1. Manual source directory override (via argument or environment variable)
        $manual = $manualSourceDir ?: getenv('SECURE_VAULT_SOURCE_DIR');
        if ($manual !== false && $manual !== null && trim($manual) !== '') {
            $manualDir = trim($manual);
            $possibleDbPaths = [
                $manualDir,
                $manualDir . DIRECTORY_SEPARATOR . 'secure-vault.sqlite',
                $manualDir . DIRECTORY_SEPARATOR . 'data' . DIRECTORY_SEPARATOR . 'secure-vault.sqlite',
                $manualDir . DIRECTORY_SEPARATOR . 'var' . DIRECTORY_SEPARATOR . 'secure-vault' . DIRECTORY_SEPARATOR . 'data' . DIRECTORY_SEPARATOR . 'secure-vault.sqlite',
            ];
            foreach ($possibleDbPaths as $p) {
                if (is_file($p)) {
                    $candidatePaths[] = $p;
                    break;
                }
            }
        } else {
            // 2. Local var in current project dir
            $localProjVar = $projectDir . DIRECTORY_SEPARATOR . 'var' . DIRECTORY_SEPARATOR . 'secure-vault' . DIRECTORY_SEPARATOR . 'data' . DIRECTORY_SEPARATOR . 'secure-vault.sqlite';
            if (is_file($localProjVar)) {
                $candidatePaths[] = $localProjVar;
            }

            // 3. Parent directory search (e.g. sibling folders of project)
            $parentDir = dirname($projectDir);
            if (is_dir($parentDir) && !self::isSystemTempOrRoot($parentDir)) {
                self::scanConstrainedDirectory($parentDir, 2, $candidatePaths, 0, $visitedDirs, $dirCount);
            }

            // 4. Grandparent directory search
            $grandparentDir = dirname($parentDir);
            if (is_dir($grandparentDir) && strlen($grandparentDir) > 4 && !self::isSystemTempOrRoot($grandparentDir)) {
                self::scanConstrainedDirectory($grandparentDir, 2, $candidatePaths, 0, $visitedDirs, $dirCount);
            }

            // 5. Windows user profile locations (Documents, Desktop, Downloads, OneDrive)
            if ($searchUserDocs && ($userProfileDir !== null || !getenv('SECURE_VAULT_DATA_DIR'))) {
                $up = $userProfileDir ?: (getenv('SECURE_VAULT_TEST_USERPROFILE') ?: getenv('USERPROFILE'));
                if ($up && is_dir($up)) {
                    $searchRoots = [
                        $up . DIRECTORY_SEPARATOR . 'Documents',
                        $up . DIRECTORY_SEPARATOR . 'Desktop',
                        $up . DIRECTORY_SEPARATOR . 'Downloads',
                    ];
                    // Also check OneDrive Documents if available
                    $od = getenv('OneDrive') ?: (getenv('OneDriveConsumer') ?: getenv('OneDriveCommercial'));
                    if ($od && is_dir($od)) {
                        $oneDocs = $od . DIRECTORY_SEPARATOR . 'Documents';
                        if (is_dir($oneDocs)) {
                            $searchRoots[] = $oneDocs;
                        }
                    }

                    foreach ($searchRoots as $rootPath) {
                        if (is_dir($rootPath) && !self::isSystemTempOrRoot($rootPath)) {
                            self::scanConstrainedDirectory($rootPath, 3, $candidatePaths, 0, $visitedDirs, $dirCount);
                        }
                    }
                }
            }
        }

        // De-duplicate and filter out candidates inside the persistent directory itself
        $seen = [];
        $verifiedCandidates = [];

        foreach ($candidatePaths as $rawPath) {
            $real = realpath($rawPath);
            if ($real === false) continue;

            $normalized = self::normalizePath($real);
            if (isset($seen[$normalized])) continue;
            $seen[$normalized] = true;

            // Exclude anything already inside the target persistent directory
            if (str_starts_with($normalized, $normalizedPersistent)) {
                continue;
            }

            $info = self::inspectCandidate($real);
            if ($info !== null) {
                $verifiedCandidates[] = $info;
            }
        }

        // Sort candidates: highest user_count first, then highest audit_count, then newest mtime
        usort($verifiedCandidates, function ($a, $b) {
            if ($a['user_count'] !== $b['user_count']) {
                return $b['user_count'] <=> $a['user_count'];
            }
            if ($a['audit_count'] !== $b['audit_count']) {
                return $b['audit_count'] <=> $a['audit_count'];
            }
            return $b['mtime'] <=> $a['mtime'];
        });

        return $verifiedCandidates;
    }

    /**
     * Bounded scanner: searches up to a maximum depth for secure-vault.sqlite files.
     */
    private static function scanConstrainedDirectory(
        string $dir,
        int $maxDepth,
        array &$results,
        int $currentDepth = 0,
        array &$visitedDirs = [],
        int &$dirCount = 0
    ): void {
        if ($currentDepth > $maxDepth || !is_dir($dir) || !is_readable($dir) || $dirCount > 250 || count($results) >= 20) {
            return;
        }

        $real = realpath($dir);
        if ($real === false || isset($visitedDirs[strtolower($real)])) {
            return;
        }
        $visitedDirs[strtolower($real)] = true;
        $dirCount++;

        $items = @scandir($dir);
        if ($items === false) return;

        foreach ($items as $item) {
            if ($item === '.' || $item === '..' || $item === '.git' || $item === 'node_modules' || $item === 'vendor' || $item === '$Recycle.Bin' || $item === 'System Volume Information') {
                continue;
            }

            $full = $dir . DIRECTORY_SEPARATOR . $item;

            // Avoid symbolic links and junctions to prevent recursion loops
            if (is_link($full)) {
                continue;
            }

            if ($item === 'secure-vault.sqlite' && is_file($full)) {
                $results[] = $full;
                continue;
            }

            if (is_dir($full)) {
                // Check known standard layouts immediately at this directory
                $knownLocations = [
                    $full . DIRECTORY_SEPARATOR . 'var' . DIRECTORY_SEPARATOR . 'secure-vault' . DIRECTORY_SEPARATOR . 'data' . DIRECTORY_SEPARATOR . 'secure-vault.sqlite',
                    $full . DIRECTORY_SEPARATOR . 'data' . DIRECTORY_SEPARATOR . 'secure-vault.sqlite',
                    $full . DIRECTORY_SEPARATOR . 'secure-vault.sqlite',
                ];
                foreach ($knownLocations as $known) {
                    if (is_file($known)) {
                        $results[] = $known;
                    }
                }

                // Recurse up to maxDepth
                if ($currentDepth < $maxDepth) {
                    $lower = strtolower($item);
                    $isPromising = ($currentDepth === 0)
                        || str_contains($lower, 'secure')
                        || str_contains($lower, 'vault')
                        || str_contains($lower, 'pkl')
                        || str_contains($lower, 'project')
                        || str_contains($lower, 'app')
                        || str_contains($lower, 'install')
                        || str_contains($lower, 'download')
                        || str_contains($lower, 'code')
                        || str_contains($lower, 'repo')
                        || str_contains($lower, 'backup')
                        || str_contains($lower, 'var')
                        || str_contains($lower, 'data');

                    if ($isPromising) {
                        self::scanConstrainedDirectory($full, $maxDepth, $results, $currentDepth + 1, $visitedDirs, $dirCount);
                    }
                }
            }
        }
    }

    /**
     * Execute safe, atomic, WAL-aware recovery from a candidate installation to the persistent directory.
     */
    public static function recover(array $candidate, string $persistentDir): array
    {
        $sourceDb = $candidate['db_path'];
        $sourcePrivate = $candidate['private_dir'];

        $targetDataDir = $persistentDir . DIRECTORY_SEPARATOR . 'data';
        $targetStorageDir = $persistentDir . DIRECTORY_SEPARATOR . 'storage';
        $targetBackupsDir = $persistentDir . DIRECTORY_SEPARATOR . 'backups';
        $targetDb = $targetDataDir . DIRECTORY_SEPARATOR . 'secure-vault.sqlite';

        self::ensureDirectory($persistentDir, 0700);
        self::ensureDirectory($targetDataDir, 0700);
        self::ensureDirectory($targetStorageDir, 0700);
        self::ensureDirectory($targetBackupsDir, 0700);

        $createdDb = false;
        $createdSecrets = false;
        $tempTargetDb = $targetDb . '.recovering.' . bin2hex(random_bytes(4));

        try {
            // 1. Flush WAL and export database safely using SQLite backup API / VACUUM INTO
            $candidatePdo = new PDO('sqlite:' . $sourceDb, null, null, [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_TIMEOUT => 5,
            ]);
            // Truncate checkpoint to ensure all WAL transactions are merged into the main file
            try {
                $candidatePdo->exec('PRAGMA wal_checkpoint(TRUNCATE)');
            } catch (Throwable $e) {
                // Non-fatal if DB was not in WAL mode
            }

            if (is_file($tempTargetDb)) @unlink($tempTargetDb);

            // VACUUM INTO creates an atomic, defragmented snapshot of the live database
            $candidatePdo->exec("VACUUM INTO " . $candidatePdo->quote($tempTargetDb));
            unset($candidatePdo);

            // Verify recovered database integrity
            if (!self::isDatabaseValid($tempTargetDb)) {
                @unlink($tempTargetDb);
                throw new RuntimeException('Pemulihan gagal: Database hasil snapshot tidak lulus uji integritas.');
            }

            // Atomic swap into place
            if (!rename($tempTargetDb, $targetDb)) {
                @unlink($tempTargetDb);
                throw new RuntimeException('Gagal memindahkan database hasil pemulihan ke lokasi persisten.');
            }
            $createdDb = true;
            @chmod($targetDb, 0600);

            // 2. Recover secrets.php (essential for MFA decryption and JWT signing)
            $possibleSecrets = [
                $sourcePrivate . DIRECTORY_SEPARATOR . 'secrets.php',
                $sourcePrivate . DIRECTORY_SEPARATOR . 'private' . DIRECTORY_SEPARATOR . 'secrets.php',
                dirname($sourcePrivate) . DIRECTORY_SEPARATOR . 'backend_php' . DIRECTORY_SEPARATOR . 'secrets.php',
            ];
            $targetSecrets = $persistentDir . DIRECTORY_SEPARATOR . 'secrets.php';
            $recoveredSecrets = false;
            $foundSourceSecrets = null;
            foreach ($possibleSecrets as $sec) {
                if (is_file($sec)) {
                    $foundSourceSecrets = $sec;
                    break;
                }
            }

            if ($foundSourceSecrets !== null && !is_file($targetSecrets)) {
                if (!copy($foundSourceSecrets, $targetSecrets)) {
                    throw new RuntimeException('Pemulihan gagal: Berkas rahasia lama (secrets.php) ditemukan tetapi gagal disalin ke lokasi persisten.');
                }
                $createdSecrets = true;
                @chmod($targetSecrets, 0600);
                $recoveredSecrets = true;
            } elseif (is_file($targetSecrets)) {
                $recoveredSecrets = true;
            } elseif (!empty($candidate['has_secrets'])) {
                throw new RuntimeException('Pemulihan gagal: Metadata mencatat secrets.php ada tetapi berkas tidak dapat dibaca.');
            } elseif (($candidate['user_count'] ?? 0) > 0) {
                throw new RuntimeException("Pemulihan gagal: Database mencatat {$candidate['user_count']} akun pengguna, tetapi berkas kunci rahasia (secrets.php) tidak ditemukan.");
            }

            // 3. Recover storage (encrypted file chunks)
            $possibleStorageDirs = [
                $sourcePrivate . DIRECTORY_SEPARATOR . 'storage',
                dirname($sourcePrivate) . DIRECTORY_SEPARATOR . 'backend_php' . DIRECTORY_SEPARATOR . 'storage',
                dirname($sourceDb) . DIRECTORY_SEPARATOR . 'storage',
                $sourcePrivate . DIRECTORY_SEPARATOR . 'data' . DIRECTORY_SEPARATOR . 'storage',
                $sourcePrivate . DIRECTORY_SEPARATOR . 'data' . DIRECTORY_SEPARATOR . 'files',
                $sourcePrivate . DIRECTORY_SEPARATOR . 'files',
            ];
            $recoveredChunkDirs = 0;
            $seenStorage = [];
            foreach ($possibleStorageDirs as $srcStorage) {
                $realStorage = realpath($srcStorage);
                if ($realStorage !== false && is_dir($realStorage) && !isset($seenStorage[$realStorage])) {
                    $seenStorage[$realStorage] = true;
                    $recoveredChunkDirs += self::copyDirectoryRecursive($realStorage, $targetStorageDir);
                }
            }

            if (($candidate['chunk_count'] ?? 0) > 0 && $recoveredChunkDirs === 0) {
                throw new RuntimeException("Pemulihan gagal: Database mencatat {$candidate['chunk_count']} chunk terenkripsi, tetapi berkas chunk fisik tidak ditemukan di storage lama.");
            }

            // 4. Recover SMTP settings if present
            $possibleSmtp = [
                $sourcePrivate . DIRECTORY_SEPARATOR . 'smtp.json',
                $sourcePrivate . DIRECTORY_SEPARATOR . 'private' . DIRECTORY_SEPARATOR . 'smtp.json',
            ];
            $targetSmtp = $persistentDir . DIRECTORY_SEPARATOR . 'smtp.json';
            $recoveredSmtp = false;
            if (!is_file($targetSmtp)) {
                foreach ($possibleSmtp as $srcSmtp) {
                    if (is_file($srcSmtp)) {
                        if (copy($srcSmtp, $targetSmtp)) {
                            @chmod($targetSmtp, 0600);
                            $recoveredSmtp = true;
                            break;
                        }
                    }
                }
            }

            // 5. Recover MFA challenge tokens if present
            $sourceMfa = dirname($sourceDb) . DIRECTORY_SEPARATOR . 'mfa_tokens.json';
            $targetMfa = $targetDataDir . DIRECTORY_SEPARATOR . 'mfa_tokens.json';
            $recoveredMfaTokens = false;
            if (is_file($sourceMfa) && !is_file($targetMfa)) {
                if (copy($sourceMfa, $targetMfa)) {
                    @chmod($targetMfa, 0600);
                    $recoveredMfaTokens = true;
                }
            }

            // 6. Write recovery receipt
            $receipt = [
                'timestamp' => gmdate('Y-m-d\TH:i:s.000\Z'),
                'source_db' => $sourceDb,
                'source_private' => $sourcePrivate,
                'target_db' => $targetDb,
                'target_dir' => $persistentDir,
                'user_count' => $candidate['user_count'],
                'audit_count' => $candidate['audit_count'],
                'file_count' => $candidate['file_count'],
                'recovered_secrets' => $recoveredSecrets,
                'recovered_chunk_dirs' => $recoveredChunkDirs,
                'recovered_smtp' => $recoveredSmtp,
                'recovered_mfa_tokens' => $recoveredMfaTokens,
            ];
            $receiptPath = $persistentDir . DIRECTORY_SEPARATOR . 'recovery_receipt.json';
            @file_put_contents($receiptPath, json_encode($receipt, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));

            return $receipt;
        } catch (Throwable $e) {
            // Clean up any partially created files so we never leave broken state
            if (is_file($tempTargetDb)) @unlink($tempTargetDb);
            if ($createdDb && is_file($targetDb)) @unlink($targetDb);
            if ($createdSecrets && is_file($targetSecrets)) @unlink($targetSecrets);
            throw $e;
        }
    }

    /**
     * High-level bootstrap orchestrator called before the application processes requests.
     */
    public static function bootstrap(?string $projectDir = null, ?string $targetDir = null, bool $searchUserDocs = true, ?string $userProfileDir = null): array
    {
        $projectDir = $projectDir ?: dirname(__DIR__, 2);
        $persistentDir = self::resolvePersistentDirectory($targetDir);
        $targetDataDir = $persistentDir . DIRECTORY_SEPARATOR . 'data';
        $targetDb = $targetDataDir . DIRECTORY_SEPARATOR . 'secure-vault.sqlite';

        // Stage 1: Check if persistent data directory already has a valid database
        if (self::isDatabaseValid($targetDb)) {
            $info = self::inspectCandidate($targetDb);
            return [
                'status' => self::STATUS_ALREADY_EXISTS,
                'message' => 'Direktori data persisten aktif dan database valid ditemukan.',
                'persistent_dir' => $persistentDir,
                'db_file' => $targetDb,
                'info' => $info,
            ];
        }

        // Stage 2: Persistent database does not exist. Scan for candidate previous installations.
        $candidates = self::findCandidates($projectDir, $persistentDir, null, $searchUserDocs, $userProfileDir);

        $manual = getenv('SECURE_VAULT_SOURCE_DIR');
        if ($manual !== false && trim($manual) !== '' && empty($candidates)) {
            return [
                'status' => self::STATUS_ERROR,
                'message' => "Direktori sumber SECURE_VAULT_SOURCE_DIR '{$manual}' tidak berisi database SQLite yang valid atau lulus verifikasi.",
                'persistent_dir' => $persistentDir,
            ];
        }

        // Filter candidates that actually contain user accounts (user_count > 0)
        $candidatesWithUsers = array_values(array_filter($candidates, fn($c) => ($c['user_count'] ?? 0) > 0));

        // Case A: Exactly ONE valid candidate with user accounts found -> Automatic Recovery!
        if (count($candidatesWithUsers) === 1) {
            $chosen = $candidatesWithUsers[0];
            try {
                $receipt = self::recover($chosen, $persistentDir);
                return [
                    'status' => self::STATUS_RECOVERED,
                    'message' => 'Database dan data instalasi sebelumnya berhasil dipulihkan secara otomatis.',
                    'persistent_dir' => $persistentDir,
                    'db_file' => $targetDb,
                    'source' => $chosen['db_path'],
                    'receipt' => $receipt,
                ];
            } catch (Throwable $e) {
                return [
                    'status' => self::STATUS_ERROR,
                    'message' => 'Gagal memulihkan database: ' . $e->getMessage(),
                    'persistent_dir' => $persistentDir,
                    'source' => $chosen['db_path'],
                ];
            }
        }

        // Case B: More than one candidate with user accounts found -> Ambiguity safety stop!
        if (count($candidatesWithUsers) > 1) {
            return [
                'status' => self::STATUS_AMBIGUOUS_CANDIDATES,
                'message' => 'Ditemukan lebih dari satu kandidat database lama. Pemilihan otomatis ditunda demi mencegah kehilangan data.',
                'persistent_dir' => $persistentDir,
                'candidates' => $candidatesWithUsers,
            ];
        }

        // Case C: No candidates with users, but maybe a candidate with 0 users (fresh unseeded/seeded)
        if (count($candidates) === 1 && ($candidates[0]['audit_count'] ?? 0) > 0) {
            $chosen = $candidates[0];
            try {
                $receipt = self::recover($chosen, $persistentDir);
                return [
                    'status' => self::STATUS_RECOVERED,
                    'message' => 'Instalasi sebelumnya berhasil dipulihkan.',
                    'persistent_dir' => $persistentDir,
                    'db_file' => $targetDb,
                    'source' => $chosen['db_path'],
                    'receipt' => $receipt,
                ];
            } catch (Throwable $e) {
                return [
                    'status' => self::STATUS_ERROR,
                    'message' => 'Gagal memulihkan database: ' . $e->getMessage(),
                    'persistent_dir' => $persistentDir,
                    'source' => $chosen['db_path'],
                ];
            }
        }

        // Case D: Completely clean machine / fresh installation
        self::ensureDirectory($persistentDir, 0700);
        self::ensureDirectory($targetDataDir, 0700);
        self::ensureDirectory($persistentDir . DIRECTORY_SEPARATOR . 'storage', 0700);
        self::ensureDirectory($persistentDir . DIRECTORY_SEPARATOR . 'backups', 0700);

        return [
            'status' => self::STATUS_NEW_INSTALLATION,
            'message' => 'Instalasi baru terdeteksi (tidak ditemukan database sebelumnya). Sistem siap diinisialisasi.',
            'persistent_dir' => $persistentDir,
            'db_file' => $targetDb,
        ];
    }

    /**
     * Copy directory contents recursively while preserving file contents.
     */
    public static function copyDirectoryRecursive(string $src, string $dst): int
    {
        if (!is_dir($src)) return 0;
        self::ensureDirectory($dst, 0700);

        $copiedCount = 0;
        $items = @scandir($src) ?: [];
        foreach ($items as $item) {
            if ($item === '.' || $item === '..' || $item === '.gitkeep') continue;
            $srcItem = $src . DIRECTORY_SEPARATOR . $item;
            $dstItem = $dst . DIRECTORY_SEPARATOR . $item;

            if (is_dir($srcItem) && !is_link($srcItem)) {
                $copiedCount += self::copyDirectoryRecursive($srcItem, $dstItem);
                $copiedCount++;
            } elseif (is_file($srcItem) && !is_link($srcItem)) {
                if (copy($srcItem, $dstItem)) {
                    @chmod($dstItem, 0600);
                }
            }
        }
        return $copiedCount;
    }

    private static function isSystemTempOrRoot(string $dir): bool
    {
        $norm = self::normalizePath($dir);
        $temp = self::normalizePath(sys_get_temp_dir());
        // Stop scanning upwards if we reach the system temp root itself or drive root
        if ($norm === $temp) {
            return true;
        }
        if (strlen($norm) <= 3) {
            return true;
        }
        return false;
    }

    private static function normalizePath(string $p): string
    {
        return strtolower(rtrim(str_replace('\\', '/', $p), '/'));
    }
}
