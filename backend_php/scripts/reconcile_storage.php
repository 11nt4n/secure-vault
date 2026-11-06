<?php
// Conservative storage reconciliation. Default is dry-run; --apply moves only
// unreferenced directories and abandoned *.tmp files into a private quarantine.
require_once __DIR__ . '/../config.php';
require_once __DIR__ . '/../db/Database.php';

if (PHP_SAPI !== 'cli') { fwrite(STDERR, "CLI only.\n"); exit(2); }
$apply = in_array('--apply', $argv, true);
$db = Database::getInstance();
$knownFiles = [];
$knownChunks = [];
foreach ($db->getUsers() as $user) {
    foreach ($db->getFilesByOwner((string)$user['id'], true) as $file) {
        $knownFiles[(string)$file['id']] = true;
        foreach ($db->getChunksByFile((string)$file['id']) as $chunk) {
            $knownChunks[(string)$file['id'] . '/' . basename((string)$chunk['storage_path'])] = true;
        }
    }
}
$quarantine = PRIVATE_DIR . DIRECTORY_SEPARATOR . 'storage-quarantine';
if ($apply && !is_dir($quarantine) && !mkdir($quarantine, 0700, true) && !is_dir($quarantine)) {
    fwrite(STDERR, "Cannot create quarantine directory.\n"); exit(1);
}
$report = ['orphan_directories' => [], 'orphan_temp_files' => [], 'missing_chunk_files' => [], 'quarantined' => []];
$entries = scandir(STORAGE_DIR) ?: [];
foreach ($entries as $entry) {
    if ($entry === '.' || $entry === '..') continue;
    $path = STORAGE_DIR . DIRECTORY_SEPARATOR . $entry;
    if (!is_dir($path) || is_link($path)) continue;
    if (!isset($knownFiles[$entry])) {
        $report['orphan_directories'][] = $entry;
        if ($apply) {
            $target = $quarantine . DIRECTORY_SEPARATOR . 'orphan-dir-' . $entry . '-' . bin2hex(random_bytes(4));
            if (rename($path, $target)) $report['quarantined'][] = $entry;
        }
        continue;
    }
    foreach (scandir($path) ?: [] as $child) {
        if ($child === '.' || $child === '..') continue;
        $childPath = $path . DIRECTORY_SEPARATOR . $child;
        if (str_ends_with($child, '.tmp') && is_file($childPath) && !is_link($childPath)) {
            $report['orphan_temp_files'][] = $entry . '/' . $child;
            if ($apply) {
                $target = $quarantine . DIRECTORY_SEPARATOR . 'orphan-tmp-' . $entry . '-' . bin2hex(random_bytes(4));
                if (rename($childPath, $target)) $report['quarantined'][] = $entry . '/' . $child;
            }
        }
    }
}
foreach (array_keys($knownChunks) as $relative) {
    $path = STORAGE_DIR . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $relative);
    if (!is_file($path)) $report['missing_chunk_files'][] = $relative;
}
fwrite(STDOUT, json_encode(['mode' => $apply ? 'apply' : 'dry-run', 'report' => $report], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL);
if (count($report['missing_chunk_files']) > 0) exit(10);
