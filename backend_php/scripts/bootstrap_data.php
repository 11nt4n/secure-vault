<?php
// backend_php/scripts/bootstrap_data.php
// Automated pre-flight data bootstrap and legacy installation recovery.
// Executed by start_all_php.bat prior to launching PHP server processes.

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit(1);
}

require_once dirname(__DIR__) . '/utils/PersistentStorage.php';

$projectDir = dirname(__DIR__, 2);
$result = PersistentStorage::bootstrap($projectDir);

echo "========================================================\n";
echo "  SECURE VAULT - DATA BOOTSTRAP & PERSISTENT STORAGE    \n";
echo "========================================================\n";

switch ($result['status']) {
    case PersistentStorage::STATUS_ALREADY_EXISTS:
        $info = $result['info'] ?? [];
        $userCount = $info['user_count'] ?? 0;
        $auditCount = $info['audit_count'] ?? 0;
        $fileCount = $info['file_count'] ?? 0;

        echo "[OK] Penyimpanan lokal persisten aktif dan siap digunakan.\n";
        echo "     Direktori : " . $result['persistent_dir'] . "\n";
        echo "     Database  : " . $result['db_file'] . "\n";
        echo "     Status    : {$userCount} pengguna, {$fileCount} file, {$auditCount} log audit.\n";
        if ($userCount === 0) {
            echo "\n[INFO] Belum ada akun terdaftar pada sistem.\n";
            echo "       Jalankan 'php backend_php/scripts/init_admin.php' untuk membuat akun administrator awal.\n";
        }
        echo "========================================================\n\n";
        exit(0);

    case PersistentStorage::STATUS_RECOVERED:
        $receipt = $result['receipt'] ?? [];
        $userCount = $receipt['user_count'] ?? 0;
        $auditCount = $receipt['audit_count'] ?? 0;
        $fileCount = $receipt['file_count'] ?? 0;
        $secStatus = !empty($receipt['recovered_secrets']) ? 'Berhasil dipulihkan' : 'Dibuat baru';

        echo "[SUKSES] Instalasi sebelumnya berhasil dipulihkan secara otomatis!\n";
        echo "         Sumber     : " . ($result['source'] ?? '-') . "\n";
        echo "         Target     : " . $result['persistent_dir'] . "\n";
        echo "         Pengguna   : {$userCount} akun dipulihkan\n";
        echo "         Audit Log  : {$auditCount} entri (integritas terjaga)\n";
        echo "         File Vault : {$fileCount} file terenkripsi dipulihkan\n";
        echo "         Kunci MFA  : {$secStatus}\n";
        echo "\nPengguna dapat langsung login menggunakan username dan password lama.\n";
        echo "========================================================\n\n";
        exit(0);

    case PersistentStorage::STATUS_NEW_INSTALLATION:
        echo "[INFO] Instalasi baru terdeteksi (tidak ada database sebelumnya pada komputer ini).\n";
        echo "       Direktori data baru: " . $result['persistent_dir'] . "\n";
        echo "       Penyimpanan lokal telah disiapkan secara aman.\n";
        echo "\n[PERHATIAN] Belum ada akun administrator.\n";
        echo "            Jalankan perintah berikut pada terminal:\n";
        echo "            php backend_php/scripts/init_admin.php\n";
        echo "========================================================\n\n";
        exit(0);

    case PersistentStorage::STATUS_AMBIGUOUS_CANDIDATES:
        echo "[PERINGATAN] Ditemukan lebih dari satu kandidat database lama:\n";
        foreach (($result['candidates'] ?? []) as $i => $cand) {
            $num = $i + 1;
            $timeStr = date('Y-m-d H:i:s', $cand['mtime']);
            echo "  [{$num}] {$cand['db_path']}\n";
            echo "      Pengguna : {$cand['user_count']} | Audit: {$cand['audit_count']} | Waktu: {$timeStr}\n";
        }
        echo "\nDemi keamanan dan mencegah salah pilih, sistem tidak memilih secara otomatis.\n";
        echo "Untuk memulihkan database tertentu, tetapkan variabel lingkungan sebelum menjalankan aplikasi:\n";
        echo "  set SECURE_VAULT_SOURCE_DIR=<path_folder_data_yang_dipilih>\n";
        echo "Contoh:\n";
        echo "  set SECURE_VAULT_SOURCE_DIR=" . dirname($result['candidates'][0]['db_path']) . "\n";
        echo "========================================================\n\n";
        exit(2);

    case PersistentStorage::STATUS_ERROR:
    default:
        echo "[ERROR] Terjadi kesalahan pada proses bootstrap:\n";
        echo "        " . ($result['message'] ?? 'Unknown error') . "\n";
        echo "========================================================\n\n";
        exit(1);
}
