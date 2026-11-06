<?php
// backend_php/routes/FileRoutes.php

require_once __DIR__ . '/../config.php';
require_once __DIR__ . '/../db/Database.php';
require_once __DIR__ . '/../utils/Response.php';
require_once __DIR__ . '/../utils/Audit.php';
require_once __DIR__ . '/../middleware/AuthMiddleware.php';

class FileRoutes
{
    private const MAX_FILE_SIZE_BYTES = 524288000; // 500 MiB
    private const CHUNK_SIZE_BYTES = 5242880;      // 5 MiB plaintext chunks
    private const GCM_TAG_BYTES = 16;
    private const MAX_METADATA_FIELD_BYTES = 16384;

    private static function isCompleted(array $file): bool
    {
        // Backward compatibility: Stage 1 records did not carry upload_status.
        return ($file['upload_status'] ?? 'completed') === 'completed';
    }

    private static function decodeBase64Field($value, int $maxBytes): ?string
    {
        if (!is_string($value) || $value === '' || strlen($value) > $maxBytes) return null;
        $decoded = base64_decode($value, true);
        if (!is_string($decoded) || base64_encode($decoded) !== $value) return null;
        return $decoded;
    }

    /** Encrypted text values are encoded as ciphertextB64:ivB64 by the browser. */
    private static function validEncryptedText($value): bool
    {
        if (!is_string($value) || strlen($value) > self::MAX_METADATA_FIELD_BYTES) return false;
        $parts = explode(':', $value);
        if (count($parts) !== 2) return false;
        $ciphertext = self::decodeBase64Field($parts[0], self::MAX_METADATA_FIELD_BYTES);
        $iv = self::decodeBase64Field($parts[1], 64);
        return is_string($ciphertext) && strlen($ciphertext) >= self::GCM_TAG_BYTES
            && is_string($iv) && strlen($iv) === 12;
    }

    private static function requireNotDeleting(array $file): void
    {
        if (!empty($file['deletion_pending'])) {
            Response::error('Berkas sedang dalam proses penghapusan; akses ditangguhkan.', 409);
        }
    }

    private static function requireCompleted(array $file): void
    {
        self::requireNotDeleting($file);
        if (($file['kind'] ?? 'file') !== 'file') Response::error('Objek ini adalah folder, bukan berkas.', 400);
        if (!self::isCompleted($file)) {
            Response::error('Berkas belum lengkap diunggah.', 409);
        }
    }

    private static function validateParentFolder(Database $db, string $ownerId, $parentFolderId): ?string
    {
        if ($parentFolderId === null) return null;
        if (!is_string($parentFolderId) || !preg_match('/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/', $parentFolderId)) {
            Response::error('ID folder tujuan tidak valid.', 400);
        }
        $parent = $db->getFileById($parentFolderId);
        if (!$parent || $parent['owner_id'] !== $ownerId || ($parent['kind'] ?? 'file') !== 'folder'
            || !empty($parent['deletion_pending'])) {
            Response::error('Folder tujuan tidak ditemukan atau akses ditolak.', 404);
        }
        return $parentFolderId;
    }

    public static function list(): void
    {
        $user = AuthMiddleware::authenticate();
        $db = Database::getInstance();
        $files = $db->getFilesByOwner($user['id'], true);
        Response::json(['files' => $files]);
    }

    public static function listFolders(): void
    {
        $user = AuthMiddleware::authenticate();
        Response::json(['folders' => Database::getInstance()->getFoldersByOwner($user['id'])]);
    }

    public static function createFolder(array $body): void
    {
        $user = AuthMiddleware::authenticate();
        $encryptedName = $body['encryptedFolderName'] ?? null;
        $wrappedDek = $body['wrappedDek'] ?? null;
        if (!self::validEncryptedText($encryptedName)) Response::error('Nama folder terenkripsi tidak valid.', 400);
        $decodedWrappedDek = self::decodeBase64Field($wrappedDek, 256);
        if (!is_string($decodedWrappedDek) || strlen($decodedWrappedDek) !== 40) Response::error('Kunci folder terbungkus tidak valid.', 400);
        $db = Database::getInstance();
        $parentId = self::validateParentFolder($db, $user['id'], $body['parentFolderId'] ?? null);
        $folderId = Database::generateUuid();
        $folder = [
            'id' => $folderId,
            'owner_id' => $user['id'],
            'kind' => 'folder',
            'parent_folder_id' => $parentId,
            'encrypted_file_name' => $encryptedName,
            'encrypted_tags' => '',
            'wrapped_dek' => $wrappedDek,
            'file_size_bytes' => 0,
            'total_chunks' => 0,
            'upload_status' => 'completed',
            'quota_accounted' => false,
            'created_at' => gmdate('Y-m-d\TH:i:s.000\Z'),
        ];
        $db->transaction(function (Database $tx) use ($folder, $user, $folderId): void {
            $tx->addFile($folder);
            Audit::logEvent($user['id'], 'FOLDER_CREATE', $folderId, null, null, 'SUCCESS');
        });
        Response::json(['folderId' => $folderId], 201);
    }

    public static function deleteFolder(string $folderId): void
    {
        $user = AuthMiddleware::authenticate();
        $db = Database::getInstance();
        $folder = $db->getFileById($folderId);
        if (!$folder || ($folder['kind'] ?? 'file') !== 'folder' || $folder['owner_id'] !== $user['id']) {
            Response::error('Folder tidak ditemukan atau akses ditolak.', 404);
        }
        if ($db->folderHasChildren($folderId, $user['id'])) Response::error('Folder masih berisi berkas atau subfolder.', 409);
        $db->transaction(function (Database $tx) use ($folderId, $user): void {
            $tx->deleteFile($folderId);
            Audit::logEvent($user['id'], 'FOLDER_DELETE', $folderId, null, null, 'SUCCESS');
        });
        Response::json(['message' => 'Folder kosong berhasil dihapus.']);
    }

    public static function init(array $body): void
    {
        $user = AuthMiddleware::authenticate();
        $encryptedFileName = $body['encryptedFileName'] ?? null;
        $encryptedTags = $body['encryptedTags'] ?? null;
        $wrappedDek = $body['wrappedDek'] ?? null;
        $fileSizeBytes = $body['fileSizeBytes'] ?? null;
        $totalChunks = $body['totalChunks'] ?? null;
        $db = Database::getInstance();
        $parentFolderId = self::validateParentFolder($db, $user['id'], $body['parentFolderId'] ?? null);

        if (!is_int($fileSizeBytes) || !is_int($totalChunks)) {
            Response::error('Ukuran berkas dan jumlah chunk harus berupa bilangan bulat.', 400);
        }
        if ($fileSizeBytes < 1 || $fileSizeBytes > self::MAX_FILE_SIZE_BYTES) {
            Response::error('Ukuran berkas harus antara 1 byte dan 500 MiB.', 413);
        }
        $expectedChunks = (int)ceil($fileSizeBytes / self::CHUNK_SIZE_BYTES);
        if ($totalChunks < 1 || $totalChunks > 100 || $totalChunks !== $expectedChunks) {
            Response::error('Jumlah chunk tidak sesuai ukuran berkas atau melampaui batas.', 400);
        }
        if (!self::validEncryptedText($encryptedFileName) || !self::validEncryptedText($encryptedTags)) {
            Response::error('Metadata nama berkas atau tag terenkripsi tidak valid.', 400);
        }
        $decodedWrappedDek = self::decodeBase64Field($wrappedDek, 256);
        if (!is_string($decodedWrappedDek) || strlen($decodedWrappedDek) !== 40) {
            Response::error('Kunci DEK terbungkus tidak valid.', 400);
        }

        $fileId = Database::generateUuid();
        $fileDir = STORAGE_DIR . DIRECTORY_SEPARATOR . $fileId;
        if (!mkdir($fileDir, 0700, true)) {
            Response::error('Gagal menyiapkan direktori unggahan privat.', 500);
        }
        @chmod($fileDir, 0700);

        $newFile = [
            'id' => $fileId,
            'owner_id' => $user['id'],
            'parent_folder_id' => $parentFolderId,
            'encrypted_file_name' => $encryptedFileName,
            'encrypted_tags' => $encryptedTags,
            'file_size_bytes' => $fileSizeBytes,
            'total_chunks' => $totalChunks,
            'wrapped_dek' => $wrappedDek,
            'created_at' => gmdate('Y-m-d\\TH:i:s.000\\Z'),
        ];

        $reserved = $db->transaction(function (Database $tx) use ($user, $newFile, $fileId, $fileSizeBytes, $totalChunks): bool {
            $ok = $tx->addFileWithQuotaReservation($user['id'], $newFile);
            if ($ok) {
                Audit::logEvent($user['id'], 'FILE_INIT', $fileId, null, null, 'SUCCESS',
                    "size_bytes={$fileSizeBytes};total_chunks={$totalChunks}");
            }
            return $ok;
        });
        if (!$reserved) {
            @rmdir($fileDir);
            Response::error('Kuota penyimpanan terlampaui atau akun tidak tersedia.', 413);
        }
        Response::json(['fileId' => $fileId], 201);
    }

    public static function uploadChunk(string $fileId, int $chunkIndex): void
    {
        $user = AuthMiddleware::authenticate();
        $db = Database::getInstance();
        $file = $db->getFileById($fileId);
        if (!$file || $file['owner_id'] !== $user['id']) {
            Response::error('Akses ditolak: Anda bukan pemilik berkas ini.', 403);
        }
        self::requireNotDeleting($file);
        if (self::isCompleted($file)) {
            Response::error('Berkas telah selesai diunggah dan tidak dapat diubah.', 409);
        }
        $totalChunks = (int)$file['total_chunks'];
        if ($chunkIndex < 0 || $chunkIndex >= $totalChunks) {
            Response::error('Indeks chunk berada di luar rentang yang diizinkan.', 400);
        }

        $ivBase64 = $_POST['ivBase64'] ?? '';
        $aadString = $_POST['aadString'] ?? '';
        $iv = self::decodeBase64Field($ivBase64, 64);
        if (!is_string($iv) || strlen($iv) !== 12) {
            Response::error('IV AES-GCM harus berupa Base64 kanonis sepanjang 12 byte.', 400);
        }
        if (!is_string($aadString) || !hash_equals("{$fileId}-{$chunkIndex}", $aadString)) {
            Response::error('AAD chunk tidak sesuai dengan ID berkas dan indeksnya.', 400);
        }
        if (!isset($_FILES['chunkBlob']) || !is_array($_FILES['chunkBlob'])) {
            Response::error('Data ciphertext chunk tidak ditemukan.', 400);
        }
        $upload = $_FILES['chunkBlob'];
        $uploadError = $upload['error'] ?? UPLOAD_ERR_NO_FILE;
        $temporaryUpload = $upload['tmp_name'] ?? null;
        if (!is_int($uploadError) || !is_string($temporaryUpload)
            || $uploadError !== UPLOAD_ERR_OK || !is_uploaded_file($temporaryUpload)) {
            $code = is_int($uploadError) ? $uploadError : UPLOAD_ERR_NO_FILE;
            Response::error('Data ciphertext chunk gagal diunggah (kode ' . $code . ').', $code === UPLOAD_ERR_INI_SIZE || $code === UPLOAD_ERR_FORM_SIZE ? 413 : 400);
        }

        $plainOffset = $chunkIndex * self::CHUNK_SIZE_BYTES;
        $expectedPlainLength = min(self::CHUNK_SIZE_BYTES, (int)$file['file_size_bytes'] - $plainOffset);
        $expectedCipherLength = $expectedPlainLength + self::GCM_TAG_BYTES;
        $incomingSize = filesize($upload['tmp_name']);
        if (!is_int($incomingSize) || $incomingSize !== $expectedCipherLength) {
            Response::error('Ukuran ciphertext chunk tidak sesuai ukuran plaintext dan tag AES-GCM.', 413);
        }
        $incomingHash = hash_file('sha256', $upload['tmp_name']);
        if (!is_string($incomingHash)) Response::error('Gagal menghitung integritas chunk.', 500);

        $fileDir = STORAGE_DIR . DIRECTORY_SEPARATOR . $fileId;
        if (!is_dir($fileDir) && !mkdir($fileDir, 0700, true) && !is_dir($fileDir)) {
            Response::error('Gagal menyiapkan direktori chunk privat.', 500);
        }
        @chmod($fileDir, 0700);
        $chunkPath = $fileDir . DIRECTORY_SEPARATOR . "chunk_{$chunkIndex}.bin";
        $existingChunk = $db->getChunk($fileId, $chunkIndex);
        if ($existingChunk) {
            $oldPath = $chunkPath;
            $oldHash = is_file($oldPath) ? hash_file('sha256', $oldPath) : false;
            $same = is_string($oldHash)
                && hash_equals($oldHash, $incomingHash)
                && (int)$existingChunk['chunk_size_bytes'] === $incomingSize
                && hash_equals((string)$existingChunk['iv_base64'], $ivBase64)
                && hash_equals((string)$existingChunk['aad_string'], $aadString);
            if ($same) Response::json(['message' => "Chunk #{$chunkIndex} sudah tersimpan.", 'alreadyStored' => true], 200);
            Response::error('Chunk dengan indeks ini sudah ada dengan isi berbeda.', 409);
        }

        $temporaryPath = $fileDir . DIRECTORY_SEPARATOR . '.chunk_' . $chunkIndex . '.' . bin2hex(random_bytes(8)) . '.tmp';
        if (!move_uploaded_file($upload['tmp_name'], $temporaryPath)) {
            Response::error('Gagal menyimpan chunk terenkripsi.', 500);
        }
        @chmod($temporaryPath, 0600);
        if (!rename($temporaryPath, $chunkPath)) {
            @unlink($temporaryPath);
            Response::error('Gagal memfinalisasi penyimpanan chunk.', 500);
        }
        @chmod($chunkPath, 0600);

        $chunkRow = [
            'id' => Database::generateUuid(),
            'file_id' => $fileId,
            'chunk_index' => $chunkIndex,
            'chunk_size_bytes' => $incomingSize,
            'sha256_ciphertext' => $incomingHash,
            'iv_base64' => $ivBase64,
            'aad_string' => $aadString,
            'storage_path' => $chunkPath,
            'created_at' => gmdate('Y-m-d\\TH:i:s.000\\Z'),
        ];
        try {
            $db->transaction(function (Database $tx) use ($chunkRow, $user, $fileId, $chunkIndex, $incomingSize): void {
                $tx->saveChunk($chunkRow);
                Audit::logEvent($user['id'], 'FILE_CHUNK_UPLOAD', $fileId, null, null, 'SUCCESS',
                    "chunk_index={$chunkIndex};ciphertext_bytes={$incomingSize}");
            });
        } catch (Throwable $e) {
            // The DB transaction did not commit, so remove the newly installed object.
            @unlink($chunkPath);
            error_log('Secure Vault chunk metadata commit failed: ' . $e->getMessage());
            Response::error('Metadata chunk gagal disimpan; objek yang baru dipasang telah dibersihkan.', 500);
        }
        Response::json(['message' => "Chunk #{$chunkIndex} berhasil disimpan."], 201);
    }

    public static function complete(string $fileId): void
    {
        $user = AuthMiddleware::authenticate();
        $db = Database::getInstance();
        $file = $db->getFileById($fileId);
        if (!$file || $file['owner_id'] !== $user['id']) Response::error('Berkas tidak ditemukan atau akses ditolak.', 404);
        self::requireNotDeleting($file);
        if (self::isCompleted($file)) {
            Response::json(['message' => 'Pengunggahan berkas sudah selesai sebelumnya.', 'alreadyCompleted' => true]);
        }

        $size = (int)$file['file_size_bytes'];
        $totalChunks = (int)$file['total_chunks'];
        if ($size < 1 || $size > self::MAX_FILE_SIZE_BYTES || $totalChunks !== (int)ceil($size / self::CHUNK_SIZE_BYTES)) {
            Response::error('Metadata unggahan tidak konsisten; unggahan tidak dapat difinalisasi.', 409);
        }
        $chunks = $db->getChunksByFile($fileId);
        if (count($chunks) !== $totalChunks) {
            Response::error('Unggahan belum lengkap: jumlah chunk tersimpan tidak sesuai.', 409);
        }
        for ($i = 0; $i < $totalChunks; $i++) {
            $chunk = $chunks[$i] ?? null;
            if (!is_array($chunk) || (int)$chunk['chunk_index'] !== $i) {
                Response::error('Unggahan belum lengkap: indeks chunk hilang atau berulang.', 409);
            }
            $expectedPlainLength = min(self::CHUNK_SIZE_BYTES, $size - ($i * self::CHUNK_SIZE_BYTES));
            $expectedCipherLength = $expectedPlainLength + self::GCM_TAG_BYTES;
            $path = STORAGE_DIR . DIRECTORY_SEPARATOR . $fileId . DIRECTORY_SEPARATOR . "chunk_{$i}.bin";
            $actualSize = is_file($path) ? filesize($path) : false;
            if (!is_int($actualSize) || $actualSize !== $expectedCipherLength || (int)$chunk['chunk_size_bytes'] !== $expectedCipherLength) {
                Response::error("Unggahan belum lengkap: chunk #{$i} tidak memiliki ukuran yang benar.", 409);
            }
            if (!empty($chunk['sha256_ciphertext'])) {
                $actualHash = hash_file('sha256', $path);
                if (!is_string($actualHash) || !hash_equals((string)$chunk['sha256_ciphertext'], $actualHash)) {
                    Audit::logEvent($user['id'], 'FILE_UPLOAD_INTEGRITY_FAILURE', $fileId, null, null, 'FAILED', "chunk_index={$i}");
                    Response::error("Integritas chunk #{$i} gagal diverifikasi.", 409);
                }
            }
        }

        $result = $db->transaction(function (Database $tx) use ($fileId, $user, $totalChunks, $size): string {
            $status = $tx->markUploadComplete($fileId, $user['id']);
            if ($status === 'completed') {
                // Quota was reserved at init; completion does not charge it a second time.
                Audit::logEvent($user['id'], 'FILE_UPLOAD_COMPLETE', $fileId, null, null, 'SUCCESS',
                    "total_chunks={$totalChunks};file_size_bytes={$size}");
            }
            return $status;
        });
        if ($result === 'already_completed') {
            Response::json(['message' => 'Pengunggahan berkas sudah selesai sebelumnya.', 'alreadyCompleted' => true]);
        }
        if ($result !== 'completed') Response::error('Status unggahan tidak valid.', 409);
        Response::json(['message' => 'Pengunggahan berkas terenkripsi selesai.', 'alreadyCompleted' => false]);
    }

    public static function getChunkMeta(string $fileId, int $chunkIndex): void
    {
        $user = AuthMiddleware::authenticate();
        $db = Database::getInstance();
        $file = $db->getFileById($fileId);
        if (!$file || $file['owner_id'] !== $user['id']) Response::error('Akses ditolak.', 403);
        self::requireCompleted($file);
        if ($chunkIndex < 0 || $chunkIndex >= (int)$file['total_chunks']) Response::error('Indeks chunk tidak valid.', 400);
        $chunk = $db->getChunk($fileId, $chunkIndex);
        if (!$chunk) Response::error("Metadata chunk #{$chunkIndex} tidak ditemukan.", 404);
        Response::json([
            'ivBase64' => $chunk['iv_base64'],
            'aadString' => $chunk['aad_string'],
            'chunkSizeBytes' => (int)$chunk['chunk_size_bytes'],
        ]);
    }

    public static function streamChunkData(string $fileId, int $chunkIndex): void
    {
        $user = AuthMiddleware::authenticate();
        $db = Database::getInstance();
        $file = $db->getFileById($fileId);
        if (!$file || $file['owner_id'] !== $user['id']) Response::error('Akses ditolak.', 403);
        self::requireCompleted($file);
        if ($chunkIndex < 0 || $chunkIndex >= (int)$file['total_chunks']) Response::error('Indeks chunk tidak valid.', 400);
        $chunk = $db->getChunk($fileId, $chunkIndex);
        if (!$chunk) Response::error("Chunk #{$chunkIndex} tidak ditemukan.", 404);
        $chunkPath = STORAGE_DIR . DIRECTORY_SEPARATOR . $fileId . DIRECTORY_SEPARATOR . "chunk_{$chunkIndex}.bin";
        if (!is_file($chunkPath)) Response::error("File chunk #{$chunkIndex} tidak ditemukan di storage.", 404);
        if (!empty($chunk['sha256_ciphertext'])) {
            $actualHash = hash_file('sha256', $chunkPath);
            if (!is_string($actualHash) || !hash_equals((string)$chunk['sha256_ciphertext'], $actualHash)) {
                Audit::logEvent($user['id'], 'FILE_DOWNLOAD_INTEGRITY_FAILURE', $fileId, null, null, 'FAILED', "chunk_index={$chunkIndex}");
                Response::error('Integritas ciphertext gagal diverifikasi; unduhan dihentikan.', 409);
            }
        }
        if ($chunkIndex === 0) Audit::logEvent($user['id'], 'FILE_DOWNLOAD', $fileId, null, null, 'SUCCESS');
        Response::streamBinary($chunkPath);
    }

    public static function updateMetadata(string $fileId, array $body): void
    {
        $user = AuthMiddleware::authenticate();
        $db = Database::getInstance();
        $file = $db->getFileById($fileId);
        if (!$file || $file['owner_id'] !== $user['id']) Response::error('Akses ditolak.', 403);
        self::requireCompleted($file);

        $updates = [];
        $changed = [];
        if (array_key_exists('encryptedFileName', $body)) {
            if (!self::validEncryptedText($body['encryptedFileName'])) Response::error('Format nama berkas terenkripsi tidak valid.', 400);
            $updates['encrypted_file_name'] = $body['encryptedFileName'];
            $changed[] = 'name';
        }
        if (array_key_exists('encryptedTags', $body)) {
            if (!self::validEncryptedText($body['encryptedTags'])) Response::error('Format tag terenkripsi tidak valid.', 400);
            $updates['encrypted_tags'] = $body['encryptedTags'];
            $changed[] = 'tags';
        }
        if (!$updates) Response::error('Tidak ada metadata yang valid untuk diperbarui.', 400);
        $db->transaction(function (Database $tx) use ($fileId, $updates, $user, $changed): void {
            $tx->updateFile($fileId, $updates);
            Audit::logEvent($user['id'], 'FILE_METADATA_UPDATE', $fileId, null, null, 'SUCCESS',
                'fields=' . implode(',', $changed));
        });
        Response::json(['message' => 'Metadata berkas berhasil diperbarui.']);
    }

    public static function delete(string $fileId): void
    {
        $user = AuthMiddleware::authenticate();
        $db = Database::getInstance();
        $file = $db->getFileById($fileId);
        if (!$file) Response::error('Berkas tidak ditemukan.', 404);
        if ($file['owner_id'] !== $user['id']) Response::error('Akses ditolak: hanya pemilik berkas yang dapat menghapus.', 403);
        if (($file['kind'] ?? 'file') !== 'file') Response::error('Gunakan endpoint folder untuk menghapus folder.', 400);

        $fileSize = (int)$file['file_size_bytes'];
        $wasCompleted = self::isCompleted($file);

        // Mark unavailable before touching the filesystem. A retry resumes cleanup.
        if (empty($file['deletion_pending'])) {
            $db->transaction(function (Database $tx) use ($fileId, $user, $fileSize): void {
                $tx->markFileDeletionPending($fileId);
                Audit::logEvent($user['id'], 'FILE_DELETE_PENDING', $fileId, null, null, 'SUCCESS',
                    "file_size_bytes={$fileSize}");
            });
        }

        $fileDir = STORAGE_DIR . DIRECTORY_SEPARATOR . $fileId;
        if (is_link($fileDir)) {
            if (!unlink($fileDir)) Response::error('Penghapusan ditandai tertunda; tautan storage tidak dapat dilepas. Periksa izin lalu ulangi DELETE.', 500);
        } elseif (is_file($fileDir)) {
            if (!unlink($fileDir)) Response::error('Penghapusan ditandai tertunda; objek storage tidak dapat dilepas. Periksa izin lalu ulangi DELETE.', 500);
        } elseif (is_dir($fileDir)) {
            $entries = scandir($fileDir);
            if (!is_array($entries)) Response::error('Penghapusan ditandai tertunda, tetapi direktori storage tidak dapat dibaca. Ulangi DELETE untuk melanjutkan.', 500);
            foreach ($entries as $entry) {
                if ($entry === '.' || $entry === '..') continue;
                $path = $fileDir . DIRECTORY_SEPARATOR . $entry;
                if ((is_file($path) || is_link($path)) && !unlink($path)) {
                    Response::error('Penghapusan ditandai tertunda; objek storage belum dapat dihapus. Perbaiki izin lalu ulangi DELETE.', 500);
                }
                if (is_dir($path)) Response::error('Penghapusan ditandai tertunda; ditemukan subdirektori tidak dikenal. Pemeriksaan manual diperlukan.', 500);
            }
            if (!rmdir($fileDir)) Response::error('Penghapusan ditandai tertunda; direktori storage belum dapat dihapus. Ulangi DELETE setelah memeriksa izin.', 500);
        }

        // Commit metadata removal, quota release, and the final audit event together.
        $db->transaction(function (Database $tx) use ($fileId, $user, $fileSize, $wasCompleted): void {
            $tx->deleteFileAndReleaseQuota($fileId);
            Audit::logEvent($user['id'], 'FILE_DELETE', $fileId, null, null, 'SUCCESS',
                "file_size_bytes={$fileSize};upload_status=" . ($wasCompleted ? 'completed' : 'uploading'));
        });
        Response::json(['message' => 'Berkas dan metadata chunk telah dihapus dari penyimpanan aplikasi.']);
    }

}
