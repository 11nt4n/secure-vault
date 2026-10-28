<?php
// backend_php/routes/FileRoutes.php

require_once __DIR__ . '/../config.php';
require_once __DIR__ . '/../db/Database.php';
require_once __DIR__ . '/../utils/Response.php';
require_once __DIR__ . '/../utils/Audit.php';
require_once __DIR__ . '/../middleware/AuthMiddleware.php';

class FileRoutes
{
    public static function list(): void
    {
        $user = AuthMiddleware::authenticate();
        $db = Database::getInstance();
        $files = $db->getFilesByOwner($user['id']);

        Response::json(['files' => $files]);
    }

    public static function init(array $body): void
    {
        $user = AuthMiddleware::authenticate();
        $encryptedFileName = $body['encryptedFileName'] ?? null;
        $encryptedTags = $body['encryptedTags'] ?? null;
        $fileSizeBytes = isset($body['fileSizeBytes']) ? (int)$body['fileSizeBytes'] : null;
        $totalChunks = isset($body['totalChunks']) ? (int)$body['totalChunks'] : null;
        $wrappedDek = $body['wrappedDek'] ?? null;
        $plaintextSha256 = $body['plaintextSha256'] ?? null;

        if (!$encryptedFileName || !$fileSizeBytes || !$totalChunks || !$wrappedDek || !$plaintextSha256) {
            Response::error('Metadata berkas tidak lengkap.', 400);
        }

        // Check quota
        if (($user['storage_used_bytes'] + $fileSizeBytes) > $user['storage_quota_bytes']) {
            Response::error('Kuota penyimpanan brankas Anda telah terlampaui.', 413);
        }

        $fileId = Database::generateUuid();
        $newFile = [
            'id' => $fileId,
            'owner_id' => $user['id'],
            'encrypted_file_name' => $encryptedFileName,
            'encrypted_tags' => $encryptedTags,
            'file_size_bytes' => $fileSizeBytes,
            'total_chunks' => $totalChunks,
            'wrapped_dek' => $wrappedDek,
            'plaintext_sha256' => $plaintextSha256,
            'created_at' => gmdate('Y-m-d\TH:i:s.000\Z')
        ];

        $db = Database::getInstance();
        $db->addFile($newFile);

        // Create storage directory for chunks
        $fileDir = STORAGE_DIR . DIRECTORY_SEPARATOR . $fileId;
        if (!is_dir($fileDir)) {
            mkdir($fileDir, 0755, true);
        }

        Audit::logEvent($user['id'], 'FILE_INIT', $fileId, null, null, 'SUCCESS');

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

        $ivBase64 = $_POST['ivBase64'] ?? '';
        $aadString = $_POST['aadString'] ?? '';

        if (!isset($_FILES['chunkBlob']) || $_FILES['chunkBlob']['error'] !== UPLOAD_ERR_OK) {
            Response::error('Data ciphertext chunk tidak ditemukan atau gagal diunggah.', 400);
        }

        $fileDir = STORAGE_DIR . DIRECTORY_SEPARATOR . $fileId;
        if (!is_dir($fileDir)) {
            mkdir($fileDir, 0755, true);
        }

        $chunkPath = $fileDir . DIRECTORY_SEPARATOR . "chunk_{$chunkIndex}.bin";
        if (!move_uploaded_file($_FILES['chunkBlob']['tmp_name'], $chunkPath)) {
            Response::error('Gagal menyimpan berkas chunk ke server.', 500);
        }

        $chunkSize = filesize($chunkPath);

        $chunkRow = [
            'id' => Database::generateUuid(),
            'file_id' => $fileId,
            'chunk_index' => $chunkIndex,
            'chunk_size_bytes' => $chunkSize,
            'iv_base64' => (string)$ivBase64,
            'aad_string' => (string)$aadString,
            'storage_path' => $chunkPath,
            'created_at' => gmdate('Y-m-d\TH:i:s.000\Z')
        ];

        $db->saveChunk($chunkRow);

        Response::json(['message' => "Chunk #{$chunkIndex} berhasil disimpan."], 201);
    }

    public static function complete(string $fileId): void
    {
        $user = AuthMiddleware::authenticate();
        $db = Database::getInstance();
        $file = $db->getFileById($fileId);

        if (!$file || $file['owner_id'] !== $user['id']) {
            Response::error('Akses ditolak.', 403);
        }

        // Update storage used
        $newUsed = $user['storage_used_bytes'] + $file['file_size_bytes'];
        $db->updateUser($user['id'], ['storage_used_bytes' => $newUsed]);

        Audit::logEvent($user['id'], 'FILE_UPLOAD_COMPLETE', $fileId, null, null, 'SUCCESS');

        Response::json(['message' => 'Pengunggahan berkas terenkripsi selesai.']);
    }

    public static function getChunkMeta(string $fileId, int $chunkIndex): void
    {
        $user = AuthMiddleware::authenticate();
        $db = Database::getInstance();
        $file = $db->getFileById($fileId);

        if (!$file || $file['owner_id'] !== $user['id']) {
            Response::error('Akses ditolak.', 403);
        }

        $chunk = $db->getChunk($fileId, $chunkIndex);
        if (!$chunk) {
            Response::error("Metadata chunk #{$chunkIndex} tidak ditemukan.", 404);
        }

        Response::json([
            'ivBase64' => $chunk['iv_base64'],
            'aadString' => $chunk['aad_string'],
            'chunkSizeBytes' => (int)$chunk['chunk_size_bytes']
        ]);
    }

    public static function streamChunkData(string $fileId, int $chunkIndex): void
    {
        $user = AuthMiddleware::authenticate();
        $db = Database::getInstance();
        $file = $db->getFileById($fileId);

        if (!$file || $file['owner_id'] !== $user['id']) {
            Response::error('Akses ditolak.', 403);
        }

        $chunkPath = STORAGE_DIR . DIRECTORY_SEPARATOR . $fileId . DIRECTORY_SEPARATOR . "chunk_{$chunkIndex}.bin";
        if (!file_exists($chunkPath)) {
            Response::error("File chunk #{$chunkIndex} tidak ditemukan di storage.", 404);
        }

        if ($chunkIndex === 0) {
            Audit::logEvent($user['id'], 'FILE_DOWNLOAD', $fileId, null, null, 'SUCCESS');
        }

        Response::streamBinary($chunkPath);
    }

    public static function updateMetadata(string $fileId, array $body): void
    {
        $user = AuthMiddleware::authenticate();
        $db = Database::getInstance();
        $file = $db->getFileById($fileId);

        if (!$file || $file['owner_id'] !== $user['id']) {
            Response::error('Akses ditolak.', 403);
        }

        $updates = [];
        if (isset($body['encryptedFileName'])) {
            $updates['encrypted_file_name'] = $body['encryptedFileName'];
        }
        if (isset($body['encryptedTags'])) {
            $updates['encrypted_tags'] = $body['encryptedTags'];
        }

        if (!empty($updates)) {
            $db->updateFile($fileId, $updates);
        }

        Response::json(['message' => 'Metadata berkas berhasil diperbarui.']);
    }

    public static function delete(string $fileId): void
    {
        $user = AuthMiddleware::authenticate();
        $db = Database::getInstance();
        $file = $db->getFileById($fileId);

        if (!$file) {
            Response::error('Berkas tidak ditemukan.', 404);
        }

        if ($file['owner_id'] !== $user['id']) {
            Response::error('Akses ditolak: Hanya pemilik berkas yang dapat menghapus.', 403);
        }

        // Delete physical chunks from disk
        $fileDir = STORAGE_DIR . DIRECTORY_SEPARATOR . $fileId;
        if (is_dir($fileDir)) {
            $files = glob($fileDir . DIRECTORY_SEPARATOR . '*');
            foreach ($files as $f) {
                if (is_file($f)) unlink($f);
            }
            rmdir($fileDir);
        }

        // Reduce user storage
        $newUsed = max(0, $user['storage_used_bytes'] - $file['file_size_bytes']);
        $db->updateUser($user['id'], ['storage_used_bytes' => $newUsed]);

        // Remove from database
        $db->deleteFile($fileId);

        Audit::logEvent($user['id'], 'FILE_DELETE', $fileId, null, null, 'SUCCESS');

        Response::json(['message' => 'Berkas dan seluruh chunk terenkripsi berhasil dimusnahkan secara aman.']);
    }
}
