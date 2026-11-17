<?php
// backend_php/utils/Audit.php

require_once __DIR__ . '/../db/Database.php';

class Audit
{
    /** Legacy v1 hash retained only to verify records written by Stage 1. */
    public static function computeLogHash(
        string $prevHash,
        string $timestamp,
        string $userId,
        string $actionType,
        ?string $fileId,
        string $status
    ): string {
        $fileIdStr = $fileId ?? '';
        $payload = "{$prevHash}:{$timestamp}:{$userId}:{$actionType}:{$fileIdStr}:{$status}";
        return hash('sha256', $payload);
    }

    /** V2 hash covers the complete security-relevant record using canonical key order (SHA-256). */
    public static function computeEntryHash(array $entry): string
    {
        return self::computeEntryHashV2($entry);
    }

    /** V2 historical hash implementation retained for backward compatibility. */
    public static function computeEntryHashV2(array $entry): string
    {
        $payload = [
            'version' => 2,
            'id' => (string)$entry['id'],
            'sequence_number' => (int)$entry['sequence_number'],
            'timestamp' => (string)$entry['timestamp'],
            'user_id' => (string)$entry['user_id'],
            'action_type' => (string)$entry['action_type'],
            'file_id' => $entry['file_id'] ?? null,
            'status' => (string)$entry['status'],
            'ip_address' => (string)$entry['ip_address'],
            'user_agent' => (string)$entry['user_agent'],
            'details' => $entry['details'] ?? null,
            'previous_hash' => (string)$entry['previous_hash'],
        ];
        $encoded = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if (!is_string($encoded)) {
            throw new RuntimeException('Unable to serialize audit hash payload.');
        }
        return hash('sha256', $encoded);
    }

    /** V3 hash implementation using SHA3-512 (128-hex-character digest). */
    public static function computeEntryHashV3(array $entry): string
    {
        $payload = [
            'version' => 3,
            'id' => (string)$entry['id'],
            'sequence_number' => (int)$entry['sequence_number'],
            'timestamp' => (string)$entry['timestamp'],
            'user_id' => (string)$entry['user_id'],
            'action_type' => (string)$entry['action_type'],
            'file_id' => $entry['file_id'] ?? null,
            'status' => (string)$entry['status'],
            'ip_address' => (string)$entry['ip_address'],
            'user_agent' => (string)$entry['user_agent'],
            'details' => $entry['details'] ?? null,
            'previous_hash' => (string)$entry['previous_hash'],
        ];
        $encoded = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if (!is_string($encoded)) {
            throw new RuntimeException('Unable to serialize audit hash payload.');
        }
        return hash('sha3-512', $encoded);
    }

    public static function logEvent(
        string $userId,
        string $actionType,
        ?string $fileId = null,
        ?string $ipAddress = null,
        ?string $userAgent = null,
        string $status = 'SUCCESS',
        ?string $details = null
    ): array {
        $db = Database::getInstance();
        $logs = $db->getAuditLogs();
        $lastLog = count($logs) > 0 ? $logs[count($logs) - 1] : null;

        $prevHash = $lastLog ? (string)$lastLog['current_hash'] : str_repeat('0', 128);
        $timestamp = gmdate('Y-m-d\\TH:i:s.000\\Z');
        $seq = $lastLog ? ((int)$lastLog['sequence_number'] + 1) : 1;
        $entry = [
            'id' => Database::generateUuid(),
            'sequence_number' => $seq,
            'timestamp' => $timestamp,
            'user_id' => $userId,
            'action_type' => $actionType,
            'file_id' => $fileId,
            'ip_address' => $ipAddress ?: ($_SERVER['REMOTE_ADDR'] ?? '127.0.0.1'),
            'user_agent' => $userAgent ?: ($_SERVER['HTTP_USER_AGENT'] ?? 'SecureVault/PHP'),
            'status' => $status,
            'details' => $details,
            'hash_version' => 3,
            'previous_hash' => $prevHash,
        ];
        $entry['current_hash'] = self::computeEntryHashV3($entry);
        $db->addAuditLog($entry);
        return $entry;
    }

    public static function verifyChain(): array
    {
        $logs = Database::getInstance()->getAuditLogs();
        $total = count($logs);
        $expectedPrevious = '';

        if ($total === 0) {
            return ['isValid' => true, 'totalRecords' => 0, 'message' => 'Rantai audit kosong.'];
        }

        for ($i = 0; $i < $total; $i++) {
            $entry = $logs[$i];
            $sequence = (int)($entry['sequence_number'] ?? 0);
            if ($sequence !== $i + 1) {
                return [
                    'isValid' => false,
                    'totalRecords' => $total,
                    'brokenSequence' => $sequence,
                    'message' => "Nomor urut audit tidak kontinu pada posisi #" . ($i + 1) . '.',
                ];
            }

            $version = (int)($entry['hash_version'] ?? 1);

            // Validasi keterhubungan rantai / genesis berdasarkan versi
            if ($i === 0) {
                if ($version === 1 || $version === 2) {
                    $expectedGenesis = str_repeat('0', 64);
                } elseif ($version === 3) {
                    $expectedGenesis = str_repeat('0', 128);
                } else {
                    return [
                        'isValid' => false,
                        'totalRecords' => $total,
                        'brokenSequence' => $sequence,
                        'message' => "Versi hash audit tidak didukung pada sequence #{$sequence}.",
                    ];
                }

                if (!isset($entry['previous_hash']) || !hash_equals($expectedGenesis, (string)$entry['previous_hash'])) {
                    return [
                        'isValid' => false,
                        'totalRecords' => $total,
                        'brokenSequence' => $sequence,
                        'message' => "Format genesis hash tidak valid pada sequence #{$sequence}.",
                    ];
                }
            } else {
                if (!isset($entry['previous_hash']) || !hash_equals($expectedPrevious, (string)$entry['previous_hash'])) {
                    return [
                        'isValid' => false,
                        'totalRecords' => $total,
                        'brokenSequence' => $sequence,
                        'message' => "Rantai audit terputus pada sequence #{$sequence}.",
                    ];
                }
            }

            // Validasi integritas dan perhitungan ulang hash berdasarkan versi
            if ($version === 3) {
                $required = ['id', 'timestamp', 'user_id', 'action_type', 'status', 'ip_address', 'user_agent', 'current_hash'];
                foreach ($required as $field) {
                    if (!array_key_exists($field, $entry)) {
                        return [
                            'isValid' => false,
                            'totalRecords' => $total,
                            'brokenSequence' => $sequence,
                            'message' => "Atribut wajib audit '{$field}' hilang pada sequence #{$sequence}.",
                        ];
                    }
                }
                $recalculated = self::computeEntryHashV3($entry);
            } elseif ($version === 2) {
                $required = ['id', 'timestamp', 'user_id', 'action_type', 'status', 'ip_address', 'user_agent', 'current_hash'];
                foreach ($required as $field) {
                    if (!array_key_exists($field, $entry)) {
                        return [
                            'isValid' => false,
                            'totalRecords' => $total,
                            'brokenSequence' => $sequence,
                            'message' => "Atribut wajib audit '{$field}' hilang pada sequence #{$sequence}.",
                        ];
                    }
                }
                $recalculated = self::computeEntryHashV2($entry);
            } elseif ($version === 1) {
                // Stage 1 did not include ID, sequence, IP, user-agent or details in its hash.
                // This branch is compatibility-only; old records should be externally anchored/migrated.
                $recalculated = self::computeLogHash(
                    (string)$entry['previous_hash'],
                    (string)$entry['timestamp'],
                    (string)$entry['user_id'],
                    (string)$entry['action_type'],
                    isset($entry['file_id']) ? (string)$entry['file_id'] : null,
                    (string)$entry['status']
                );
            } else {
                return [
                    'isValid' => false,
                    'totalRecords' => $total,
                    'brokenSequence' => $sequence,
                    'message' => "Versi hash audit tidak didukung pada sequence #{$sequence}.",
                ];
            }

            if (!is_string($entry['current_hash'] ?? null) || !hash_equals($recalculated, $entry['current_hash'])) {
                return [
                    'isValid' => false,
                    'totalRecords' => $total,
                    'brokenSequence' => $sequence,
                    'message' => "Manipulasi data terdeteksi pada sequence #{$sequence}; hash tidak cocok.",
                ];
            }
            $expectedPrevious = (string)$entry['current_hash'];
        }

        $legacyV1 = count(array_filter($logs, fn($entry) => (int)($entry['hash_version'] ?? 1) === 1));
        $legacyV2 = count(array_filter($logs, fn($entry) => (int)($entry['hash_version'] ?? 1) === 2));
        $v3Count = count(array_filter($logs, fn($entry) => (int)($entry['hash_version'] ?? 1) === 3));

        $message = "Semua {$total} entri konsisten menurut versi hash masing-masing.";
        if ($legacyV1 > 0) {
            $message .= " {$legacyV1} entri versi lama (v1) belum melindungi seluruh atribut.";
        }
        if ($v3Count > 0) {
            $message .= " {$v3Count} entri versi 3 dilindungi oleh SHA3-512.";
        }
        return [
            'isValid' => true,
            'totalRecords' => $total,
            'legacyRecords' => $legacyV1,
            'v2Records' => $legacyV2,
            'v3Records' => $v3Count,
            'message' => $message
        ];
    }
}
