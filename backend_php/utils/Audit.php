<?php
// backend_php/utils/Audit.php

require_once __DIR__ . '/../db/Database.php';

class Audit
{
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

    public static function logEvent(
        string $userId,
        string $actionType,
        ?string $fileId = null,
        ?string $ipAddress = null,
        ?string $userAgent = null,
        string $status = 'SUCCESS'
    ): array {
        $db = Database::getInstance();
        $logs = $db->getAuditLogs();
        $lastLog = count($logs) > 0 ? $logs[count($logs) - 1] : null;

        $prevHash = $lastLog ? $lastLog['current_hash'] : str_repeat('0', 64);
        $timestamp = gmdate('Y-m-d\TH:i:s.000\Z');
        $seq = $lastLog ? ((int)$lastLog['sequence_number'] + 1) : 1;

        $currHash = self::computeLogHash(
            $prevHash,
            $timestamp,
            $userId,
            $actionType,
            $fileId,
            $status
        );

        $newLog = [
            'id' => Database::generateUuid(),
            'sequence_number' => $seq,
            'timestamp' => $timestamp,
            'user_id' => $userId,
            'action_type' => $actionType,
            'file_id' => $fileId,
            'ip_address' => $ipAddress ?: ($_SERVER['REMOTE_ADDR'] ?? '127.0.0.1'),
            'user_agent' => $userAgent ?: ($_SERVER['HTTP_USER_AGENT'] ?? 'SecureVault/PHP'),
            'status' => $status,
            'previous_hash' => $prevHash,
            'current_hash' => $currHash
        ];

        $db->addAuditLog($newLog);
        return $newLog;
    }

    public static function verifyChain(): array
    {
        $db = Database::getInstance();
        $logs = $db->getAuditLogs();
        $total = count($logs);

        if ($total === 0) {
            return [
                'isValid' => true,
                'totalRecords' => 0,
                'message' => 'Rantai audit kosong.'
            ];
        }

        for ($i = 0; $i < $total; $i++) {
            $entry = $logs[$i];

            // Verify previous_hash link
            if ($i > 0) {
                $prev = $logs[$i - 1];
                if ($entry['previous_hash'] !== $prev['current_hash']) {
                    return [
                        'isValid' => false,
                        'totalRecords' => $total,
                        'brokenSequence' => $entry['sequence_number'],
                        'message' => "Rantai terputus pada sequence #{$entry['sequence_number']}! previous_hash tidak cocok dengan current_hash sebelumnya."
                    ];
                }
            }

            // Recompute current hash
            $recalculated = self::computeLogHash(
                $entry['previous_hash'],
                $entry['timestamp'],
                $entry['user_id'],
                $entry['action_type'],
                $entry['file_id'] ?? null,
                $entry['status']
            );

            if ($recalculated !== $entry['current_hash']) {
                return [
                    'isValid' => false,
                    'totalRecords' => $total,
                    'brokenSequence' => $entry['sequence_number'],
                    'message' => "Manipulasi data terdeteksi pada sequence #{$entry['sequence_number']}! Hash tersimpan tidak cocok dengan hash payload."
                ];
            }
        }

        return [
            'isValid' => true,
            'totalRecords' => $total,
            'message' => "Semua {$total} blok jejak audit 100% konsisten, valid, dan tahan manipulasi."
        ];
    }
}
