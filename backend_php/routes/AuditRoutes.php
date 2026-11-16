<?php
// backend_php/routes/AuditRoutes.php

require_once __DIR__ . '/../config.php';
require_once __DIR__ . '/../db/Database.php';
require_once __DIR__ . '/../utils/Response.php';
require_once __DIR__ . '/../utils/Audit.php';
require_once __DIR__ . '/../middleware/AuthMiddleware.php';

class AuditRoutes
{
    public static function list(): void
    {
        $user = AuthMiddleware::authenticate();
        AuthMiddleware::requireAdmin($user);
        $db = Database::getInstance();
        $logs = $db->getAuditLogs();

        // Sort descending by sequence number
        usort($logs, fn($a, $b) => (int)$b['sequence_number'] <=> (int)$a['sequence_number']);

        Response::json(['logs' => $logs]);
    }

    public static function verify(): void
    {
        $user = AuthMiddleware::authenticate();
        AuthMiddleware::requireAdmin($user);
        $result = Audit::verifyChain();
        Response::json($result);
    }
}
