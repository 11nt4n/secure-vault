<?php
// Promote a registered account using a trusted server-side CLI, never a web/API request.
if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit(1);
}

require_once dirname(__DIR__) . '/config.php';
require_once dirname(__DIR__) . '/db/Database.php';
require_once dirname(__DIR__) . '/utils/Audit.php';

$username = trim((string)($argv[1] ?? ''));
if ($username === '') {
    fwrite(STDERR, "Usage: php backend_php/scripts/promote_admin.php <registered-username>\n");
    exit(2);
}
$db = Database::getInstance();
$user = $db->getUserByUsername($username);
if (!$user) {
    fwrite(STDERR, "No registered account named '{$username}' was found. Register the account in the app first.\n");
    exit(3);
}
if (($user['role'] ?? 'user') === 'admin') {
    fwrite(STDOUT, "Account '{$username}' is already an administrator.\n");
    exit(0);
}
fwrite(STDOUT, "Promote '{$username}' ({$user['email']}) to administrator? Type the username again to confirm: ");
$confirmation = trim((string)fgets(STDIN));
if (!hash_equals($username, $confirmation)) {
    fwrite(STDERR, "Confirmation did not match; no changes made.\n");
    exit(4);
}
$db->updateUser((string)$user['id'], ['role' => 'admin']);
Audit::logEvent('SYSTEM_CLI_OPERATOR', 'ADMIN_ROLE_PROMOTION', null, '127.0.0.1', 'SecureVault CLI promote_admin.php', 'SUCCESS');
fwrite(STDOUT, "Account promoted. Keep this operation restricted to trusted server operators.\n");
