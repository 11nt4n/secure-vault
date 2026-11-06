<?php
// Generate stable local-only secrets outside the PHP web root.
if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit(1);
}

$projectDir = dirname(__DIR__, 2);
$privateDir = $projectDir . DIRECTORY_SEPARATOR . 'var' . DIRECTORY_SEPARATOR . 'secure-vault';
$secretFile = $privateDir . DIRECTORY_SEPARATOR . 'secrets.php';
if (getenv('JWT_SECRET') && getenv('MFA_ENCRYPTION_KEY')) {
    fwrite(STDOUT, "Environment-managed secrets detected; no local secrets file created.\n");
    exit(0);
}
if (is_file($secretFile)) {
    fwrite(STDOUT, "Local secrets already exist at {$secretFile}; leaving them unchanged.\n");
    exit(0);
}
if (!is_dir($privateDir) && !mkdir($privateDir, 0700, true) && !is_dir($privateDir)) {
    fwrite(STDERR, "Cannot create private runtime directory.\n");
    exit(1);
}
@chmod($privateDir, 0700);
$secrets = [
    'JWT_SECRET' => bin2hex(random_bytes(32)),
    'MFA_ENCRYPTION_KEY' => base64_encode(random_bytes(32)),
];
$contents = "<?php\n// Generated local development secrets. Keep outside source control and web root.\nreturn " . var_export($secrets, true) . ";\n";
if (file_put_contents($secretFile, $contents, LOCK_EX) === false) {
    fwrite(STDERR, "Cannot write local secrets file.\n");
    exit(1);
}
@chmod($secretFile, 0600);
fwrite(STDOUT, "Created private local secrets at {$secretFile}. Do not copy this file into source control or a web root.\n");
