<?php
// Send a harmless test message to the configured sender address.
if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}
require_once __DIR__ . '/../config.php';
require_once __DIR__ . '/../utils/SmtpMailer.php';

try {
    $sender = SmtpMailer::configuredSender();
    if ($sender === '') throw new RuntimeException('Alamat pengirim SMTP belum dikonfigurasi.');
    SmtpMailer::sendVerificationCode($sender, '00000000', '', true);
    fwrite(STDOUT, "Email tes berhasil dikirim ke {$sender}.\n");
} catch (Throwable $e) {
    fwrite(STDERR, 'Tes SMTP gagal: ' . $e->getMessage() . "\n");
    exit(1);
}
