<?php
// SMTP transport for account email verification. Credentials come from the server environment.
class SmtpMailer
{
    private static function setting(string $name, string $default = ''): string
    {
        // Treat environment settings as one complete transport configuration.
        // Mixing a test/alternate host with credentials from smtp.json can leak
        // Gmail credentials to the wrong SMTP server.
        $environmentHost = getenv('SECURE_VAULT_SMTP_HOST');
        if ($environmentHost !== false && $environmentHost !== '') {
            $environment = getenv('SECURE_VAULT_SMTP_' . $name);
            return $environment === false ? $default : (string)$environment;
        }
        $path = PRIVATE_DIR . DIRECTORY_SEPARATOR . 'smtp.json';
        if (!is_file($path)) return $default;
        $settings = json_decode((string)file_get_contents($path), true);
        return is_array($settings) && is_string($settings[$name] ?? null) ? $settings[$name] : $default;
    }

    public static function configuredSender(): string
    {
        return trim(self::setting('FROM'));
    }

    private static function read($stream): string
    {
        $message = '';
        do {
            $line = fgets($stream, 2048);
            if ($line === false) throw new RuntimeException('SMTP connection closed unexpectedly.');
            $message .= $line;
        } while (isset($line[3]) && $line[3] === '-');
        return $message;
    }

    private static function expect($stream, array $codes): void
    {
        $reply = self::read($stream);
        $code = (int)substr($reply, 0, 3);
        if (!in_array($code, $codes, true)) {
            if ($code === 534 || $code === 535) throw new RuntimeException('Gmail menolak login SMTP. Periksa alamat Gmail dan App Password 16 karakter.');
            if ($code === 550 || $code === 553) throw new RuntimeException('Server SMTP menolak alamat pengirim atau penerima.');
            if ($code === 530) throw new RuntimeException('Server SMTP meminta autentikasi. Periksa konfigurasi Gmail.');
            throw new RuntimeException("Server SMTP menolak pengiriman (kode {$code}).");
        }
    }

    private static function command($stream, string $line, array $codes): void
    {
        if (fwrite($stream, $line . "\r\n") === false) throw new RuntimeException('SMTP write failed.');
        self::expect($stream, $codes);
    }

    public static function sendVerificationCode(string $to, string $code, string $username = '', bool $test = false): void
    {
        $accountInfo = $username !== '' ? "Akun Secure Vault untuk username {$username} telah dibuat.\r\nMasuk dengan kata sandi sementara yang diberikan administrator, lalu masukkan kode berikut.\r\n\r\n" : '';
        $body = $test ? 'Tes pengiriman email Secure Vault berhasil. Konfigurasi SMTP siap digunakan.'
            : $accountInfo . "Kode verifikasi Secure Vault Anda: {$code}\r\n\r\nKode ini berlaku 10 menit dan hanya untuk aktivasi akun. Jangan berikan kepada siapa pun.\r\nJika Anda tidak mengenali permintaan ini, hubungi administrator.";
        self::sendMail($to, $test ? 'Tes SMTP Secure Vault' : 'Kode verifikasi akun Secure Vault', $body);
    }

    public static function sendActivationLink(string $to, string $link, string $username): void
    {
        if (!filter_var($link, FILTER_VALIDATE_URL) || preg_match('/[\r\n]/', $link . $username)) {
            throw new RuntimeException('Tautan aktivasi tidak valid.');
        }
        $body = "Akun Secure Vault untuk username {$username} telah dibuat.\r\n\r\n"
            . "Buka tautan berikut untuk memverifikasi email dan membuat kata sandi Anda sendiri:\r\n{$link}\r\n\r\n"
            . "Tautan berlaku 24 jam dan hanya dapat dipakai sekali. Setelah aktivasi, masuk dengan kata sandi baru lalu siapkan OTP authenticator.\r\n"
            . "Jika Anda tidak mengenali permintaan ini, abaikan email ini dan hubungi administrator.";
        self::sendMail($to, 'Aktivasi akun Secure Vault', $body);
    }

    private static function sendMail(string $to, string $subject, string $body): void
    {
        $host = trim(self::setting('HOST'));
        $from = trim(self::setting('FROM'));
        $user = self::setting('USER');
        $password = self::setting('PASSWORD');
        $encryption = strtolower(self::setting('ENCRYPTION', 'tls'));
        $port = (int)self::setting('PORT', $encryption === 'ssl' ? '465' : '587');
        if ($host === '' || $from === '') {
            throw new RuntimeException('SMTP belum diatur. Jalankan configure_gmail_smtp.ps1 dari folder proyek.');
        }
        if ($host === '' || !filter_var($from, FILTER_VALIDATE_EMAIL) || !filter_var($to, FILTER_VALIDATE_EMAIL)
            || preg_match('/[\r\n]/', $host . $from . $to . $user) || $port < 1 || $port > 65535
            || !in_array($encryption, ['tls', 'ssl', 'none'], true)) {
            throw new RuntimeException('SMTP belum dikonfigurasi dengan benar.');
        }
        if ($encryption === 'none' && !in_array(strtolower($host), ['localhost', '127.0.0.1', '::1'], true)) {
            throw new RuntimeException('SMTP tanpa TLS hanya diizinkan pada komputer lokal.');
        }
        if (($user === '') !== ($password === '')) throw new RuntimeException('Kredensial SMTP tidak lengkap.');

        $context = stream_context_create(['ssl' => [
            'verify_peer' => true, 'verify_peer_name' => true, 'allow_self_signed' => false,
            'peer_name' => $host,
        ]]);
        $target = ($encryption === 'ssl' ? 'ssl://' : 'tcp://') . $host . ':' . $port;
        $stream = @stream_socket_client($target, $errno, $errstr, 10, STREAM_CLIENT_CONNECT, $context);
        if ($stream === false) throw new RuntimeException('Tidak dapat terhubung ke server SMTP. Periksa internet, host, port, dan firewall.');
        stream_set_timeout($stream, 10);
        try {
            self::expect($stream, [220]);
            self::command($stream, 'EHLO secure-vault.local', [250]);
            if ($encryption === 'tls') {
                self::command($stream, 'STARTTLS', [220]);
                if (!stream_socket_enable_crypto($stream, true, STREAM_CRYPTO_METHOD_TLS_CLIENT)) {
                    throw new RuntimeException('Koneksi TLS SMTP gagal.');
                }
                self::command($stream, 'EHLO secure-vault.local', [250]);
            }
            if ($user !== '') {
                self::command($stream, 'AUTH LOGIN', [334]);
                self::command($stream, base64_encode($user), [334]);
                self::command($stream, base64_encode($password), [235]);
            }
            self::command($stream, 'MAIL FROM:<' . $from . '>', [250]);
            self::command($stream, 'RCPT TO:<' . $to . '>', [250, 251]);
            self::command($stream, 'DATA', [354]);
            $message = "From: {$from}\r\nTo: {$to}\r\nSubject: {$subject}\r\nDate: " . gmdate('D, d M Y H:i:s') . " +0000\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n" . $body;
            $message = preg_replace('/^\./m', '..', $message);
            if (fwrite($stream, str_replace("\n", "\r\n", str_replace("\r\n", "\n", $message)) . "\r\n.\r\n") === false) {
                throw new RuntimeException('SMTP write failed.');
            }
            self::expect($stream, [250]);
            self::command($stream, 'QUIT', [221]);
        } finally {
            fclose($stream);
        }
    }
}
