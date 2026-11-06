<?php
// Lightweight static-file server with the browser security headers previously
// supplied by the Vite development server.
header_remove('X-Powered-By');
header("Content-Security-Policy: default-src 'self'; base-uri 'self'; frame-ancestors 'none'; frame-src 'self' blob:; object-src 'none'; form-action 'self'; script-src 'self' 'wasm-unsafe-eval'; worker-src 'self'; style-src 'self' https://fonts.googleapis.com; style-src-attr 'none'; style-src-elem 'self' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com data:; img-src 'self' data: blob:; connect-src 'self' http://localhost:5000 http://127.0.0.1:5000");
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: no-referrer');
header('Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()');

$root = realpath(__DIR__);
$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
if ($path === '/') $path = '/index.html';
$requested = realpath(__DIR__ . $path);
if (!$root || !$requested || !str_starts_with($requested, $root . DIRECTORY_SEPARATOR) || !is_file($requested)) {
    http_response_code(404);
    header('Content-Type: text/plain; charset=utf-8');
    echo 'Not Found';
    return true;
}

$types = [
    'html' => 'text/html; charset=utf-8',
    'css' => 'text/css; charset=utf-8',
    'js' => 'application/javascript; charset=utf-8',
    'mjs' => 'application/javascript; charset=utf-8',
    'png' => 'image/png',
    'jpg' => 'image/jpeg',
    'jpeg' => 'image/jpeg',
    'svg' => 'image/svg+xml',
    'ico' => 'image/x-icon',
    'wasm' => 'application/wasm',
    'woff' => 'font/woff',
    'woff2' => 'font/woff2',
    'txt' => 'text/plain; charset=utf-8',
];
$extension = strtolower(pathinfo($requested, PATHINFO_EXTENSION));
if (!isset($types[$extension]) || basename($requested)[0] === '.') {
    http_response_code(404);
    header('Content-Type: text/plain; charset=utf-8');
    echo 'Not Found';
    return true;
}
header('Content-Type: ' . $types[$extension]);
header('Content-Length: ' . filesize($requested));
header('Cache-Control: no-cache');
readfile($requested);
return true;
