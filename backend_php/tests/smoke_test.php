<?php
// Smoke test for Secure Vault API. Usage: php smoke_test.php http://127.0.0.1:5055 <adminUser> <adminPass>
require_once __DIR__ . '/../utils/Totp.php';

$base = $argv[1] ?? 'http://127.0.0.1:5055';
$adminUser = $argv[2] ?? 'admin';
$adminPass = $argv[3] ?? 'Adm1nPassw0rd!';
$pass = 0; $fail = 0;

function req($method, $url, $body = null, $token = null, $multipart = null) {
    $ch = curl_init($url);
    $h = [];
    if ($token) $h[] = "Authorization: Bearer $token";
    if ($multipart !== null) {
        curl_setopt($ch, CURLOPT_POSTFIELDS, $multipart);
    } elseif ($body !== null) {
        $h[] = 'Content-Type: application/json';
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($body));
    }
    curl_setopt_array($ch, [CURLOPT_CUSTOMREQUEST => $method, CURLOPT_RETURNTRANSFER => true, CURLOPT_HTTPHEADER => $h]);
    $raw = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    $json = json_decode($raw, true);
    return [$code, $json ?? $raw];
}
function check($name, $cond, $extra = '') {
    global $pass, $fail;
    if ($cond) { $pass++; echo "  [PASS] $name\n"; } else { $fail++; echo "  [FAIL] $name $extra\n"; }
}
function totpNow($secret) {
    $r = new ReflectionClass('Totp');
    $dec = $r->getMethod('base32Decode'); $dec->setAccessible(true);
    $code = $r->getMethod('codeAt'); $code->setAccessible(true);
    return $code->invoke(null, $dec->invoke(null, $secret), intdiv(time(), 30));
}

[$c, $j] = req('GET', "$base/api/health");
check('health 200', $c === 200);
[$c, $j] = req('GET', "$base/api/config");
check('config demoMode=false', $c === 200 && $j['demoMode'] === false);

$u = 'tester' . random_int(1000, 9999);
[$c, $j] = req('POST', "$base/api/auth/register", ['username' => $u, 'password' => 'weak', 'email' => "$u@x.id"]);
check('weak password rejected', $c === 400);
[$c, $j] = req('POST', "$base/api/auth/register", ['username' => $u, 'password' => 'StrongPass123', 'email' => "$u@x.id", 'role' => 'admin']);
check('register forces role=user', $c === 201 && $j['user']['role'] === 'user', json_encode($j));

for ($i = 0; $i < 5; $i++) [$c, $j] = req('POST', "$base/api/auth/login", ['username' => $u, 'password' => 'wrong']);
[$c, $j] = req('POST', "$base/api/auth/login", ['username' => $u, 'password' => 'StrongPass123']);
check('lockout after 5 failures (429)', $c === 429, "$c");

[$c, $j] = req('POST', "$base/api/auth/login", ['username' => $adminUser, 'password' => $adminPass]);
check('admin login -> MFA setup required', $c === 200 && !empty($j['mfaSetupRequired']) && !empty($j['totpSecret']), json_encode($j));
$mfaToken = $j['mfaToken']; $secret = $j['totpSecret'];
[$c, $j] = req('POST', "$base/api/auth/mfa/verify", ['mfaToken' => $mfaToken, 'code' => '123456']);
check('demo code 123456 rejected', $c === 400 && isset($j['attemptsLeft']), json_encode($j));
[$c, $j] = req('POST', "$base/api/auth/mfa/verify", ['mfaToken' => $mfaToken, 'code' => totpNow($secret)]);
check('valid TOTP -> JWT', $c === 200 && !empty($j['token']) && $j['user']['mfaEnabled'] === true, json_encode($j));
$token = $j['token'];

[$c, $j] = req('GET', "$base/api/auth/me", null, $token);
check('/me works', $c === 200 && $j['user']['role'] === 'admin');

// Upload flow
$cipher = random_bytes(1000);
$sha = hash('sha256', 'x');
[$c, $j] = req('POST', "$base/api/files/init", ['encryptedFileName' => 'YWJj:ZGVm', 'encryptedTags' => 'YWJj:ZGVm', 'fileSizeBytes' => 984, 'totalChunks' => 1, 'wrappedDek' => base64_encode(random_bytes(40)), 'plaintextSha256' => $sha], $token);
check('file init', $c === 201, json_encode($j));
$fid = $j['fileId'];
[$c, $j] = req('POST', "$base/api/files/$fid/complete", null, $token);
check('complete rejected when chunks missing', $c === 409);
$tmp = tempnam(sys_get_temp_dir(), 'c'); file_put_contents($tmp, $cipher);
[$c, $j] = req('POST', "$base/api/files/$fid/chunk/0", null, $token, ['ivBase64' => base64_encode(random_bytes(12)), 'aadString' => "$fid-9", 'chunkBlob' => new CURLFile($tmp)]);
check('wrong AAD rejected', $c === 400);
[$c, $j] = req('POST', "$base/api/files/$fid/chunk/5", null, $token, ['ivBase64' => base64_encode(random_bytes(12)), 'aadString' => "$fid-5", 'chunkBlob' => new CURLFile($tmp)]);
check('out-of-range chunk rejected', $c === 400);
[$c, $j] = req('POST', "$base/api/files/$fid/chunk/0", null, $token, ['ivBase64' => base64_encode(random_bytes(12)), 'aadString' => "$fid-0", 'chunkBlob' => new CURLFile($tmp)]);
check('chunk upload', $c === 201, json_encode($j));
[$c, $j] = req('POST', "$base/api/files/$fid/complete", null, $token);
[$c2, $j2] = req('POST', "$base/api/files/$fid/complete", null, $token);
[$c3, $me] = req('GET', "$base/api/auth/me", null, $token);
check('complete idempotent (quota counted once)', $c === 200 && $c2 === 200 && $me['user']['storageUsedBytes'] === 984, json_encode($me));
[$c, $j] = req('GET', "$base/api/files/$fid/chunk/0/data", null, $token);
check('download chunk matches', $c === 200 && $j === $cipher);
[$c, $j] = req('DELETE', "$base/api/files/$fid", null, $token);
[$c3, $me] = req('GET', "$base/api/auth/me", null, $token);
check('delete frees quota', $c === 200 && $me['user']['storageUsedBytes'] === 0);

[$c, $j] = req('GET', "$base/api/audit/verify", null, $token);
check('audit chain valid', $c === 200 && $j['isValid'] === true, json_encode($j));

[$c, $j] = req('POST', "$base/api/auth/logout", null, $token);
[$c, $j] = req('GET', "$base/api/auth/me", null, $token);
check('token invalid after logout', $c === 401);

[$c, $j] = req('GET', "$base/api/nope");
check('unknown endpoint 404 generic', $c === 404);

echo "\nRESULT: $pass passed, $fail failed\n";
exit($fail ? 1 : 0);
