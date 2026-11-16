// Run with: node backend_php/tests/onboarding_integration.mjs
import { spawn, spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdtemp, mkdir, rm, writeFile, stat } from 'node:fs/promises';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const temp = await mkdtemp(join(tmpdir(), 'secure-vault-onboarding-'));
const dataDir = join(temp, 'data');
const storageDir = join(temp, 'storage');
await mkdir(dataDir); await mkdir(storageDir);
const assert = (condition, message) => { if (!condition) throw new Error(message); };
let phpServer;
let smtpServer;
let message = '';
let messageCount = 0;

async function freePort() {
  const socket = createServer();
  await new Promise((ok, fail) => socket.once('error', fail).listen(0, '127.0.0.1', ok));
  const port = socket.address().port;
  await new Promise(ok => socket.close(ok));
  return port;
}

try {
  smtpServer = createServer(socket => {
    socket.write('220 local test SMTP\r\n');
    let buffer = ''; let inData = false; let lines = [];
    socket.on('data', chunk => {
      buffer += chunk.toString('utf8');
      while (buffer.includes('\r\n')) {
        const end = buffer.indexOf('\r\n');
        const line = buffer.slice(0, end);
        buffer = buffer.slice(end + 2);
        if (inData) {
          if (line === '.') { message = lines.join('\n'); messageCount++; lines = []; inData = false; socket.write('250 accepted\r\n'); }
          else lines.push(line);
        } else if (line.startsWith('EHLO ')) socket.write('250-localhost\r\n250 OK\r\n');
        else if (line.startsWith('RCPT TO:<reject@example.test>')) socket.write('550 rejected\r\n');
        else if (line.startsWith('MAIL FROM:') || line.startsWith('RCPT TO:')) socket.write('250 OK\r\n');
        else if (line === 'DATA') { inData = true; socket.write('354 End with dot\r\n'); }
        else if (line === 'QUIT') { socket.write('221 Bye\r\n'); socket.end(); }
        else socket.write('500 Unknown command\r\n');
      }
    });
  });
  await new Promise((ok, fail) => smtpServer.once('error', fail).listen(0, '127.0.0.1', ok));
  const env = {
    ...process.env,
    JWT_SECRET: randomBytes(32).toString('hex'),
    MFA_ENCRYPTION_KEY: randomBytes(32).toString('base64'),
    SECURE_VAULT_DATA_DIR: dataDir,
    SECURE_VAULT_STORAGE_DIR: storageDir,
    SECURE_VAULT_SMTP_HOST: '127.0.0.1',
    SECURE_VAULT_SMTP_PORT: String(smtpServer.address().port),
    SECURE_VAULT_SMTP_ENCRYPTION: 'none',
    SECURE_VAULT_SMTP_FROM: 'vault@example.test',
  };
  const seed = `require $argv[1].'/backend_php/config.php'; require $argv[1].'/backend_php/db/Database.php'; require $argv[1].'/backend_php/utils/Jwt.php'; $db=Database::getInstance(); foreach (['admin','member'] as $name) { $id=Database::generateUuid(); $role=$name==='admin'?'admin':'user'; $db->addUser(['id'=>$id,'username'=>$name,'email'=>$name.'@example.test','password_hash'=>Database::hashPassword('OldPassword123!'),'role'=>$role,'is_active'=>true,'session_version'=>0,'storage_quota_bytes'=>1000000,'storage_used_bytes'=>0]); echo Jwt::sign(['id'=>$id,'username'=>$name,'email'=>$name.'@example.test','role'=>$role,'sv'=>0], JWT_SECRET, 3600), PHP_EOL; }`;
  const seeded = spawnSync('php', ['-r', seed, root], { env, encoding: 'utf8' });
  assert(seeded.status === 0, `Gagal menyiapkan database uji: ${seeded.stderr}`);
  const [adminToken, memberToken] = seeded.stdout.trim().split(/\r?\n/);
  assert(adminToken && memberToken, 'Token uji tidak tersedia.');

  const port = await freePort();
  const base = `http://127.0.0.1:${port}/api`;
  phpServer = spawn('php', ['-S', `127.0.0.1:${port}`, '-t', join(root, 'backend_php'), join(root, 'backend_php', 'index.php')], { env, stdio: 'ignore' });
  let ready = false;
  for (let i = 0; i < 50; i++) {
    try { if ((await fetch(`${base}/health`)).ok) { ready = true; break; } } catch { /* starting */ }
    await new Promise(ok => setTimeout(ok, 100));
  }
  assert(ready, 'Server API uji tidak siap.');
  async function api(path, body, token = null) {
    const response = await fetch(base + path, { method: 'POST', headers: {
      'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}),
    }, body: JSON.stringify(body) });
    return [response.status, await response.json()];
  }

  let [status] = await api('/auth/register', { username: 'public', email: 'public@example.test', password: 'Password123456!' });
  assert(status === 403, 'Pendaftaran publik harus ditolak.');
  [status] = await api('/admin/users', { username: 'newuser', email: 'new@example.test' }, memberToken);
  assert(status === 403, 'Pengguna biasa tidak boleh membuat akun.');
  [status] = await api('/admin/users', { username: 'newuser', email: 'new@example.test' });
  assert(status === 401, 'Pembuatan akun tanpa sesi harus ditolak.');
  [status] = await api('/admin/users', { username: 'noemail', email: 'reject@example.test' }, adminToken);
  assert(status === 503, 'Akun tidak boleh dibuat jika SMTP menolak penerima.');
  let created;
  [status, created] = await api('/admin/users', { username: 'newuser', email: 'new@example.test', role: 'admin' }, adminToken);
  assert(status === 201 && !created.temporaryPassword, 'Admin harus mengirim tautan tanpa membagikan kata sandi sementara.');
  assert(messageCount === 1 && message.includes('To: new@example.test') && message.includes('Aktivasi akun Secure Vault'),
    'Tautan aktivasi harus dikirim saat akun dibuat.');
  const originalLink = message.match(/#activate=([a-f0-9-]{36})\.([a-f0-9]{64})\.newuser/)?.slice(1);
  assert(originalLink, 'Email harus memuat tautan aktivasi sekali pakai.');
  let listed = await fetch(`${base}/admin/users`, { headers: { Authorization: `Bearer ${adminToken}` } });
  let pending = (await listed.json()).users.find(u => u.username === 'newuser');
  assert(pending?.onboarding_pending && !pending.email_verified_at, 'Admin harus melihat email yang belum diverifikasi.');
  assert(!(await (await fetch(`${base}/admin/users`, { headers: { Authorization: `Bearer ${adminToken}` } })).json()).users.some(u => u.username === 'noemail'),
    'Akun gagal kirim email tidak boleh tersimpan.');
  [status] = await api(`/admin/users/${pending.id}/resend-verification`, {}, memberToken);
  assert(status === 403, 'Pengguna biasa tidak boleh mengirim ulang tautan.');
  [status] = await api(`/admin/users/${pending.id}/resend-verification`, {}, adminToken);
  assert(status === 429, 'Pengiriman ulang harus dibatasi selama 1 menit.');
  const ageLink = `require $argv[1].'/backend_php/config.php'; require $argv[1].'/backend_php/db/Database.php'; Database::getInstance()->updateUser($argv[2], ['activation_sent_at'=>time()-61]);`;
  const aged = spawnSync('php', ['-r', ageLink, root, pending.id], { env, encoding: 'utf8' });
  assert(aged.status === 0, `Gagal menyiapkan uji kirim ulang: ${aged.stderr}`);
  [status] = await api(`/admin/users/${pending.id}/resend-verification`, {}, adminToken);
  assert(status === 200 && messageCount === 2, 'Admin gagal mengirim ulang tautan aktivasi.');
  const resentLink = message.match(/#activate=([a-f0-9-]{36})\.([a-f0-9]{64})\.newuser/)?.slice(1);
  assert(resentLink && resentLink[1] !== originalLink[1], 'Pengiriman ulang harus mengganti token.');
  [status] = await api('/auth/activate', { userId: originalLink[0], token: originalLink[1], newPassword: 'FreshPassword123!' });
  assert(status === 400, 'Tautan lama harus tidak berlaku setelah pengiriman ulang.');
  [status] = await api('/auth/activate', { userId: resentLink[0], token: resentLink[1], newPassword: 'short' });
  assert(status === 400, 'Kata sandi pendek harus ditolak.');
  [status] = await api('/auth/login', { username: 'newuser', password: 'FreshPassword123!' });
  assert(status === 401, 'Akun yang belum aktif tidak boleh login.');
  [status] = await api('/auth/activate', { userId: resentLink[0], token: resentLink[1], newPassword: 'FreshPassword123!' });
  assert(status === 200, 'Tautan valid gagal mengaktifkan akun.');
  [status] = await api('/auth/activate', { userId: resentLink[0], token: resentLink[1], newPassword: 'AnotherPassword123!' });
  assert(status === 400, 'Tautan aktivasi harus sekali pakai.');
  let login;
  [status, login] = await api('/auth/login', { username: 'newuser', password: 'FreshPassword123!' });
  assert(status === 200 && login.mfaRequired && login.mfaSetupRequired && !login.token,
    'Login sesudah aktivasi harus meminta setup OTP.');
  const listResponse = await fetch(`${base}/admin/users`, { headers: { Authorization: `Bearer ${adminToken}` } });
  const users = (await listResponse.json()).users;
  const newUser = users.find(u => u.username === 'newuser');
  assert(newUser?.role === 'user' && newUser.is_active && !newUser.onboarding_pending && newUser.email_verified_at,
    'Peran atau status pengguna baru tidak sesuai.');
  let lockedUser;
  [status, lockedUser] = await api('/admin/users', { username: 'locktest', email: 'lock@example.test' }, adminToken);
  assert(status === 201 && !lockedUser.temporaryPassword, 'Akun uji pending gagal dibuat.');
  const memberId = users.find(u => u.username === 'member')?.id;
  assert(memberId, 'Akun anggota uji tidak ditemukan.');
  const adminId = users.find(u => u.username === 'admin')?.id;
  const adminQuota = await fetch(`${base}/admin/users/${adminId}/quota`, { method: 'PATCH', headers: {
    'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}`,
  }, body: JSON.stringify({ storageQuotaBytes: 2000000 }) });
  assert(adminQuota.status === 403, 'Kuota akun admin tidak boleh diubah.');
  [status] = await api(`/admin/users/${adminId}/revoke`, {}, adminToken);
  assert(status === 403, 'Akun admin tidak boleh dinonaktifkan.');
  [status] = await api(`/admin/users/${adminId}/reactivate`, {}, adminToken);
  assert(status === 403, 'Status akun admin tidak boleh diubah.');
  [status] = await api(`/admin/users/${adminId}/resend-verification`, {}, adminToken);
  assert(status === 403, 'Aktivasi akun admin tidak boleh diubah.');
  for (const path of ['/audit', '/audit/verify']) {
    const denied = await fetch(base + path, { headers: { Authorization: `Bearer ${memberToken}` } });
    assert(denied.status === 403, `User tidak boleh membuka ${path}.`);
    const allowed = await fetch(base + path, { headers: { Authorization: `Bearer ${adminToken}` } });
    assert(allowed.status === 200, `Admin harus dapat membuka ${path}.`);
  }
  async function deleteUser(id, confirmUsername, token = adminToken) {
    const response = await fetch(`${base}/admin/users/${id}`, { method: 'DELETE', headers: {
      'Content-Type': 'application/json', Authorization: `Bearer ${token}`,
    }, body: JSON.stringify({ confirmUsername }) });
    return response.status;
  }
  assert(await deleteUser(memberId, 'member', memberToken) === 403, 'Pengguna biasa tidak boleh menghapus akun.');
  assert(await deleteUser(adminId, 'admin') === 403, 'Admin tidak boleh menghapus akunnya sendiri.');
  assert(await deleteUser(memberId, 'member') === 409, 'Akun aktif tidak boleh langsung dihapus.');
  [status] = await api(`/admin/users/${memberId}/revoke`, {}, memberToken);
  assert(status === 403, 'Pengguna biasa tidak boleh menonaktifkan akun.');
  [status] = await api(`/admin/users/${memberId}/revoke`, {}, adminToken);
  assert(status === 200, 'Admin gagal menonaktifkan akun.');
  const oldSession = await fetch(`${base}/auth/me`, { headers: { Authorization: `Bearer ${memberToken}` } });
  assert(oldSession.status === 401, 'Sesi lama masih bisa beraktivitas setelah akun dinonaktifkan.');
  [status] = await api('/auth/login', { username: 'member', password: 'OldPassword123!' });
  assert(status === 403, 'Akun nonaktif masih bisa masuk.');
  listed = await fetch(`${base}/admin/users`, { headers: { Authorization: `Bearer ${adminToken}` } });
  let member = (await listed.json()).users.find(u => u.id === memberId);
  assert(member && !member.is_active, 'Akun nonaktif harus tetap tersimpan di daftar pengguna.');
  [status] = await api(`/admin/users/${memberId}/reactivate`, {}, memberToken);
  assert(status === 401, 'Sesi yang dicabut tidak boleh mengaktifkan akun.');
  [status] = await api(`/admin/users/${memberId}/reactivate`, {}, adminToken);
  assert(status === 200, 'Admin gagal mengaktifkan kembali akun.');
  listed = await fetch(`${base}/admin/users`, { headers: { Authorization: `Bearer ${adminToken}` } });
  member = (await listed.json()).users.find(u => u.id === memberId);
  assert(member?.is_active, 'Status akun tidak kembali aktif.');
  const revokedSession = await fetch(`${base}/auth/me`, { headers: { Authorization: `Bearer ${memberToken}` } });
  assert(revokedSession.status === 401, 'Sesi lama kembali aktif setelah akun dipulihkan.');
  [status, login] = await api('/auth/login', { username: 'member', password: 'OldPassword123!' });
  assert(status === 200 && login.mfaRequired, 'Akun yang dipulihkan harus bisa masuk melalui MFA.');
  const pendingId = (await (await fetch(`${base}/admin/users`, { headers: { Authorization: `Bearer ${adminToken}` } })).json()).users.find(u => u.username === 'locktest')?.id;
  [status] = await api(`/admin/users/${pendingId}/reactivate`, {}, adminToken);
  assert(status === 409, 'Admin tidak boleh melewati verifikasi akun baru.');
  [status] = await api(`/admin/users/${memberId}/revoke`, {}, adminToken);
  assert(status === 200, 'Akun uji tidak bisa dinonaktifkan untuk penghapusan.');
  const seedOwnedData = `require $argv[1].'/backend_php/config.php'; require $argv[1].'/backend_php/db/Database.php'; $db=Database::getInstance(); $userId=$argv[2]; $fileId=Database::generateUuid(); $folderId=Database::generateUuid(); $db->addFile(['id'=>$fileId,'owner_id'=>$userId,'kind'=>'file','upload_status'=>'completed','file_size_bytes'=>4,'total_chunks'=>1]); $db->saveChunk(['id'=>Database::generateUuid(),'file_id'=>$fileId,'chunk_index'=>0,'chunk_size_bytes'=>4,'storage_path'=>'chunk_0.bin']); $db->addFile(['id'=>$folderId,'owner_id'=>$userId,'kind'=>'folder','upload_status'=>'completed','file_size_bytes'=>0,'total_chunks'=>0]); $db->setVaultProfile(['user_id'=>$userId]); echo $fileId;`;
  const seededData = spawnSync('php', ['-r', seedOwnedData, root, memberId], { env, encoding: 'utf8' });
  assert(seededData.status === 0, `Gagal menyiapkan data brankas uji: ${seededData.stderr}`);
  const fileId = seededData.stdout.trim();
  const fileDir = join(storageDir, fileId);
  await mkdir(fileDir);
  await writeFile(join(fileDir, 'chunk_0.bin'), 'test');
  assert(await deleteUser(memberId, 'wrong') === 400, 'Konfirmasi username salah harus ditolak.');
  assert(await deleteUser(memberId, 'member') === 200, 'Admin gagal menghapus akun nonaktif.');
  const remaining = spawnSync('php', ['-r', `require $argv[1].'/backend_php/config.php'; require $argv[1].'/backend_php/db/Database.php'; $db=Database::getInstance(); $id=$argv[2]; $fileId=$argv[3]; echo json_encode(['user'=>$db->getUserById($id),'files'=>$db->getFilesByOwner($id,true),'folders'=>$db->getFoldersByOwner($id),'profile'=>$db->getVaultProfile($id),'chunks'=>$db->getChunksByFile($fileId)]);`, root, memberId, fileId], { env, encoding: 'utf8' });
  assert(remaining.status === 0, `Gagal memeriksa penghapusan data: ${remaining.stderr}`);
  const deletedData = JSON.parse(remaining.stdout);
  assert(deletedData.user === null && deletedData.files.length === 0 && deletedData.folders.length === 0
    && deletedData.profile === null && deletedData.chunks.length === 0, 'Data milik akun yang dihapus masih tersisa.');
  assert(!(await stat(fileDir).catch(() => null)), 'Ciphertext di storage masih tersisa.');
  const auditResponse = await fetch(`${base}/audit/verify`, { headers: { Authorization: `Bearer ${adminToken}` } });
  assert(auditResponse.ok && (await auditResponse.json()).isValid, 'Rantai audit rusak setelah akun dihapus.');
  console.log('OK: tautan aktivasi email, login OTP, penonaktifan, dan penghapusan akun.');
} finally {
  phpServer?.kill();
  if (smtpServer) await new Promise(ok => smtpServer.close(ok));
  if (temp.startsWith(join(tmpdir(), 'secure-vault-onboarding-'))) await rm(temp, { recursive: true, force: true });
}
