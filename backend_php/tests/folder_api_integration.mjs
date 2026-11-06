// Run with: node backend_php/tests/folder_api_integration.mjs
import { spawn, spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdtemp, mkdir, rm } from 'node:fs/promises';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const temp = await mkdtemp(join(tmpdir(), 'secure-vault-folders-'));
const dataDir = join(temp, 'data');
const storageDir = join(temp, 'storage');
await mkdir(dataDir); await mkdir(storageDir);
const env = {
  ...process.env,
  JWT_SECRET: randomBytes(32).toString('hex'),
  MFA_ENCRYPTION_KEY: randomBytes(32).toString('base64'),
  SECURE_VAULT_DATA_DIR: dataDir,
  SECURE_VAULT_STORAGE_DIR: storageDir,
};
let server;
const assert = (condition, message) => { if (!condition) throw new Error(message); };
const encrypted = () => `${randomBytes(32).toString('base64')}:${randomBytes(12).toString('base64')}`;

async function freePort() {
  const socket = createServer();
  await new Promise((ok, fail) => socket.once('error', fail).listen(0, '127.0.0.1', ok));
  const port = socket.address().port;
  await new Promise(ok => socket.close(ok));
  return port;
}

try {
  const seed = `require $argv[1].'/backend_php/config.php'; require $argv[1].'/backend_php/db/Database.php'; require $argv[1].'/backend_php/utils/Jwt.php'; $db=Database::getInstance(); foreach (['owner','other'] as $name) { $id=Database::generateUuid(); $db->addUser(['id'=>$id,'username'=>$name,'email'=>$name.'@example.test','role'=>'user','is_active'=>1,'session_version'=>0,'storage_quota_bytes'=>1000000,'storage_used_bytes'=>0]); echo Jwt::sign(['id'=>$id,'username'=>$name,'email'=>$name.'@example.test','role'=>'user','sv'=>0], JWT_SECRET, 3600), PHP_EOL; }`;
  const created = spawnSync('php', ['-r', seed, root], { env, encoding:'utf8' });
  assert(created.status === 0, `Gagal menyiapkan akun uji: ${created.stderr}`);
  const [ownerToken, otherToken] = created.stdout.trim().split(/\r?\n/);
  assert(ownerToken && otherToken, 'Token akun uji tidak tersedia.');

  const port = await freePort();
  const base = `http://127.0.0.1:${port}/api`;
  server = spawn('php', ['-S', `127.0.0.1:${port}`, '-t', join(root, 'backend_php'), join(root, 'backend_php', 'index.php')], { env, stdio:'ignore' });
  let ready = false;
  for (let attempt = 0; attempt < 50; attempt++) {
    try { const response = await fetch(`${base}/health`); if (response.ok) { ready = true; break; } } catch { /* server starting */ }
    await new Promise(ok => setTimeout(ok, 100));
  }
  assert(ready, 'Server uji tidak siap.');
  async function api(method, path, token, body) {
    const response = await fetch(base + path, { method, headers: {
      ...(token ? { Authorization:`Bearer ${token}` } : {}),
      ...(body ? { 'Content-Type':'application/json' } : {}),
    }, ...(body ? { body:JSON.stringify(body) } : {}) });
    return [response.status, await response.json()];
  }
  const folderBody = parentFolderId => ({ encryptedFolderName:encrypted(), wrappedDek:randomBytes(40).toString('base64'), parentFolderId });
  let [code, result] = await api('POST', '/folders', null, folderBody(null));
  assert(code === 401, 'Folder tanpa autentikasi harus ditolak.');
  [code, result] = await api('POST', '/folders', ownerToken, folderBody(null));
  assert(code === 201 && result.folderId, `Folder root gagal dibuat: ${code} ${JSON.stringify(result)}`);
  const rootId = result.folderId;
  [code, result] = await api('GET', '/folders', otherToken);
  assert(code === 200 && result.folders.length === 0, 'Folder pemilik bocor ke akun lain.');
  [code, result] = await api('POST', '/folders', otherToken, folderBody(rootId));
  assert(code === 404, 'Akun lain dapat membuat subfolder di folder pemilik.');
  [code, result] = await api('POST', '/folders', ownerToken, folderBody(rootId));
  assert(code === 201 && result.folderId, 'Subfolder gagal dibuat.');
  const childId = result.folderId;
  [code, result] = await api('POST', '/files/init', ownerToken, {
    encryptedFileName:encrypted(), encryptedTags:encrypted(), wrappedDek:randomBytes(40).toString('base64'),
    fileSizeBytes:1, totalChunks:1, parentFolderId:childId,
  });
  assert(code === 201 && result.fileId, `Berkas dalam folder gagal diinisialisasi: ${code} ${JSON.stringify(result)}`);
  const fileId = result.fileId;
  const chunk = new FormData();
  chunk.append('ivBase64', randomBytes(12).toString('base64'));
  chunk.append('aadString', `${fileId}-0`);
  chunk.append('chunkBlob', new Blob([randomBytes(17)]), 'chunk.bin');
  const chunkResponse = await fetch(`${base}/files/${fileId}/chunk/0`, {
    method:'POST', headers:{ Authorization:`Bearer ${ownerToken}` }, body:chunk,
  });
  assert(chunkResponse.status === 201, `Chunk berkas dalam folder gagal diunggah: ${chunkResponse.status}`);
  [code] = await api('POST', `/files/${fileId}/complete`, ownerToken);
  assert(code === 200, 'Berkas dalam folder gagal diselesaikan.');
  [code, result] = await api('GET', '/files', ownerToken);
  assert(code === 200 && result.files.length === 1 && result.files[0].parent_folder_id === childId, 'Daftar berkas tidak memuat tujuan folder yang benar.');
  [code, result] = await api('GET', '/folders', ownerToken);
  assert(code === 200 && result.folders.length === 2 && result.folders.some(folder => folder.id === childId && folder.parent_folder_id === rootId), 'Struktur folder tidak tersimpan.');
  [code] = await api('POST', '/folders', ownerToken, folderBody(fileId));
  assert(code === 404, 'Berkas biasa diterima sebagai folder induk.');
  [code] = await api('DELETE', `/files/${rootId}`, ownerToken);
  assert(code === 400, 'Endpoint berkas dapat menghapus folder.');
  [code] = await api('POST', '/files/init', otherToken, {
    encryptedFileName:encrypted(), encryptedTags:encrypted(), wrappedDek:randomBytes(40).toString('base64'),
    fileSizeBytes:1, totalChunks:1, parentFolderId:childId,
  });
  assert(code === 404, 'Akun lain dapat mengunggah ke folder pemilik.');
  [code] = await api('DELETE', `/folders/${rootId}`, ownerToken);
  assert(code === 409, 'Folder dengan subfolder dapat dihapus.');
  [code] = await api('DELETE', `/folders/${childId}`, ownerToken);
  assert(code === 409, 'Folder dengan berkas dapat dihapus.');
  [code] = await api('DELETE', `/folders/${childId}`, otherToken);
  assert(code === 404, 'Akun lain dapat menghapus folder pemilik.');
  [code] = await api('DELETE', `/files/${fileId}`, ownerToken);
  assert(code === 200, 'Berkas dalam folder gagal dihapus.');
  [code] = await api('DELETE', `/folders/${childId}`, ownerToken);
  assert(code === 200, 'Subfolder kosong gagal dihapus.');
  [code] = await api('DELETE', `/folders/${rootId}`, ownerToken);
  assert(code === 200, 'Folder root kosong gagal dihapus.');
  [code, result] = await api('GET', '/audit/verify', ownerToken);
  assert(code === 200 && result.isValid === true, 'Rantai audit rusak setelah operasi folder.');
  console.log('PASS: create/list/nest/upload/delete folder, isolasi pemilik, dan audit.');
} finally {
  if (server) { server.kill(); await new Promise(ok => server.once('exit', ok)); }
  await rm(temp, { recursive:true, force:true });
}
