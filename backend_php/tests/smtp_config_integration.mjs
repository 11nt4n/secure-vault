// Run with: node backend_php/tests/smtp_config_integration.mjs
import { spawn } from 'node:child_process';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const temp = await mkdtemp(join(tmpdir(), 'secure-vault-smtp-'));
let server;
let delivered = '';
try {
  server = createServer(socket => {
    socket.write('220 local SMTP test\r\n');
    let buffer = ''; let data = false;
    socket.on('data', bytes => {
      buffer += bytes.toString('utf8');
      while (buffer.includes('\r\n')) {
        const end = buffer.indexOf('\r\n');
        const line = buffer.slice(0, end);
        buffer = buffer.slice(end + 2);
        if (data) {
          if (line === '.') { data = false; socket.write('250 accepted\r\n'); }
          else delivered += line + '\n';
        } else if (line.startsWith('EHLO ')) socket.write('250 local\r\n');
        else if (line.startsWith('MAIL FROM:') || line.startsWith('RCPT TO:')) socket.write('250 accepted\r\n');
        else if (line === 'DATA') { data = true; socket.write('354 send data\r\n'); }
        else if (line === 'QUIT') { socket.write('221 bye\r\n'); socket.end(); }
      }
    });
  });
  await new Promise((ok, fail) => server.once('error', fail).listen(0, '127.0.0.1', ok));
  await writeFile(join(temp, 'smtp.json'), JSON.stringify({
    HOST: '127.0.0.1', PORT: String(server.address().port), ENCRYPTION: 'none',
    FROM: 'vault@example.test', USER: '', PASSWORD: '',
  }));
  const env = { ...process.env };
  for (const key of Object.keys(env)) if (key.startsWith('SECURE_VAULT_SMTP_')) delete env[key];
  const script = `define('PRIVATE_DIR',$argv[1]); require $argv[2].'/backend_php/utils/SmtpMailer.php'; SmtpMailer::sendVerificationCode('member@example.test','12345678','member'); echo SmtpMailer::configuredSender();`;
  const result = await new Promise((ok, fail) => {
    const child = spawn('php', ['-r', script, temp, root], { env });
    let stdout = ''; let stderr = '';
    child.stdout.on('data', chunk => { stdout += chunk; });
    child.stderr.on('data', chunk => { stderr += chunk; });
    child.once('error', fail);
    child.once('close', code => ok({ code, stdout, stderr }));
  });
  if (result.code !== 0 || result.stdout !== 'vault@example.test'
    || !delivered.includes('Kode verifikasi Secure Vault Anda: 12345678')) {
    throw new Error(`Konfigurasi SMTP privat gagal dipakai: ${result.stderr}`);
  }
  console.log('OK: konfigurasi SMTP privat mengirim kode melalui server SMTP lokal.');
} finally {
  if (server) await new Promise(ok => server.close(ok));
  if (temp.startsWith(join(tmpdir(), 'secure-vault-smtp-'))) await rm(temp, { recursive: true, force: true });
}
