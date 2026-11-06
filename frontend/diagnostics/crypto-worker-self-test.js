import { generateFileDek } from '../js/crypto.js?v=9';
import { encryptChunkOffThread, decryptChunkOffThread, isCryptoWorkerAvailable } from '../js/crypto-worker-client.js?v=9';

const button = document.querySelector('#run-test');
const output = document.querySelector('#result');
const hex = (bytes) => [...bytes].map((value) => value.toString(16).padStart(2, '0')).join('');

button.addEventListener('click', async () => {
  button.disabled = true;
  const lines = [];
  try {
    lines.push(`Build: ${window.__SECURE_VAULT_BUILD__ || 'diagnostics'}`);
    lines.push(`Web Worker API: ${isCryptoWorkerAvailable() ? 'tersedia' : 'tidak tersedia (fallback main thread)'}`);
    lines.push(`File System Access API: ${typeof window.showSaveFilePicker === 'function' ? 'tersedia' : 'tidak tersedia (fallback Blob)'}`);

    const key = await generateFileDek();
    const original = crypto.getRandomValues(new Uint8Array(1024 * 1024 + 37));
    const expected = hex(original);
    const encrypted = await encryptChunkOffThread(original.buffer, key, 'diagnostic-file-id', 0);
    const decrypted = await decryptChunkOffThread(encrypted.ciphertext, encrypted.ivB64, key, 'diagnostic-file-id', 0);
    if (hex(decrypted) !== expected) throw new Error('Round-trip AES-GCM tidak menghasilkan plaintext yang identik.');
    lines.push('AES-GCM worker round-trip 1 MiB + 37 byte: PASS');

    const tampered = encrypted.ciphertext.slice();
    tampered[0] ^= 0x01;
    let rejected = false;
    try {
      await decryptChunkOffThread(tampered, encrypted.ivB64, key, 'diagnostic-file-id', 0);
    } catch {
      rejected = true;
    }
    if (!rejected) throw new Error('Ciphertext yang dimodifikasi tidak ditolak.');
    lines.push('AES-GCM tamper detection: PASS');
    lines.push('Catatan: jalankan halaman ini lewat localhost/HTTPS agar browser mengaktifkan module Worker.');
    output.textContent = lines.join('\n');
  } catch (error) {
    lines.push(`FAIL: ${error?.message || String(error)}`);
    output.textContent = lines.join('\n');
  } finally {
    button.disabled = false;
  }
});

if (new URLSearchParams(location.search).get('autorun') === '1') {
  button.click();
}
