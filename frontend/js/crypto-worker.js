// Secure Vault V9: per-chunk AES-GCM work runs off the UI thread.
// Argon2id remains on the established main-thread path for browser compatibility.
import { encryptChunk, decryptChunk } from './crypto.js?v=9';

self.addEventListener('message', async (event) => {
  const message = event.data || {};
  const { id, operation, payload } = message;
  if (!Number.isSafeInteger(id)) return;
  if (!payload || !(payload.buffer instanceof ArrayBuffer)) {
    self.postMessage({ id, error: 'Payload crypto worker tidak valid.' });
    return;
  }

  try {
    if (operation === 'encrypt') {
      const plaintext = new Uint8Array(payload.buffer);
      try {
        const result = await encryptChunk(plaintext, payload.dek, payload.fileId, payload.chunkIndex);
        const ciphertextBuffer = result.ciphertext.buffer;
        self.postMessage({ id, result: { ciphertextBuffer, ivB64: result.ivB64, aad: result.aad } }, [ciphertextBuffer]);
      } finally {
        plaintext.fill(0);
      }
      return;
    }

    if (operation === 'decrypt') {
      const ciphertext = new Uint8Array(payload.buffer);
      try {
        const plaintext = await decryptChunk(ciphertext, payload.ivB64, payload.dek, payload.fileId, payload.chunkIndex);
        const plaintextBuffer = plaintext.buffer;
        self.postMessage({ id, result: { plaintextBuffer } }, [plaintextBuffer]);
      } finally {
        ciphertext.fill(0);
      }
      return;
    }

    throw new Error('Operasi crypto worker tidak dikenal.');
  } catch (error) {
    self.postMessage({ id, error: error?.message || 'Operasi kriptografi di worker gagal.' });
  }
});
