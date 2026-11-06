#!/usr/bin/env node
// Executes the same crypto-worker.js handler using Node worker_threads as a CI smoke test.
import assert from 'node:assert/strict';
import { Worker } from 'node:worker_threads';
import { webcrypto } from 'node:crypto';

globalThis.crypto ??= webcrypto;

const worker = new Worker(new URL('./crypto_worker_node_adapter.mjs', import.meta.url), { type: 'module' });
let nextId = 1;
const pending = new Map();
worker.on('message', (message) => {
  const request = pending.get(message.id);
  if (!request) return;
  pending.delete(message.id);
  if (message.error) request.reject(new Error(message.error));
  else request.resolve(message.result);
});
worker.on('error', (error) => {
  for (const request of pending.values()) request.reject(error);
  pending.clear();
});

function send(operation, payload, transfer = []) {
  const id = nextId++;
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
    worker.postMessage({ id, operation, payload }, transfer);
  });
}

try {
  const dek = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
  const original = new Uint8Array(1024 * 1024 + 37);
  for (let offset = 0; offset < original.byteLength; offset += 65536) {
    crypto.getRandomValues(original.subarray(offset, Math.min(offset + 65536, original.byteLength)));
  }
  const expected = Buffer.from(original).toString('hex');
  const plainBuffer = original.buffer;
  const encrypted = await send('encrypt', { buffer: plainBuffer, dek, fileId: 'node-worker-test', chunkIndex: 0 }, [plainBuffer]);
  assert.equal(plainBuffer.byteLength, 0, 'plaintext ArrayBuffer must be transferred/detached from caller');

  const badCipher = new Uint8Array(encrypted.ciphertextBuffer.slice(0));
  badCipher[0] ^= 1;
  const cipher = new Uint8Array(encrypted.ciphertextBuffer);
  const cipherBuffer = cipher.buffer;
  const decrypted = await send('decrypt', { buffer: cipherBuffer, ivB64: encrypted.ivB64, dek, fileId: 'node-worker-test', chunkIndex: 0 }, [cipherBuffer]);
  assert.equal(Buffer.from(new Uint8Array(decrypted.plaintextBuffer)).toString('hex'), expected);

  await assert.rejects(
    send('decrypt', { buffer: badCipher.buffer, ivB64: encrypted.ivB64, dek, fileId: 'node-worker-test', chunkIndex: 0 }, [badCipher.buffer]),
    /Integritas chunk gagal|decrypt|operation/i
  );

  console.log('CRYPTO WORKER NODE SMOKE TEST: PASS');
  console.log('- AES-GCM round-trip of 1 MiB + 37 byte chunk passed.');
  console.log('- CryptoKey crossed worker boundary via structured clone.');
  console.log('- Plaintext buffer was transferred/detached from caller.');
  console.log('- Modified ciphertext was rejected by AES-GCM authentication.');
} finally {
  await worker.terminate();
}
