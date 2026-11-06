// Thin request/response client for the per-chunk Web Crypto worker.
import { encryptChunk, decryptChunk } from './crypto.js?v=9';

let worker = null;
let nextRequestId = 1;
const pending = new Map();

function settleAll(error) {
  for (const entry of pending.values()) entry.reject(error);
  pending.clear();
}

function getWorker() {
  if (worker) return worker;
  if (typeof Worker !== 'function') return null;
  try {
    worker = new Worker(new URL('./crypto-worker.js?v=9', import.meta.url), {
      type: 'module',
      name: 'secure-vault-chunk-crypto'
    });
    worker.addEventListener('message', (event) => {
      const message = event.data || {};
      const entry = pending.get(message.id);
      if (!entry) return;
      pending.delete(message.id);
      if (message.error) entry.reject(new Error(message.error));
      else entry.resolve(message.result);
    });
    worker.addEventListener('error', (event) => {
      const error = new Error(`Crypto Worker gagal: ${event.message || 'kesalahan worker tidak diketahui'}`);
      worker?.terminate();
      worker = null;
      settleAll(error);
    });
    return worker;
  } catch {
    worker = null;
    return null;
  }
}

function asTransferableBuffer(value) {
  if (value instanceof ArrayBuffer) return value;
  if (ArrayBuffer.isView(value)) {
    if (value.byteOffset === 0 && value.byteLength === value.buffer.byteLength) return value.buffer;
    return value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength);
  }
  throw new TypeError('Data chunk harus berupa ArrayBuffer atau typed array.');
}

function send(operation, payload, transfer) {
  const activeWorker = getWorker();
  if (!activeWorker) return null;
  const id = nextRequestId++;
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
    try {
      activeWorker.postMessage({ id, operation, payload }, transfer);
    } catch (error) {
      pending.delete(id);
      reject(error);
    }
  });
}

export async function encryptChunkOffThread(data, dek, fileId, chunkIndex) {
  const buffer = asTransferableBuffer(data);
  const resultPromise = send('encrypt', { buffer, dek, fileId, chunkIndex }, [buffer]);
  if (resultPromise) {
    const result = await resultPromise;
    return { ciphertext: new Uint8Array(result.ciphertextBuffer), ivB64: result.ivB64, aad: result.aad };
  }

  const plaintext = new Uint8Array(buffer);
  try {
    return await encryptChunk(plaintext, dek, fileId, chunkIndex);
  } finally {
    plaintext.fill(0);
  }
}

export async function decryptChunkOffThread(data, ivB64, dek, fileId, chunkIndex) {
  const buffer = asTransferableBuffer(data);
  const resultPromise = send('decrypt', { buffer, ivB64, dek, fileId, chunkIndex }, [buffer]);
  if (resultPromise) {
    const result = await resultPromise;
    return new Uint8Array(result.plaintextBuffer);
  }

  const ciphertext = new Uint8Array(buffer);
  try {
    return await decryptChunk(ciphertext, ivB64, dek, fileId, chunkIndex);
  } finally {
    ciphertext.fill(0);
  }
}

export function terminateCryptoWorker(reason = 'Brankas dikunci; worker kriptografi dihentikan.') {
  if (worker) {
    worker.terminate();
    worker = null;
  }
  settleAll(new Error(reason));
}

export function isCryptoWorkerAvailable() {
  return typeof Worker === 'function';
}
