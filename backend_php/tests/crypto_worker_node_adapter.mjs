// Node-only adapter for exercising the exact worker message handler in CI.
import { parentPort } from 'node:worker_threads';
import { webcrypto } from 'node:crypto';

globalThis.crypto ??= webcrypto;
globalThis.self = {
  addEventListener(type, handler) {
    if (type === 'message') parentPort.on('message', (data) => handler({ data }));
  },
  postMessage(message, transfer = []) {
    parentPort.postMessage(message, transfer);
  }
};

await import('../../frontend/js/crypto-worker.js?v=9');
