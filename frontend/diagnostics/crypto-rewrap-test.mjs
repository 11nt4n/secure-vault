#!/usr/bin/env node
/**
 * Regression test for Secure Vault's passphrase re-wrap key lifecycle.
 * Run from the project root with:
 *   node --experimental-default-type=module frontend/diagnostics/crypto-rewrap-test.mjs
 * This test exercises Web Crypto only; it does not require PHP or SQLite.
 */
import assert from 'node:assert/strict';


const {
  generateMasterKey,
  generateFileDek,
  wrapMasterKey,
  unwrapMasterKey,
  rewrapMasterKeyForPassphrase,
  wrapDek,
  unwrapDek,
  encryptChunk,
  decryptChunk,
  verifyPassphrase,
  computeSha256,
  computeSha256Blob,
} = await import('../js/crypto.js');

async function makeKek() {
  return crypto.subtle.importKey(
    'raw',
    crypto.getRandomValues(new Uint8Array(32)),
    { name: 'AES-KW' },
    false,
    ['wrapKey', 'unwrapKey']
  );
}

const oldKek = await makeKek();
const newKek = await makeKek();
const createdMasterKey = await generateMasterKey();
const originalWrapped = await wrapMasterKey(createdMasterKey, oldKek);
const activeMasterKey = await unwrapMasterKey(originalWrapped, oldKek);

assert.equal(activeMasterKey.extractable, false, 'normal unlocked Master Key must be non-extractable');

const rewrapped = await rewrapMasterKeyForPassphrase(originalWrapped, oldKek, newKek);
assert.equal(rewrapped.sessionMasterKey.extractable, false, 'post-re-wrap session Master Key must remain non-extractable');
assert.equal(await verifyPassphrase(
  rewrapped.sessionMasterKey,
  rewrapped.verifier.verifierCiphertext,
  rewrapped.verifier.verifierIv,
  rewrapped.verifier.verifierWrappedDek
), true, 'new verifier must validate against the re-wrapped Master Key');

await assert.rejects(
  () => unwrapMasterKey(rewrapped.wrappedMasterKeyB64, oldKek),
  'old KEK must no longer unwrap the updated Master Key'
);

const unwrappedWithNewKek = await unwrapMasterKey(rewrapped.wrappedMasterKeyB64, newKek);
assert.equal(unwrappedWithNewKek.extractable, false);

const dek = await generateFileDek();
const wrappedDek = await wrapDek(dek, rewrapped.sessionMasterKey);
const recoveredDek = await unwrapDek(wrappedDek, unwrappedWithNewKek);
const sample = new TextEncoder().encode('Secure Vault re-wrap regression payload');
const encrypted = await encryptChunk(sample, recoveredDek, 'test-file-id', 0);
const decrypted = await decryptChunk(encrypted.ciphertext, encrypted.ivB64, recoveredDek, 'test-file-id', 0);
assert.deepEqual(decrypted, sample, 'file DEK wrapping and AES-GCM chunk round-trip must still work');

for (const size of [0, 1, 3, 55, 56, 63, 64, 65, 127, 128, 129, 1024, 65537, 1024 * 1024]) {
  const bytes = Uint8Array.from({ length: size }, (_, index) => (index * 31 + size) & 0xff);
  const expected = await computeSha256(bytes);
  const actual = await computeSha256Blob(new Blob([bytes]), null, 37);
  assert.equal(actual, expected, `incremental SHA-256 mismatch at ${size} bytes`);
}

console.log('PASS: re-wrap works; long-lived Master Key remains non-extractable; old KEK is rejected; AES-GCM round-trip and incremental SHA-256 vectors pass.');
