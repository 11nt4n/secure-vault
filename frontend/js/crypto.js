// Zero-Knowledge 3-Layer Envelope Encryption:
// Passphrase -> KEK (Argon2id WASM) -> Master Key (AES-KW) -> File DEK (AES-KW) -> AES-256-GCM chunks with AAD.
const ramState = { kek: null, masterKey: null };
export const VERIFIER_PLAINTEXT = 'SECURE_VAULT_PASS_VERIFIER_V1';
export function clearVaultKeys() { ramState.kek = null; ramState.masterKey = null; }
export function getLoadedMasterKey() { return ramState.masterKey; }
export function getLoadedKek() { return ramState.kek; }
export function setLoadedKeys(kek, masterKey) { ramState.kek = kek; ramState.masterKey = masterKey; }
export function isVaultKeyLoaded() { return ramState.masterKey !== null; }
export function generateSalt(length = 16) { return crypto.getRandomValues(new Uint8Array(length)); }
export function uint8ArrayToB64(arr) { let binary = ''; for (let i = 0; i < arr.byteLength; i++) binary += String.fromCharCode(arr[i]); return btoa(binary); }
export function b64ToUint8Array(b64) { const binary = atob(b64); const bytes = new Uint8Array(binary.length); for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i); return bytes; }
export async function deriveKek(passphrase, salt, onProgress = null) {
  // Source comparison: this keeps the original React implementation's exact
  // Argon2-browser invocation and parameter values. No Worker or KDF downgrade.
  const globalArgon2 = typeof window !== 'undefined' ? window.argon2 : null;
  if (!globalArgon2 || typeof globalArgon2.hash !== 'function') {
    throw new Error('Runtime Argon2id tidak ditemukan. Periksa build frontend dan pemuatan argon2-bundled.min.js.');
  }
  if (!crypto?.subtle) {
    throw new Error('Web Crypto tidak tersedia. Jalankan aplikasi melalui localhost atau HTTPS, bukan file://.');
  }
  if (!(salt instanceof Uint8Array) || salt.byteLength !== 16) {
    throw new Error('Salt Argon2id tidak valid. Salt harus berupa Uint8Array 16-byte.');
  }

  const report = (message) => { try { onProgress?.(message); } catch { /* progress UI must not break cryptography */ } };
  report('Runtime Argon2id ditemukan. Memuat mesin WASM dan menurunkan kunci 256-bit...');

  let keyBytes;
  let watchdog;
  try {
    const hashPromise = globalArgon2.hash({
      pass: passphrase,
      salt: salt,
      time: 3,
      mem: 65536,
      hashLen: 32,
      parallelism: 1,
      type: globalArgon2.ArgonType ? globalArgon2.ArgonType.Argon2id : 2,
    });
    const timeoutPromise = new Promise((_, reject) => {
      watchdog = setTimeout(() => reject(new Error(
        'Argon2id tidak memberikan respons dalam 30 detik. Periksa apakah browser memblokir WebAssembly atau apakah folder frontend yang dijalankan merupakan build lama. Jalankan /diagnostics/argon2-self-test.html dan cocokkan identitas build V4.'
      )), 30000);
    });
    const result = await Promise.race([hashPromise, timeoutPromise]);
    if (!result || !result.hash || result.hash.length !== 32) {
      throw new Error('Argon2id tidak menghasilkan kunci 32-byte yang valid.');
    }
    keyBytes = new Uint8Array(result.hash);
    report('Argon2id berhasil. Mengimpor KEK ke Web Crypto...');
  } catch (error) {
    throw new Error(`Derivasi Argon2id gagal: ${error?.message || String(error)}`);
  } finally {
    if (watchdog) clearTimeout(watchdog);
  }

  try {
    return await crypto.subtle.importKey(
      'raw', keyBytes, { name: 'AES-KW' }, false, ['wrapKey', 'unwrapKey']
    );
  } catch (error) {
    throw new Error(`Argon2id selesai, tetapi KEK gagal diimpor ke Web Crypto: ${error?.message || String(error)}`);
  } finally {
    keyBytes.fill(0);
  }
}

export async function generateMasterKey() { return crypto.subtle.generateKey({ name: 'AES-KW', length: 256 }, true, ['wrapKey', 'unwrapKey']); }
export async function generateFileDek() { return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']); }
export async function wrapMasterKey(masterKey, kek) { const value = await crypto.subtle.wrapKey('raw', masterKey, kek, { name: 'AES-KW' }); return uint8ArrayToB64(new Uint8Array(value)); }
export async function unwrapMasterKey(wrappedB64, kek) { return crypto.subtle.unwrapKey('raw', b64ToUint8Array(wrappedB64), kek, { name: 'AES-KW' }, { name: 'AES-KW', length: 256 }, false, ['wrapKey', 'unwrapKey']); }

/**
 * Re-wrap an existing Master Key without making the long-lived session key
 * extractable. A temporary extractable copy exists only for this operation,
 * because Web Crypto requires an extractable target for wrapKey(). The returned
 * session key is unwrapped again as non-extractable before it is put in RAM state.
 */
export async function rewrapMasterKeyForPassphrase(wrappedCurrentB64, oldKek, newKek) {
  if (!wrappedCurrentB64 || !oldKek || !newKek) {
    throw new Error('Material kunci untuk re-wrap tidak lengkap. Buka brankas kembali lalu ulangi.');
  }

  const temporaryMasterKey = await crypto.subtle.unwrapKey(
    'raw',
    b64ToUint8Array(wrappedCurrentB64),
    oldKek,
    { name: 'AES-KW' },
    { name: 'AES-KW', length: 256 },
    true,
    ['wrapKey', 'unwrapKey']
  );

  const wrappedMasterKeyB64 = await wrapMasterKey(temporaryMasterKey, newKek);
  const sessionMasterKey = await unwrapMasterKey(wrappedMasterKeyB64, newKek);
  const verifier = await createVerifier(temporaryMasterKey);

  return { wrappedMasterKeyB64, sessionMasterKey, verifier };
}
export async function wrapDek(dek, masterKey) { const value = await crypto.subtle.wrapKey('raw', dek, masterKey, { name: 'AES-KW' }); return uint8ArrayToB64(new Uint8Array(value)); }
export async function unwrapDek(wrappedB64, masterKey) { return crypto.subtle.unwrapKey('raw', b64ToUint8Array(wrappedB64), masterKey, { name: 'AES-KW' }, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']); }
export async function encryptText(text, key) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  let gcmKey = key;
  if (key.algorithm.name === 'AES-KW') gcmKey = await generateFileDek();
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, gcmKey, new TextEncoder().encode(text));
  return { ciphertextB64: uint8ArrayToB64(new Uint8Array(encrypted)), ivB64: uint8ArrayToB64(iv) };
}
export async function decryptText(ciphertextB64, ivB64, key) {
  const result = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64ToUint8Array(ivB64) }, key, b64ToUint8Array(ciphertextB64));
  return new TextDecoder().decode(result);
}
export async function createVerifier(masterKey) {
  const dek = await generateFileDek();
  const encrypted = await encryptText(VERIFIER_PLAINTEXT, dek);
  return { verifierCiphertext: encrypted.ciphertextB64, verifierIv: encrypted.ivB64, verifierWrappedDek: await wrapDek(dek, masterKey) };
}
export async function verifyPassphrase(masterKey, ciphertext, iv, wrappedDek) {
  try { const dek = await unwrapDek(wrappedDek, masterKey); return (await decryptText(ciphertext, iv, dek)) === VERIFIER_PLAINTEXT; } catch { return false; }
}
export async function encryptChunk(chunkData, dek, fileId, chunkIndex) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const aad = `${fileId}-${chunkIndex}`;
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: new TextEncoder().encode(aad), tagLength: 128 }, dek, chunkData);
  return { ciphertext: new Uint8Array(ciphertext), ivB64: uint8ArrayToB64(iv), aad };
}
export async function decryptChunk(ciphertext, ivB64, dek, fileId, chunkIndex) {
  try {
    const result = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64ToUint8Array(ivB64), additionalData: new TextEncoder().encode(`${fileId}-${chunkIndex}`), tagLength: 128 }, dek, ciphertext);
    return new Uint8Array(result);
  } catch { throw new Error(`Integritas chunk gagal! Chunk #${chunkIndex} telah dimanipulasi atau tertukar (AAD/Tag Mismatch).`); }
}
export async function computeSha256(data) {
  const hash = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hash)).map(value => value.toString(16).padStart(2, '0')).join('');
}


// Incremental SHA-256 used to hash Blob/File data without loading the whole file into RAM.
const SHA256_K = new Uint32Array([
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
]);
const rotr32 = (value, shift) => (value >>> shift) | (value << (32 - shift));

class IncrementalSha256 {
  constructor() {
    this.state = new Uint32Array([0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]);
    this.buffer = new Uint8Array(64);
    this.bufferLength = 0;
    this.totalBytes = 0n;
    this.finished = false;
  }

  update(input) {
    if (this.finished) throw new Error('SHA-256 stream sudah difinalisasi.');
    const data = input instanceof Uint8Array ? input : new Uint8Array(input);
    this.totalBytes += BigInt(data.byteLength);
    let offset = 0;

    if (this.bufferLength > 0) {
      const needed = Math.min(64 - this.bufferLength, data.byteLength);
      this.buffer.set(data.subarray(0, needed), this.bufferLength);
      this.bufferLength += needed;
      offset += needed;
      if (this.bufferLength === 64) {
        this.processBlock(this.buffer);
        this.bufferLength = 0;
      }
    }

    while (offset + 64 <= data.byteLength) {
      this.processBlock(data.subarray(offset, offset + 64));
      offset += 64;
    }

    if (offset < data.byteLength) {
      this.buffer.set(data.subarray(offset), 0);
      this.bufferLength = data.byteLength - offset;
    }
    return this;
  }

  processBlock(block) {
    const words = new Uint32Array(64);
    for (let i = 0; i < 16; i++) {
      const j = i * 4;
      words[i] = ((block[j] << 24) | (block[j + 1] << 16) | (block[j + 2] << 8) | block[j + 3]) >>> 0;
    }
    for (let i = 16; i < 64; i++) {
      const x = words[i - 15];
      const y = words[i - 2];
      const s0 = rotr32(x, 7) ^ rotr32(x, 18) ^ (x >>> 3);
      const s1 = rotr32(y, 17) ^ rotr32(y, 19) ^ (y >>> 10);
      words[i] = (words[i - 16] + s0 + words[i - 7] + s1) >>> 0;
    }

    let a=this.state[0], b=this.state[1], c=this.state[2], d=this.state[3];
    let e=this.state[4], f=this.state[5], g=this.state[6], h=this.state[7];
    for (let i = 0; i < 64; i++) {
      const sum1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
      const choice = (e & f) ^ (~e & g);
      const temp1 = (h + sum1 + choice + SHA256_K[i] + words[i]) >>> 0;
      const sum0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
      const majority = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (sum0 + majority) >>> 0;
      h=g; g=f; f=e; e=(d + temp1) >>> 0;
      d=c; c=b; b=a; a=(temp1 + temp2) >>> 0;
    }
    this.state[0]=(this.state[0]+a)>>>0; this.state[1]=(this.state[1]+b)>>>0;
    this.state[2]=(this.state[2]+c)>>>0; this.state[3]=(this.state[3]+d)>>>0;
    this.state[4]=(this.state[4]+e)>>>0; this.state[5]=(this.state[5]+f)>>>0;
    this.state[6]=(this.state[6]+g)>>>0; this.state[7]=(this.state[7]+h)>>>0;
  }

  digestHex() {
    if (this.finished) throw new Error('SHA-256 stream sudah difinalisasi.');
    const bitLength = this.totalBytes * 8n;
    this.buffer[this.bufferLength++] = 0x80;
    if (this.bufferLength > 56) {
      this.buffer.fill(0, this.bufferLength);
      this.processBlock(this.buffer);
      this.bufferLength = 0;
    }
    this.buffer.fill(0, this.bufferLength, 56);
    for (let i = 0; i < 8; i++) {
      this.buffer[63 - i] = Number((bitLength >> BigInt(i * 8)) & 0xffn);
    }
    this.processBlock(this.buffer);
    this.finished = true;
    return Array.from(this.state, value => value.toString(16).padStart(8, '0')).join('');
  }
}

export async function computeSha256Blob(blob, onProgress = null, chunkSize = 5 * 1024 * 1024) {
  if (!blob || typeof blob.slice !== 'function' || !Number.isFinite(blob.size)) {
    throw new TypeError('Input SHA-256 harus berupa Blob atau File.');
  }
  if (!Number.isSafeInteger(chunkSize) || chunkSize < 1) {
    throw new RangeError('Ukuran chunk SHA-256 tidak valid.');
  }
  const hasher = new IncrementalSha256();
  for (let offset = 0; offset < blob.size; offset += chunkSize) {
    const end = Math.min(offset + chunkSize, blob.size);
    const data = new Uint8Array(await blob.slice(offset, end).arrayBuffer());
    hasher.update(data);
    data.fill(0);
    try { onProgress?.(end, blob.size); } catch { /* UI progress must not affect hashing */ }
  }
  return hasher.digestHex();
}
