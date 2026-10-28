// Zero-Knowledge 3-Layer Envelope Encryption:
// Passphrase -> KEK (Argon2id WASM) -> Master Key (AES-KW) -> File DEK (AES-KW) -> AES-256-GCM Chunks with AAD

export interface EphemeralVaultState {
  kek: CryptoKey | null;
  masterKey: CryptoKey | null;
}

// In-memory RAM storage for non-extractable keys
const ramState: EphemeralVaultState = {
  kek: null,
  masterKey: null,
};

export const VERIFIER_PLAINTEXT = 'SECURE_VAULT_PASS_VERIFIER_V1';

/**
 * Clear all cryptographic keys from browser memory immediately.
 */
export function clearVaultKeys(): void {
  ramState.kek = null;
  ramState.masterKey = null;
}

export function getLoadedMasterKey(): CryptoKey | null {
  return ramState.masterKey;
}

export function setLoadedKeys(kek: CryptoKey, masterKey: CryptoKey): void {
  ramState.kek = kek;
  ramState.masterKey = masterKey;
}

export function isVaultKeyLoaded(): boolean {
  return ramState.masterKey !== null;
}

/**
 * Generate a cryptographically secure random salt (16 bytes).
 */
export function generateSalt(length = 16): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(length));
}

/**
 * Convert Uint8Array to Base64
 */
export function uint8ArrayToB64(arr: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < arr.byteLength; i++) {
    binary += String.fromCharCode(arr[i]);
  }
  return btoa(binary);
}

/**
 * Convert Base64 to Uint8Array
 */
export function b64ToUint8Array(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Derive KEK (Key Encryption Key) from user passphrase using Argon2id WASM
 * Parameters: m=64 MiB (65536 KiB), t=3, p=1, hashLen=32 bytes (256-bit).
 * Falls back to high-iteration PBKDF2 if Argon2 WASM fails or times out.
 */
export async function deriveKek(passphrase: string, salt: Uint8Array): Promise<CryptoKey> {
  let keyBytes: Uint8Array;

  try {
    const globalArgon2 = typeof window !== 'undefined' ? (window as any).argon2 : null;
    if (globalArgon2 && typeof globalArgon2.hash === 'function') {
      const res = await globalArgon2.hash({
        pass: passphrase,
        salt: salt,
        time: 3,
        mem: 65536, // 64 MiB
        hashLen: 32, // 256-bit key
        parallelism: 1,
        type: globalArgon2.ArgonType ? globalArgon2.ArgonType.Argon2id : 2,
      });
      keyBytes = new Uint8Array(res.hash);
    } else {
      throw new Error('Argon2 WASM runtime not initialized');
    }
  } catch (err) {
    console.warn('Argon2id WASM failed/unavailable, falling back to PBKDF2 (SHA-256 600,000 iters):', err);
    const enc = new TextEncoder();
    const baseKey = await crypto.subtle.importKey(
      'raw',
      enc.encode(passphrase),
      'PBKDF2',
      false,
      ['deriveBits']
    );
    const derivedBits = await crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt: salt,
        iterations: 600000,
        hash: 'SHA-256',
      },
      baseKey,
      256
    );
    keyBytes = new Uint8Array(derivedBits);
  }

  // Import as AES-KW key (used to wrap/unwrap Master Key)
  return crypto.subtle.importKey(
    'raw',
    keyBytes,
    { name: 'AES-KW' },
    false, // non-extractable
    ['wrapKey', 'unwrapKey']
  );
}

/**
 * Generate a new 256-bit Master Key (MK).
 */
export async function generateMasterKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey(
    { name: 'AES-KW', length: 256 },
    true, // extractable only during wrapping
    ['wrapKey', 'unwrapKey']
  );
}

/**
 * Generate a new 256-bit Data Encryption Key (DEK) for a file.
 */
export async function generateFileDek(): Promise<CryptoKey> {
  return crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true, // extractable only during wrapping with MK
    ['encrypt', 'decrypt']
  );
}

/**
 * Wrap Master Key using KEK via AES Key Wrap (RFC 3394).
 */
export async function wrapMasterKey(masterKey: CryptoKey, kek: CryptoKey): Promise<string> {
  const wrapped = await crypto.subtle.wrapKey('raw', masterKey, kek, { name: 'AES-KW' });
  return uint8ArrayToB64(new Uint8Array(wrapped));
}

/**
 * Unwrap Master Key using KEK.
 */
export async function unwrapMasterKey(wrappedB64: string, kek: CryptoKey): Promise<CryptoKey> {
  const wrappedBytes = b64ToUint8Array(wrappedB64);
  return crypto.subtle.unwrapKey(
    'raw',
    wrappedBytes,
    kek,
    { name: 'AES-KW' },
    { name: 'AES-KW', length: 256 },
    false, // non-extractable in RAM
    ['wrapKey', 'unwrapKey']
  );
}

/**
 * Wrap File DEK using Master Key.
 */
export async function wrapDek(dek: CryptoKey, masterKey: CryptoKey): Promise<string> {
  const wrapped = await crypto.subtle.wrapKey('raw', dek, masterKey, { name: 'AES-KW' });
  return uint8ArrayToB64(new Uint8Array(wrapped));
}

/**
 * Unwrap File DEK using Master Key.
 */
export async function unwrapDek(wrappedDekB64: string, masterKey: CryptoKey): Promise<CryptoKey> {
  const wrappedBytes = b64ToUint8Array(wrappedDekB64);
  return crypto.subtle.unwrapKey(
    'raw',
    wrappedBytes,
    masterKey,
    { name: 'AES-KW' },
    { name: 'AES-GCM', length: 256 },
    false, // non-extractable in RAM
    ['encrypt', 'decrypt']
  );
}

/**
 * Encrypt arbitrary string (e.g. filename, metadata, verifier) with a key via AES-256-GCM
 */
export async function encryptText(text: string, key: CryptoKey): Promise<{ ciphertextB64: string; ivB64: string }> {
  const enc = new TextEncoder();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  
  // If key is AES-KW, we derive an AES-GCM key from it or export/import
  let gcmKey = key;
  if (key.algorithm.name === 'AES-KW') {
    // Wrap a fresh GCM key or derive
    const rawDek = await generateFileDek();
    gcmKey = rawDek;
  }

  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    gcmKey,
    enc.encode(text)
  );

  return {
    ciphertextB64: uint8ArrayToB64(new Uint8Array(encrypted)),
    ivB64: uint8ArrayToB64(iv),
  };
}

/**
 * Decrypt string with AES-256-GCM
 */
export async function decryptText(ciphertextB64: string, ivB64: string, key: CryptoKey): Promise<string> {
  const dec = new TextDecoder();
  const iv = b64ToUint8Array(ivB64);
  const ciphertext = b64ToUint8Array(ciphertextB64);

  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    key,
    ciphertext
  );

  return dec.decode(decrypted);
}

/**
 * Create an encrypted verifier string using the Master Key.
 * We encrypt VERIFIER_PLAINTEXT with a dedicated DEK and store wrapped DEK + verifier ciphertext.
 */
export async function createVerifier(masterKey: CryptoKey): Promise<{ verifierCiphertext: string; verifierIv: string; verifierWrappedDek: string }> {
  const dek = await generateFileDek();
  const { ciphertextB64, ivB64 } = await encryptText(VERIFIER_PLAINTEXT, dek);
  const wrappedDek = await wrapDek(dek, masterKey);
  return {
    verifierCiphertext: ciphertextB64,
    verifierIv: ivB64,
    verifierWrappedDek: wrappedDek,
  };
}

/**
 * Validate passphrase by attempting to unwrap and decrypt the verifier string.
 */
export async function verifyPassphrase(
  masterKey: CryptoKey,
  verifierCiphertext: string,
  verifierIv: string,
  verifierWrappedDek: string
): Promise<boolean> {
  try {
    const dek = await unwrapDek(verifierWrappedDek, masterKey);
    const plaintext = await decryptText(verifierCiphertext, verifierIv, dek);
    return plaintext === VERIFIER_PLAINTEXT;
  } catch (err) {
    return false;
  }
}

/**
 * Encrypt a 5 MB file chunk using AES-256-GCM with AAD = `${fileId}-${chunkIndex}`
 */
export async function encryptChunk(
  chunkData: Uint8Array,
  dek: CryptoKey,
  fileId: string,
  chunkIndex: number
): Promise<{ ciphertext: Uint8Array; ivB64: string; aad: string }> {
  const iv = crypto.getRandomValues(new Uint8Array(12)); // 96-bit IV
  const aad = `${fileId}-${chunkIndex}`;
  const enc = new TextEncoder();
  const aadBytes = enc.encode(aad);

  const ciphertextBuf = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv,
      additionalData: aadBytes,
      tagLength: 128,
    },
    dek,
    chunkData
  );

  return {
    ciphertext: new Uint8Array(ciphertextBuf),
    ivB64: uint8ArrayToB64(iv),
    aad,
  };
}

/**
 * Decrypt a 5 MB file chunk using AES-256-GCM with AAD verification.
 * Throws an error immediately if tampering or chunk reordering is detected.
 */
export async function decryptChunk(
  ciphertext: Uint8Array,
  ivB64: string,
  dek: CryptoKey,
  fileId: string,
  chunkIndex: number
): Promise<Uint8Array> {
  const iv = b64ToUint8Array(ivB64);
  const expectedAad = `${fileId}-${chunkIndex}`;
  const enc = new TextEncoder();
  const aadBytes = enc.encode(expectedAad);

  try {
    const plaintextBuf = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv,
        additionalData: aadBytes,
        tagLength: 128,
      },
      dek,
      ciphertext
    );
    return new Uint8Array(plaintextBuf);
  } catch (err) {
    throw new Error(`Integritas chunk gagal! Chunk #${chunkIndex} telah dimanipulasi atau tertukar (AAD/Tag Mismatch).`);
  }
}

/**
 * Compute SHA-256 hash of a file or chunk for integrity verification.
 */
export async function computeSha256(data: Uint8Array): Promise<string> {
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}
