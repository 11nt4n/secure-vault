'use strict';
const button = document.getElementById('run');
const output = document.getElementById('output');
const write = (message) => { output.textContent = message; };

button.addEventListener('click', async () => {
  button.disabled = true;
  const lines = [];
  const report = (line) => { lines.push(line); write(lines.join('\n')); };
  try {
    report(`Konteks aman: ${window.isSecureContext ? 'ya' : 'tidak'}`);
    if (!window.crypto?.subtle) throw new Error('Web Crypto tidak tersedia. Jalankan pada localhost atau HTTPS.');
    if (!window.argon2 || typeof window.argon2.hash !== 'function') throw new Error('Runtime argon2-bundled.min.js tidak berhasil dimuat.');
    report('Runtime Argon2id: termuat.\nBuild yang diuji: NATIVE-V9-2026.11.04');

    const salt = window.crypto.getRandomValues(new Uint8Array(16));
    const start = performance.now();
    const hashPromise = window.argon2.hash({
      pass: 'SecureVault local diagnostic only', salt, time: 3, mem: 65536, hashLen: 32, parallelism: 1,
      type: window.argon2.ArgonType ? window.argon2.ArgonType.Argon2id : 2
    });
    let timeoutId;
    let result;
    try {
      result = await Promise.race([hashPromise, new Promise((_, reject) => {
        timeoutId = setTimeout(() => reject(new Error('TIMEOUT: Argon2id tidak selesai dalam 30 detik. Kemungkinan WebAssembly terblokir atau mesin WASM gagal diinisialisasi.')), 30000);
      })]);
    } finally {
      if (timeoutId) clearTimeout(timeoutId);
    }
    const elapsed = ((performance.now() - start) / 1000).toFixed(2);
    if (!result?.hash || result.hash.length !== 32) throw new Error('Argon2id tidak menghasilkan kunci 32-byte.');
    report(`Argon2id: BERHASIL (${elapsed} detik, 32 byte).`);

    const keyBytes = new Uint8Array(result.hash);
    const kek = await window.crypto.subtle.importKey('raw', keyBytes, {name:'AES-KW'}, false, ['wrapKey','unwrapKey']);
    keyBytes.fill(0);
    const master = await window.crypto.subtle.generateKey({name:'AES-KW',length:256}, true, ['wrapKey','unwrapKey']);
    const wrapped = await window.crypto.subtle.wrapKey('raw', master, kek, {name:'AES-KW'});
    const reopened = await window.crypto.subtle.unwrapKey('raw', wrapped, kek, {name:'AES-KW'}, {name:'AES-KW',length:256}, false, ['wrapKey','unwrapKey']);
    if (reopened.algorithm.name !== 'AES-KW') throw new Error('Master Key hasil unwrap tidak valid.');
    report('Web Crypto AES-KW: BERHASIL (wrap + unwrap Master Key).');
    report('HASIL AKHIR: SEMUA UJI LULUS.');
  } catch (error) {
    report(`HASIL AKHIR: GAGAL.\nDetail: ${error?.message || String(error)}`);
  } finally {
    button.disabled = false;
  }
});
