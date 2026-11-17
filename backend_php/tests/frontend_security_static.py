#!/usr/bin/env python3
"""Static guardrails for Secure Vault frontend hardening (no external packages)."""
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[2]
FRONTEND = ROOT / "frontend"
APP = (FRONTEND / "js" / "app.js").read_text(encoding="utf-8")
CLIENT = (FRONTEND / "js" / "crypto-worker-client.js").read_text(encoding="utf-8")
WORKER = (FRONTEND / "js" / "crypto-worker.js").read_text(encoding="utf-8")
ROUTER = (FRONTEND / "router.php").read_text(encoding="utf-8")
INDEX = (FRONTEND / "index.html").read_text(encoding="utf-8")
ALL_HTML = "\n".join(path.read_text(encoding="utf-8") for path in FRONTEND.rglob("*.html"))

failures = []

def require(condition: bool, message: str) -> None:
    if not condition:
        failures.append(message)

require("style-src 'self'" in ROUTER and "'unsafe-inline'" not in ROUTER,
        "CSP harus melarang inline styles.")
require("style-src-attr 'none'" in ROUTER,
        "CSP harus secara eksplisit memblokir atribut style inline.")
require("worker-src 'self'" in ROUTER,
        "CSP harus membatasi Worker ke same-origin.")
require("'unsafe-eval'" not in ROUTER,
        "CSP tidak boleh mengizinkan unsafe-eval.")
require("'wasm-unsafe-eval'" in ROUTER,
        "Runtime Argon2id WASM memerlukan pengecualian wasm-unsafe-eval yang eksplisit.")
require(not re.search(r"\sstyle\s*=", APP + ALL_HTML, re.IGNORECASE),
        "Template/HTML masih memiliki atribut style inline.")
require(not re.search(r"<style\b", ALL_HTML, re.IGNORECASE),
        "Halaman HTML masih memiliki style block inline.")
require(not re.search(r"\son[a-z]+\s*=", ALL_HTML + APP, re.IGNORECASE),
        "Template masih mengandung inline event handler HTML.")
require(not re.search(r"\b(?:eval)\s*\(|new\s+Function\s*\(|document\.write\s*\(", APP),
        "Ditemukan sink eksekusi kode dinamis yang berisiko.")
require("encryptChunkOffThread" in APP and "decryptChunkOffThread" in APP,
        "Upload/download harus menggunakan helper Web Worker.")
require("new Worker(" in CLIENT and "type: 'module'" in CLIENT,
        "Crypto Worker module belum dikonfigurasi.")
require("plaintext.fill(0)" in WORKER and "ciphertext.fill(0)" in WORKER,
        "Worker harus membersihkan buffer sementara setelah operasi.")
require("showSaveFilePicker" in APP and "createWritable" in APP and "writable.write(plaintext)" in APP,
        "Jalur download streaming File System Access API tidak ditemukan.")
require("forEachDecryptedChunk" in APP and "processedBytes !== fileSize" in APP,
        "Download harus memvalidasi panjang setiap chunk dan ukuran total.")
require("file.arrayBuffer()" not in APP,
        "Upload tidak boleh memuat seluruh file sekaligus ke ArrayBuffer.")
app_v = re.search(r"app\.js\?v=(\d+)", INDEX)
css_v = re.search(r"styles\.css\?v=(\d+)", INDEX)
require(bool(app_v and int(app_v.group(1)) >= 9 and css_v and int(css_v.group(1)) >= 9),
        "Cache-buster frontend belum dinaikkan ke minimal V9.")

if failures:
    print("FRONTEND SECURITY STATIC CHECK: FAIL")
    for failure in failures:
        print(f"- {failure}")
    sys.exit(1)

print("FRONTEND SECURITY STATIC CHECK: PASS")
print("- CSP style-src tidak mengizinkan inline styles atau unsafe-eval.")
print("- CSP membatasi Worker ke same-origin dan mempertahankan izin WASM Argon2id.")
print("- Upload/download memakai helper worker dan jalur unduh streaming.")
print("- Buffer plaintext/ciphertext sementara dibersihkan di worker.")
print("- Tidak ada pemuatan seluruh file melalui file.arrayBuffer().")
