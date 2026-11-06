# Security fixes applied

This package remains a local prototype and is not production-ready. The following high-priority improvements were applied:

- Argon2id is fail-closed: the vault no longer silently changes to PBKDF2 when the WASM runtime fails.
- Vault passphrases now require at least 12 characters at creation and re-wrap.
- Login and MFA verification are throttled to five failed attempts per 15 minutes for each account/IP pair. The throttle is persisted under the database lock.
- Vault setup and master-key re-wrap validate canonical Base64 and exact cryptographic material lengths before changing stored state.
- JWTs carry a server-side session generation. Logout and administrator session revocation increment that generation, invalidating existing tokens immediately.
- API responses and the Vite development server now emit a CSP baseline, anti-framing, referrer, MIME, and permissions headers. HSTS is opt-in through `SECURE_VAULT_ENABLE_HSTS=1` and must only be enabled behind valid HTTPS.
- Documentation now states that a JSON-resident hash chain is not an immutable, independently anchored audit trail.

Production blockers still include Keycloak/OIDC PKCE, PostgreSQL with a real transaction model, TLS/reverse-proxy deployment, gateway rate limiting, immutable/external audit anchoring, and independent security testing.

## Iteration 1 remediation (2026-11-02)

- Corrected Master Key passphrase re-wrap: the application now creates a temporary extractable copy only during re-wrap and restores a non-extractable session key before returning to normal use.
- Kept vault profile material synchronized after initial setup and passphrase re-wrap.
- Changed upload processing to read, hash, encrypt, and release one 5 MiB plaintext chunk at a time instead of buffering the complete file.
- Changed download assembly to a Blob of authenticated plaintext chunks rather than making an additional full-file contiguous buffer; legacy SHA-256 checks remain active.
- Serialized MFA challenge creation, failure-count updates, and single-use consumption with a stable inter-process lock.
- Aligned PHP upload limits across launchers and documentation, and added fail-fast checks for the required `pdo_sqlite` extension.
- Corrected admin ciphertext telemetry to count stored ciphertext chunk lengths rather than plaintext file sizes.
- Added repeatable Web Crypto, incremental SHA-256, and concurrent MFA challenge regression tests.

The API suites Stage 1 and Stage 2 must still be executed in an environment with `pdo_sqlite` enabled. Download processing still retains the decrypted chunk parts until Blob creation, and plaintext file hashes remain visible as server-side metadata for this iteration. See `REMEDIATION_LOG.md` for the remaining work.
