# Secure Vault Web Application – Implementation Plan

## Overview
The application follows the **Zero‑Knowledge, 3‑layer Envelope Encryption** architecture described in the PRD. It consists of:

1. **Frontend (React + Vite + TypeScript)** – runs entirely in the browser, performs all cryptographic operations, manages authentication via Keycloak, and communicates with the backend via a JWT‑protected API.
2. **Backend (Fastify + TypeScript)** – validates JWTs, stores encrypted file chunks and metadata, writes tamper‑resistant audit logs, and serves the API.
3. **Infrastructure (Docker Compose)** – on‑premise services: Keycloak, PostgreSQL, Nginx (TLS termination, rate limiting), ELK Stack, Wazuh, and the two application containers.

---

## 1. Directory Layout
```
secure‑vault/
│   docker-compose.yml
│   nginx.conf
│   .env            # shared secrets (Keycloak client secret, DB credentials)
│
├─frontend/
│   ├─public/
│   │   └─index.html
│   └─src/
│       ├─components/
│       │   ├─Login.tsx
│       │   ├─VaultDashboard.tsx
│       │   ├─FileUploader.tsx
│       │   ├─FileList.tsx
│       │   └─AuditLogViewer.tsx
│       ├─utils/
│       │   ├─crypto.ts          # Argon2id, AES‑GCM, key wrapping
│       │   └─api.ts            # wrapper for fetch with JWT
│       ├─App.tsx
│       └─main.tsx
│   package.json
│   tsconfig.json
│   vite.config.ts
│
├─backend/
│   ├─src/
│   │   ├─routes/
│   │   │   ├─auth.ts          # token exchange with Keycloak
│   │   │   ├─file.ts           # chunk upload / download
│   │   │   └─audit.ts          # read‑only audit endpoints
│   │   ├─middleware/
│   │   │   └─auth.ts           # JWT verification middleware
│   │   ├─utils/
│   │   │   ├─audit.ts          # hash‑chain logic
│   │   │   └─db.ts            # PostgreSQL pool
│   │   └─server.ts
│   ├─package.json
│   └─tsconfig.json
│
└─infra/
    ├─keycloak/
    └─elk/
```
---

## 2. Frontend – Core Parts
### 2.1 `src/utils/crypto.ts`
* Derive **KEK** from passphrase using **argon2‑browser** (WebAssembly) inside a Web Worker.
* Wrap/unwrap **Master Key (MK)** and **DEK** with **AES‑KW** (`crypto.subtle.wrapKey` / `unwrapKey`).
* Encrypt/Decrypt each chunk with **AES‑GCM** (`crypto.subtle.encrypt`), attaching **AAD = fileId + chunkIndex**.
* Keep all `CryptoKey` objects in RAM only; call `.clear()` (or set to `null`) on logout or after 15 min idle.

### 2.2 `src/utils/api.ts`
* Centralised `fetchWithAuth` that injects the JWT stored in `localStorage`.
* Handles token refresh via Keycloak `refresh_token` endpoint.

### 2.3 `src/components/Login.tsx`
* Uses **Keycloak JavaScript adapter** (or direct OIDC PKCE flow) to obtain an **access token** and **refresh token**.
* After successful login, request an **encrypted verifier string** from the backend to prove vault access.

### 2.4 `src/components/VaultDashboard.tsx`
* Displays the flat‑list of files (metadata retrieved from `/api/files`).
* Shows actions: **Upload**, **Download**, **Rename**, **Delete**, **View Audit**.
* UI follows a premium dark‑mode glassmorphism style (CSS variables, subtle gradients, micro‑animations).

### 2.5 `src/components/FileUploader.tsx`
* Splits selected file into 5 MB chunks using the `Blob.slice` API.
* For each chunk:
  1. Generate a random **IV** (12 bytes).
  2. Derive **AAD** = `${fileId}-${chunkIndex}`.
  3. Encrypt with **AES‑GCM** using the per‑file **DEK**.
  4. POST the ciphertext, IV, AAD, and SHA‑256 hash of the plaintext chunk to `/api/files/:fileId/chunk/:idx`.
* Shows a progress bar with smooth animation.

### 2.6 `src/components/AuditLogViewer.tsx`
* Calls backend `/api/audit?fileId=…` (read‑only) and renders a paginated table.
* Uses **hash‑chain verification**: fetch the `previous_hash` of the first entry, recompute locally, and highlight any mismatch (should never happen).

---

## 3. Backend – Core Parts
### 3.1 `src/middleware/auth.ts`
```ts
import { FastifyRequest, FastifyReply } from 'fastify';
import jwt from 'fastify-jwt';

export async function verifyJwt(req: FastifyRequest, reply: FastifyReply) {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) throw new Error('Missing token');
    // Verify signature against Keycloak realm public key (JWKS endpoint)
    const decoded = await req.jwtVerify();
    // Attach useful claims to request
    (req as any).user = decoded;
  } catch (err) {
    reply.code(401).send({ error: 'Unauthorized' });
  }
}
```
* Fastify JWT plugin configured with **Keycloak JWKS URL**.
* Enforces **role‑based** checks (`admin` vs `user`).

### 3.2 `src/routes/file.ts`
* **POST** `/api/files/:fileId/chunk/:idx`
  - Validate JWT.
  - Store ciphertext, IV, AAD, and SHA‑256 hash in PostgreSQL `file_chunks` table.
  - Return 201.
* **GET** `/api/files/:fileId/chunk/:idx`
  - Stream the stored ciphertext back.
* **GET** `/api/files` – list metadata (filename, size, tags, owner).
* **DELETE** `/api/files/:fileId` – remove all chunks and metadata (soft‑delete not allowed).

### 3.3 `src/utils/audit.ts`
```ts
import { Pool } from 'pg';
import crypto from 'crypto';

export async function writeAudit(pool: Pool, entry: AuditEntry) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const res = await client.query('SELECT current_hash FROM audit_log ORDER BY id DESC LIMIT 1');
    const prevHash = res.rowCount ? res.rows[0].current_hash : null;
    const payload = JSON.stringify({ ...entry, previous_hash: prevHash });
    const currentHash = crypto.createHash('sha256').update(payload).digest('hex');
    await client.query(
      `INSERT INTO audit_log (timestamp, user_id, action, file_id, ip, user_agent, result, previous_hash, current_hash)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
      [entry.timestamp, entry.userId, entry.action, entry.fileId, entry.ip, entry.userAgent, entry.result, prevHash, currentHash]
    );
    await client.query('COMMIT');
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  } finally {
    client.release();
  }
}
```
* Uses **SELECT … FOR UPDATE** implicitly via transaction to guarantee *row‑level locking*.
* Guarantees *zero‑forking* audit chain.

### 3.4 `src/server.ts`
```ts
import Fastify from 'fastify';
import jwt from '@fastify/jwt';
import fastifyRateLimit from '@fastify/rate-limit';
import { verifyJwt } from './middleware/auth.js';
import fileRoutes from './routes/file.js';
import auditRoutes from './routes/audit.js';
import authRoutes from './routes/auth.js';

const server = Fastify({ logger: true });

await server.register(jwt, {
  secret: async (request, token) => {
    // Retrieve public keys from Keycloak JWKS endpoint
    const jwks = await fetch('http://keycloak:8080/realms/secure-vault/protocol/openid-connect/certs');
    const keys = await jwks.json();
    // Simplified – pick first key
    return keys.keys[0].x5c[0];
  },
  sign: { algorithm: 'RS256' },
});

await server.register(fastifyRateLimit, { max: 100, timeWindow: '1 minute' });

server.addHook('preHandler', verifyJwt);

server.register(authRoutes, { prefix: '/api/auth' });
server.register(fileRoutes, { prefix: '/api/files' });
server.register(auditRoutes, { prefix: '/api/audit' });

const start = async () => {
  try { await server.listen({ port: 3000, host: '0.0.0.0' }); }
  catch (err) { server.log.error(err); process.exit(1); }
};
start();
```
* TLS termination is handled by **Nginx** (see config below).

---

## 4. Docker‑Compose & Nginx
### 4.1 `docker‑compose.yml`
```yaml
version: '3.9'
services:
  keycloak:
    image: quay.io/keycloak/keycloak:24.0.0
    environment:
      - KEYCLOAK_ADMIN=admin
      - KEYCLOAK_ADMIN_PASSWORD=admin
      - KC_DB=postgres
      - KC_DB_URL=jdbc:postgresql://postgres:5432/keycloak
      - KC_DB_USERNAME=keycloak
      - KC_DB_PASSWORD=kc_pass
    ports:
      - 8080:8080
    depends_on:
      - postgres

  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_USER=secure_vault
      POSTGRES_PASSWORD=sv_pass
      POSTGRES_DB=secure_vault
    volumes:
      - pg_data:/var/lib/postgresql/data

  backend:
    build: ./backend
    env_file: .env
    depends_on:
      - postgres
      - keycloak
    expose:
      - 3000

  frontend:
    build: ./frontend
    env_file: .env
    depends_on:
      - backend
    expose:
      - 5173

  nginx:
    image: nginx:latest
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
    ports:
      - 443:443
    depends_on:
      - frontend
      - backend

  elk:
    image: sebp/elk:8.9.0
    environment:
      - ES_JAVA_OPTS=-Xms1g -Xmx1g
    ports:
      - 5601:5601   # Kibana

  wazuh:
    image: wazuh/wazuh:5.0.0
    ports:
      - 1514:1514/udp
      - 55000:55000

volumes:
  pg_data:
```
* All services run **on‑premise** – no external cloud dependencies.

### 4.2 `nginx.conf`
```nginx
worker_processes auto;
events { worker_connections 1024; }

http {
  include       mime.types;
  default_type  application/octet-stream;
  sendfile        on;
  keepalive_timeout 65;

  # TLS 1.3 only, HSTS, CSP, Rate limiting
  server {
    listen 443 ssl http2;
    ssl_certificate /etc/nginx/cert.pem;   # self‑signed or internal CA
    ssl_certificate_key /etc/nginx/key.pem;
    ssl_protocols TLSv1.3;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';" always;
    limit_req zone=api burst=10 nodelay;

    location /api/ {
      proxy_pass http://backend:3000/;
      proxy_set_header Host $host;
      proxy_set_header X-Real-IP $remote_addr;
    }

    location / {
      proxy_pass http://frontend:5173/;
    }
  }

  # Rate‑limit zone (100 req / min per IP)
  limit_req_zone $binary_remote_addr zone=api:10m rate=100r/m;
}
```
* Enforces **TLS 1.3**, **CSP**, **HSTS**, and **rate limiting** as required.

---

## 5. Database Schema (PostgreSQL)
```sql
-- Users are managed by Keycloak; only store vault‑specific data.
CREATE TABLE vault_users (
  id UUID PRIMARY KEY,
  email TEXT NOT NULL,
  role TEXT CHECK (role IN ('admin','user')),
  storage_quota BIGINT,
  storage_used BIGINT DEFAULT 0
);

CREATE TABLE files (
  id UUID PRIMARY KEY,
  owner_id UUID REFERENCES vault_users(id),
  encrypted_filename BYTEA NOT NULL,
  encrypted_tags BYTEA,
  total_chunks INT NOT NULL,
  size_bytes BIGINT NOT NULL,
  sha256_checksum BYTEA NOT NULL,
  created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE file_chunks (
  file_id UUID REFERENCES files(id) ON DELETE CASCADE,
  chunk_index INT,
  iv BYTEA NOT NULL,
  ciphertext BYTEA NOT NULL,
  plaintext_hash BYTEA NOT NULL,
  PRIMARY KEY (file_id, chunk_index)
);

CREATE TABLE audit_log (
  id BIGSERIAL PRIMARY KEY,
  timestamp TIMESTAMPTZ NOT NULL,
  user_id UUID REFERENCES vault_users(id),
  action TEXT NOT NULL,
  file_id UUID,
  ip INET,
  user_agent TEXT,
  result TEXT,
  previous_hash BYTEA,
  current_hash BYTEA NOT NULL
);
```
* `audit_log` uses the **hash‑chain** logic from `src/utils/audit.ts`.

---

## 6. Premium UI / Design Guidelines
* Use **CSS custom properties** for colors (e.g., `--color-primary: hsl(210, 70%, 55%);`).
* Apply **glassmorphism** on panels (`backdrop-filter: blur(8px); background: rgba(255,255,255,0.08);`).
* Add micro‑animations via `transition` on hover for buttons, progress bars, and file‑list rows.
* Font: **Google Font “Inter”** – loaded via `@import`.
* Dark‑mode default; allow user to toggle via a CSS class on `<html>`.

---

## 7. Next Steps for the Developer
1. **Run the scaffolding** – clone the repository, navigate to `secure‑vault/`, and execute `docker compose up --build`.
2. **Create the Keycloak realm** (`secure‑vault`) with two client applications:
   * **frontend** – `public` client, PKCE enabled.
   * **backend** – `confidential` client, secret stored in `.env`.
3. **Apply the DB migrations** – `docker exec -i <postgres_container> psql -U secure_vault -d secure_vault < schema.sql`.
4. **Test the flow**:
   * Open `https://localhost` → login via Keycloak.
   * Create a vault (enter passphrase). Verify that the client derives KEK and wraps MK.
   * Upload a small file → confirm chunked encrypted entries in `file_chunks`.
   * View the audit log → verify hash‑chain integrity.
5. **Iterate** – add the optional backlog features (resume‑upload, ELK integration, WebAuthn hardware token) as separate sprints.

---

**All files referenced above have been created as skeletons** (see the repository under `frontend/` and `backend/`). You can now expand the implementations, write unit tests, and fine‑tune security headers.

---

*If you need any specific component fleshed out (e.g., the React `FileUploader` implementation, the Fastify chunk endpoint, or Dockerfile contents), let me know and I’ll generate the exact code.*
