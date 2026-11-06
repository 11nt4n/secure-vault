-- Secure Vault relational SQLite schema, version 2.
-- `payload` is a temporary compatibility envelope. Core identity, relation,
-- uniqueness, quota, lifecycle and lookup fields are stored as typed columns.

CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY NOT NULL,
    record_key TEXT NOT NULL UNIQUE,
    username TEXT UNIQUE,
    email TEXT UNIQUE,
    role TEXT NOT NULL DEFAULT 'user',
    is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
    storage_quota_bytes INTEGER NOT NULL DEFAULT 0 CHECK (storage_quota_bytes >= 0),
    storage_used_bytes INTEGER NOT NULL DEFAULT 0 CHECK (storage_used_bytes >= 0),
    created_at TEXT,
    payload TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_users_role_active ON users(role, is_active);

CREATE TABLE IF NOT EXISTS vault_profiles (
    user_id TEXT PRIMARY KEY NOT NULL,
    record_key TEXT NOT NULL UNIQUE,
    created_at TEXT,
    updated_at TEXT,
    payload TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS encrypted_files (
    id TEXT PRIMARY KEY NOT NULL,
    record_key TEXT NOT NULL UNIQUE,
    owner_id TEXT NOT NULL,
    upload_status TEXT NOT NULL DEFAULT 'completed' CHECK (upload_status IN ('uploading', 'completed')),
    deletion_pending INTEGER NOT NULL DEFAULT 0 CHECK (deletion_pending IN (0, 1)),
    file_size_bytes INTEGER NOT NULL DEFAULT 0 CHECK (file_size_bytes >= 0),
    total_chunks INTEGER NOT NULL DEFAULT 0 CHECK (total_chunks >= 0),
    created_at TEXT,
    payload TEXT NOT NULL,
    FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_encrypted_files_owner_status ON encrypted_files(owner_id, upload_status, deletion_pending);
CREATE INDEX IF NOT EXISTS idx_encrypted_files_created_at ON encrypted_files(created_at);

CREATE TABLE IF NOT EXISTS file_chunks (
    id TEXT PRIMARY KEY NOT NULL,
    record_key TEXT NOT NULL UNIQUE,
    file_id TEXT NOT NULL,
    chunk_index INTEGER NOT NULL CHECK (chunk_index >= 0),
    chunk_size_bytes INTEGER NOT NULL DEFAULT 0 CHECK (chunk_size_bytes >= 0),
    storage_path TEXT NOT NULL,
    sha256_ciphertext TEXT,
    created_at TEXT,
    payload TEXT NOT NULL,
    UNIQUE (file_id, chunk_index),
    FOREIGN KEY (file_id) REFERENCES encrypted_files(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_file_chunks_file_index ON file_chunks(file_id, chunk_index);

CREATE TABLE IF NOT EXISTS audit_logs (
    id TEXT PRIMARY KEY NOT NULL,
    record_key TEXT NOT NULL UNIQUE,
    sequence_number INTEGER UNIQUE,
    timestamp TEXT,
    user_id TEXT,
    action_type TEXT,
    file_id TEXT,
    status TEXT,
    previous_hash TEXT,
    current_hash TEXT,
    payload TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_action ON audit_logs(user_id, action_type);

CREATE TABLE IF NOT EXISTS auth_rate_limits (
    record_key TEXT PRIMARY KEY NOT NULL,
    window_started_at INTEGER NOT NULL DEFAULT 0,
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    payload TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_auth_rate_limits_window ON auth_rate_limits(window_started_at);
