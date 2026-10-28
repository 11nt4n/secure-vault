-- Secure Vault MySQL Database Schema (Optional for XAMPP / phpMyAdmin)
-- Standard: ISO/IEC 15408:2022 & ISO/IEC 18045:2026

CREATE DATABASE IF NOT EXISTS `secure_vault` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE `secure_vault`;

-- 1. Users Table
CREATE TABLE IF NOT EXISTS `users` (
    `id` VARCHAR(36) NOT NULL PRIMARY KEY,
    `username` VARCHAR(64) NOT NULL UNIQUE,
    `password_hash` VARCHAR(64) NOT NULL,
    `email` VARCHAR(128) NOT NULL UNIQUE,
    `role` ENUM('admin', 'user') NOT NULL DEFAULT 'user',
    `is_active` TINYINT(1) NOT NULL DEFAULT 1,
    `storage_quota_bytes` BIGINT UNSIGNED NOT NULL DEFAULT 5368709120,
    `storage_used_bytes` BIGINT UNSIGNED NOT NULL DEFAULT 0,
    `created_at` VARCHAR(32) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 2. Vault Profiles (Zero-Knowledge Passphrase Wrapped Keys)
CREATE TABLE IF NOT EXISTS `vault_profiles` (
    `user_id` VARCHAR(36) NOT NULL PRIMARY KEY,
    `argon2_salt` VARCHAR(64) NOT NULL,
    `wrapped_master_key` TEXT NOT NULL,
    `verifier_ciphertext` TEXT NOT NULL,
    `verifier_iv` VARCHAR(64) NOT NULL,
    `verifier_wrapped_dek` TEXT NOT NULL,
    `created_at` VARCHAR(32) NOT NULL,
    `updated_at` VARCHAR(32) NOT NULL,
    FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 3. Encrypted Files Metadata
CREATE TABLE IF NOT EXISTS `encrypted_files` (
    `id` VARCHAR(36) NOT NULL PRIMARY KEY,
    `owner_id` VARCHAR(36) NOT NULL,
    `encrypted_file_name` TEXT NOT NULL,
    `encrypted_tags` TEXT NULL,
    `file_size_bytes` BIGINT UNSIGNED NOT NULL,
    `total_chunks` INT UNSIGNED NOT NULL,
    `wrapped_dek` TEXT NOT NULL,
    `plaintext_sha256` VARCHAR(64) NOT NULL,
    `created_at` VARCHAR(32) NOT NULL,
    FOREIGN KEY (`owner_id`) REFERENCES `users`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 4. File Chunks (Ciphertext Blobs Metadata)
CREATE TABLE IF NOT EXISTS `file_chunks` (
    `id` VARCHAR(36) NOT NULL PRIMARY KEY,
    `file_id` VARCHAR(36) NOT NULL,
    `chunk_index` INT UNSIGNED NOT NULL,
    `chunk_size_bytes` INT UNSIGNED NOT NULL,
    `iv_base64` VARCHAR(64) NOT NULL,
    `aad_string` VARCHAR(128) NOT NULL,
    `storage_path` VARCHAR(255) NOT NULL,
    `created_at` VARCHAR(32) NOT NULL,
    UNIQUE KEY `uk_file_chunk` (`file_id`, `chunk_index`),
    FOREIGN KEY (`file_id`) REFERENCES `encrypted_files`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 5. Tamper-Resistant SHA-256 Hash-Chain Audit Logs
CREATE TABLE IF NOT EXISTS `audit_logs` (
    `id` VARCHAR(36) NOT NULL PRIMARY KEY,
    `sequence_number` BIGINT UNSIGNED NOT NULL UNIQUE,
    `timestamp` VARCHAR(32) NOT NULL,
    `user_id` VARCHAR(64) NOT NULL,
    `action_type` VARCHAR(64) NOT NULL,
    `file_id` VARCHAR(36) NULL,
    `ip_address` VARCHAR(45) NOT NULL,
    `user_agent` TEXT NOT NULL,
    `status` ENUM('SUCCESS', 'FAILED') NOT NULL,
    `previous_hash` CHAR(64) NOT NULL,
    `current_hash` CHAR(64) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
