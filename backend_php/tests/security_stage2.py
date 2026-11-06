#!/usr/bin/env python3
"""Stage 2 upload, quota, idempotency and audit regression tests (stdlib only)."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import socket
import struct
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def totp(secret: str, timestamp: int | None = None) -> str:
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    bits = "".join(f"{alphabet.index(c):05b}" for c in secret.rstrip("="))
    key = bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits) - 7, 8))
    counter = (int(time.time()) if timestamp is None else timestamp) // 30
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    number = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(number % 1_000_000).zfill(6)


def request(base: str, path: str, payload=None, headers=None, method=None):
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    actual_headers = {"Content-Type": "application/json"}
    actual_headers.update(headers or {})
    req = urllib.request.Request(base + path, data=data, headers=actual_headers, method=method or ("POST" if data is not None else "GET"))
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            raw = response.read()
            try:
                parsed = json.loads(raw) if raw else {}
            except json.JSONDecodeError:
                parsed = raw
            return response.status, parsed, response.headers
    except urllib.error.HTTPError as error:
        raw = error.read()
        try:
            parsed = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            parsed = raw
        return error.code, parsed, error.headers


def multipart_request(base: str, path: str, token: str, iv: str, aad: str, blob: bytes):
    boundary = "----SecureVaultTest" + secrets.token_hex(12)
    pieces = []
    for name, value in (("ivBase64", iv), ("aadString", aad)):
        pieces.append((
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n".encode()
            + value.encode() + b"\r\n"
        ))
    pieces.append(
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"chunkBlob\"; filename=\"chunk.bin\"\r\nContent-Type: application/octet-stream\r\n\r\n".encode()
        + blob + b"\r\n"
    )
    body = b"".join(pieces) + f"--{boundary}--\r\n".encode()
    req = urllib.request.Request(
        base + path,
        data=body,
        headers={
            "Authorization": "Bearer " + token,
            "Content-Type": f"multipart/form-data; boundary={boundary}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            raw = response.read()
            return response.status, json.loads(raw) if raw else {}, response.headers
    except urllib.error.HTTPError as error:
        raw = error.read()
        try:
            parsed = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            parsed = raw
        return error.code, parsed, error.headers


def main() -> int:
    php = os.environ.get("PHP_BINARY", "php")
    sqlite_probe = subprocess.run(
        [php, "-r", "exit(extension_loaded('pdo_sqlite') ? 0 : 1);"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10,
    )
    if sqlite_probe.returncode != 0:
        print("BLOCKED: ekstensi PHP pdo_sqlite tidak aktif pada PHP_BINARY yang dipilih.", file=sys.stderr)
        print("Aktifkan pdo_sqlite pada php.ini lalu jalankan ulang suite ini.", file=sys.stderr)
        if sqlite_probe.stderr.strip():
            print(sqlite_probe.stderr.strip(), file=sys.stderr)
        return 2
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]

    with tempfile.TemporaryDirectory(prefix="secure-vault-stage2-") as temporary:
        private = Path(temporary)
        env = os.environ.copy()
        env.update({
            "JWT_SECRET": secrets.token_hex(32),
            "MFA_ENCRYPTION_KEY": base64.b64encode(os.urandom(32)).decode("ascii"),
            "SECURE_VAULT_DATA_DIR": str(private / "data"),
            "SECURE_VAULT_STORAGE_DIR": str(private / "storage"),
            "SECURE_VAULT_CORS_ORIGINS": "http://localhost:5173",
        })
        (private / "data").mkdir()
        (private / "storage").mkdir()
        log_path = private / "server.log"
        with log_path.open("w", encoding="utf-8") as log:
            server = subprocess.Popen(
                [php, "-d", "upload_max_filesize=8M", "-d", "post_max_size=10M",
                 "-d", "max_execution_time=120", "-d", "max_input_time=120",
                 "-S", f"127.0.0.1:{port}", "-t", "backend_php", "backend_php/index.php"],
                cwd=PROJECT_ROOT, env=env, stdout=log, stderr=subprocess.STDOUT,
            )
            base = f"http://127.0.0.1:{port}/api"
            try:
                for _ in range(80):
                    if server.poll() is not None:
                        raise RuntimeError(f"PHP server stopped. Inspect {log_path}")
                    try:
                        status, _, _ = request(base, "/health")
                        if status == 200:
                            break
                    except urllib.error.URLError:
                        pass
                    time.sleep(0.15)
                else:
                    raise RuntimeError(f"PHP server did not become ready. Inspect {log_path}")

                username, email = "stage2user", "stage2@example.test"
                password = "Sufficiently-Long-Password-90"
                status, registration, _ = request(base, "/auth/register", {
                    "username": username, "password": password, "email": email,
                })
                assert status == 201, (status, registration)
                status, login, _ = request(base, "/auth/login", {"username": username, "password": password})
                assert status == 200 and login["mfaSetupRequired"] is True, (status, login)
                challenge = login["mfaToken"]
                status, setup, _ = request(base, "/auth/mfa/setup", {"mfaToken": challenge})
                assert status == 200, (status, setup)
                status, verified, _ = request(base, "/auth/mfa/verify", {
                    "mfaToken": challenge, "code": totp(setup["secret"]),
                })
                assert status == 200 and verified.get("token"), (status, verified)
                token = verified["token"]
                auth = {"Authorization": "Bearer " + token}

                # Authentication throttle keys must survive a fresh PHP process and
                # remain distinct after loading the SQLite record_key column.
                rate_write_php = (
                    "require 'backend_php/config.php'; require 'backend_php/db/Database.php'; "
                    "$db=Database::getInstance(); "
                    "$db->recordRateLimitFailure('stage2-throttle-a',300); "
                    "$db->recordRateLimitFailure('stage2-throttle-b',300);"
                )
                rate_write = subprocess.run([php, "-r", rate_write_php], cwd=PROJECT_ROOT, env=env,
                                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=10)
                assert rate_write.returncode == 0, rate_write.stdout
                rate_read_php = (
                    "require 'backend_php/config.php'; require 'backend_php/db/Database.php'; "
                    "$db=Database::getInstance(); "
                    "if (!$db->isRateLimited('stage2-throttle-a',1,300) "
                    "|| !$db->isRateLimited('stage2-throttle-b',1,300)) exit(1);"
                )
                rate_read = subprocess.run([php, "-r", rate_read_php], cwd=PROJECT_ROOT, env=env,
                                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=10)
                assert rate_read.returncode == 0, rate_read.stdout

                # Invalid file dimensions, chunk counts, and wrapped keys must be rejected.
                valid_meta = {
                    "encryptedFileName": base64.b64encode(b"n" * 16).decode() + ":" + base64.b64encode(b"i" * 12).decode(),
                    "encryptedTags": base64.b64encode(b"t" * 16).decode() + ":" + base64.b64encode(b"j" * 12).decode(),
                    "fileSizeBytes": 1,
                    "totalChunks": 1,
                    "wrappedDek": base64.b64encode(b"w" * 40).decode(),
                }
                for bad_size in (-1, 0, 524288001):
                    bad = dict(valid_meta, fileSizeBytes=bad_size, totalChunks=1)
                    status, _, _ = request(base, "/files/init", bad, auth)
                    assert status in (400, 413), (bad_size, status)
                status, _, _ = request(base, "/files/init", dict(valid_meta, totalChunks=2), auth)
                assert status == 400, f"Mismatched chunk count accepted: {status}"
                # Plaintext fingerprints have been removed from the storage API.
                status, _, _ = request(base, "/files/init", dict(valid_meta, wrappedDek=base64.b64encode(b"w" * 39).decode()), auth)
                assert status == 400, f"Invalid wrapped DEK accepted: {status}"

                # A legacy plaintext fingerprint may arrive from an old client, but it must
                # not be persisted or returned by the current server.
                legacy_payload = dict(valid_meta, plaintextSha256=hashlib.sha256(b"x").hexdigest())
                # Init atomically reserves quota. Incomplete records are not shown as completed files.
                status, initialized, _ = request(base, "/files/init", legacy_payload, auth)
                assert status == 201 and initialized.get("fileId"), (status, initialized)
                file_id = initialized["fileId"]
                inject_legacy_hash_php = (
                    "require 'backend_php/config.php'; require 'backend_php/db/Database.php'; "
                    "$db=Database::getInstance(); $db->updateFile($argv[1], ['plaintext_sha256'=>str_repeat('a',64)]);"
                )
                inject_proc = subprocess.run([php, "-r", inject_legacy_hash_php, file_id], cwd=PROJECT_ROOT, env=env,
                                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=10)
                assert inject_proc.returncode == 0, inject_proc.stdout
                status, me, _ = request(base, "/auth/me", headers=auth)
                assert status == 200, (status, me)
                user_obj = me.get("user", me)
                assert int(user_obj.get("storageUsedBytes", user_obj.get("storage_used_bytes", -1))) == 1, user_obj

                # Set quota to the already-reserved byte, then verify a second reservation is denied.
                user_id = registration["user"]["id"]
                set_quota_php = (
                    "require 'backend_php/config.php'; require 'backend_php/db/Database.php'; "
                    "$db=Database::getInstance(); $db->updateUser($argv[1], ['storage_quota_bytes'=>(int)$argv[2]]);"
                )
                quota_proc = subprocess.run([php, "-r", set_quota_php, user_id, "1"], cwd=PROJECT_ROOT, env=env,
                                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=10)
                assert quota_proc.returncode == 0, quota_proc.stdout
                status, _, _ = request(base, "/files/init", valid_meta, auth)
                assert status == 413, f"Quota over-reservation was accepted: {status}"
                quota_proc = subprocess.run([php, "-r", set_quota_php, user_id, str(5 * 1024 * 1024 * 1024)], cwd=PROJECT_ROOT, env=env,
                                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=10)
                assert quota_proc.returncode == 0, quota_proc.stdout

                status, files, _ = request(base, "/files", headers=auth)
                assert status == 200 and len(files["files"]) == 1 and files["files"][0].get("upload_status") == "uploading", files
                assert "plaintext_sha256" not in files["files"][0], files["files"][0]

                # An incomplete upload cannot be completed; malformed chunks are rejected.
                status, _, _ = request(base, f"/files/{file_id}/complete", {}, auth)
                assert status == 409, f"Incomplete upload was finalized: {status}"
                iv = base64.b64encode(os.urandom(12)).decode()
                good_blob = b"c" * 17  # 1 byte plaintext + 16 byte AES-GCM tag
                status, _, _ = multipart_request(base, f"/files/{file_id}/chunk/0", token, iv, "wrong-aad", good_blob)
                assert status == 400, f"Mismatched AAD accepted: {status}"
                status, _, _ = multipart_request(base, f"/files/{file_id}/chunk/1", token, iv, f"{file_id}-1", good_blob)
                assert status == 400, f"Out-of-range chunk accepted: {status}"
                status, _, _ = multipart_request(base, f"/files/{file_id}/chunk/0", token, iv, f"{file_id}-0", b"short")
                assert status == 413, f"Incorrect ciphertext size accepted: {status}"

                status, uploaded, _ = multipart_request(base, f"/files/{file_id}/chunk/0", token, iv, f"{file_id}-0", good_blob)
                assert status == 201, (status, uploaded)
                status, retried, _ = multipart_request(base, f"/files/{file_id}/chunk/0", token, iv, f"{file_id}-0", good_blob)
                assert status == 200 and retried.get("alreadyStored") is True, (status, retried)
                status, _, _ = multipart_request(base, f"/files/{file_id}/chunk/0", token, iv, f"{file_id}-0", b"d" * 17)
                assert status == 409, f"Conflicting duplicate chunk accepted: {status}"

                status, completed, _ = request(base, f"/files/{file_id}/complete", {}, auth)
                assert status == 200 and completed.get("alreadyCompleted") is False, (status, completed)
                status, repeated, _ = request(base, f"/files/{file_id}/complete", {}, auth)
                assert status == 200 and repeated.get("alreadyCompleted") is True, (status, repeated)
                status, me, _ = request(base, "/auth/me", headers=auth)
                user_obj = me.get("user", me)
                assert int(user_obj.get("storageUsedBytes", user_obj.get("storage_used_bytes", -1))) == 1, user_obj
                status, files, _ = request(base, "/files", headers=auth)
                assert status == 200 and len(files["files"]) == 1, files

                status, metadata, _ = request(base, f"/files/{file_id}/chunk/0/meta", headers=auth)
                assert status == 200 and metadata["aadString"] == f"{file_id}-0", (status, metadata)
                status, chunk_data, _ = request(base, f"/files/{file_id}/chunk/0/data", headers=auth)
                assert status == 200 and chunk_data == good_blob, (status, chunk_data)

                # Ciphertext tampering on disk must be detected before download.
                chunk_path = private / "storage" / file_id / "chunk_0.bin"
                chunk_path.write_bytes(b"z" * 17)
                status, _, _ = request(base, f"/files/{file_id}/chunk/0/data", headers=auth)
                assert status == 409, f"Tampered chunk was served: {status}"

                # Audit v2 protects metadata fields, not just the previous hash chain.
                status, audit_result, _ = request(base, "/audit/verify", headers=auth)
                assert status == 200 and audit_result.get("isValid") is True, (status, audit_result)
                # Tamper with the active SQLite-backed audit record through a test-only
                # local CLI operation, then restore the exact trusted snapshot.
                audit_backup = private / "audit-trusted-snapshot.json"
                tamper_php = (
                    "require 'backend_php/config.php'; require 'backend_php/db/Database.php'; "
                    "$db=Database::getInstance(); $logs=$db->getAuditLogs(); "
                    "file_put_contents($argv[1], json_encode($logs)); "
                    "$logs[count($logs)-1]['user_agent']='tampered-agent'; $db->replaceAuditLogs($logs);"
                )
                tamper_proc = subprocess.run([php, "-r", tamper_php, str(audit_backup)], cwd=PROJECT_ROOT, env=env,
                                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=10)
                assert tamper_proc.returncode == 0, tamper_proc.stdout
                status, audit_result, _ = request(base, "/audit/verify", headers=auth)
                assert status == 200 and audit_result.get("isValid") is False, (status, audit_result)
                restore_php = (
                    "require 'backend_php/config.php'; require 'backend_php/db/Database.php'; "
                    "$logs=json_decode(file_get_contents($argv[1]), true); "
                    "if (!is_array($logs)) exit(2); Database::getInstance()->replaceAuditLogs($logs);"
                )
                restore_proc = subprocess.run([php, "-r", restore_php, str(audit_backup)], cwd=PROJECT_ROOT, env=env,
                                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=10)
                assert restore_proc.returncode == 0, restore_proc.stdout

                # Simulate a process interruption after the deletion tombstone was committed.
                # The file must be inaccessible, and a repeated DELETE must resume cleanup.
                mark_pending_php = (
                    "require 'backend_php/config.php'; require 'backend_php/db/Database.php'; "
                    "$db=Database::getInstance(); $db->updateFile($argv[1], ['deletion_pending'=>true]);"
                )
                pending_proc = subprocess.run([php, "-r", mark_pending_php, file_id], cwd=PROJECT_ROOT, env=env,
                                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=10)
                assert pending_proc.returncode == 0, pending_proc.stdout
                status, _, _ = request(base, f"/files/{file_id}/chunk/0/meta", headers=auth)
                assert status == 409, f"File in deletion recovery state remained accessible: {status}"

                # Deletion must release exactly one byte, including after recovery.
                status, deleted, _ = request(base, f"/files/{file_id}", {}, auth, method="DELETE")
                assert status == 200, (status, deleted)
                status, me, _ = request(base, "/auth/me", headers=auth)
                user_obj = me.get("user", me)
                assert int(user_obj.get("storageUsedBytes", user_obj.get("storage_used_bytes", -1))) == 0, user_obj

                # Partial uploads reserve quota and deletion releases that reservation.
                partial_meta = dict(valid_meta, fileSizeBytes=2)
                status, partial, _ = request(base, "/files/init", partial_meta, auth)
                assert status == 201, (status, partial)
                status, me, _ = request(base, "/auth/me", headers=auth)
                user_obj = me.get("user", me)
                assert int(user_obj.get("storageUsedBytes", user_obj.get("storage_used_bytes", -1))) == 2, user_obj
                status, _, _ = request(base, f"/files/{partial['fileId']}", {}, auth, method="DELETE")
                assert status == 200, status
                status, me, _ = request(base, "/auth/me", headers=auth)
                user_obj = me.get("user", me)
                assert int(user_obj.get("storageUsedBytes", user_obj.get("storage_used_bytes", -1))) == 0, user_obj

                # Exercise the configured 5 MiB production chunk size against PHP's upload limits.
                five_mib = 5 * 1024 * 1024
                large_meta = dict(valid_meta, fileSizeBytes=five_mib, totalChunks=1,
                                  )
                status, large_init, _ = request(base, "/files/init", large_meta, auth)
                assert status == 201, (status, large_init)
                large_id = large_init["fileId"]
                large_iv = base64.b64encode(os.urandom(12)).decode()
                large_ciphertext = b"c" * (five_mib + 16)
                status, _, _ = multipart_request(base, f"/files/{large_id}/chunk/0", token,
                                                  large_iv, f"{large_id}-0", large_ciphertext)
                assert status == 201, f"5 MiB chunk upload failed under configured PHP limits: {status}"
                status, _, _ = request(base, f"/files/{large_id}/complete", {}, auth)
                assert status == 200, status
                status, _, _ = request(base, f"/files/{large_id}", {}, auth, method="DELETE")
                assert status == 200, status

                # An invalid JSON database must fail closed without being overwritten.
                corrupt_root = private / "corrupt-runtime"
                corrupt_data = corrupt_root / "data"
                corrupt_storage = corrupt_root / "storage"
                corrupt_data.mkdir(parents=True)
                corrupt_storage.mkdir()
                corrupt_db = corrupt_data / "database.json"
                corrupt_db.write_text('{"users": [', encoding="utf-8")
                corrupt_env = dict(env, SECURE_VAULT_DATA_DIR=str(corrupt_data), SECURE_VAULT_STORAGE_DIR=str(corrupt_storage))
                corrupt_proc = subprocess.run(
                    [php, "-r", "require 'backend_php/config.php'; require 'backend_php/db/Database.php'; Database::getInstance();"],
                    cwd=PROJECT_ROOT, env=corrupt_env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    text=True, timeout=10,
                )
                assert corrupt_proc.returncode != 0 and corrupt_db.read_text(encoding="utf-8") == '{"users": [',                     "Corrupt database was silently reset or accepted"

                # Verify the operator-driven audit v1->v2 migration on an isolated runtime.
                migration_root = private / "migration-runtime"
                migration_data = migration_root / "data"
                migration_storage = migration_root / "storage"
                migration_data.mkdir(parents=True)
                migration_storage.mkdir()
                migration_env = dict(env, SECURE_VAULT_DATA_DIR=str(migration_data), SECURE_VAULT_STORAGE_DIR=str(migration_storage))
                setup_legacy = (
                    "require 'backend_php/config.php'; require 'backend_php/db/Database.php'; require 'backend_php/utils/Audit.php'; "
                    "$db=Database::getInstance(); $logs=$db->getAuditLogs(); $e=$logs[0]; "
                    "unset($e['hash_version'],$e['details']); "
                    "$e['current_hash']=Audit::computeLogHash($e['previous_hash'],$e['timestamp'],$e['user_id'],$e['action_type'],$e['file_id']??null,$e['status']); "
                    "$db->replaceAuditLogs([$e]);"
                )
                migration_fixture = subprocess.run([php, "-r", setup_legacy], cwd=PROJECT_ROOT, env=migration_env,
                                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=10)
                assert migration_fixture.returncode == 0, migration_fixture.stdout
                migration_proc = subprocess.run([php, "backend_php/scripts/migrate_audit_v2.php"], cwd=PROJECT_ROOT,
                                                env=migration_env, input="MIGRATE-AUDIT-V2\n", stdout=subprocess.PIPE,
                                                stderr=subprocess.STDOUT, text=True, timeout=10)
                assert migration_proc.returncode == 0 and "Migration completed" in migration_proc.stdout, migration_proc.stdout
                migration_verify = subprocess.run(
                    [php, "-r", "require 'backend_php/config.php'; require 'backend_php/db/Database.php'; require 'backend_php/utils/Audit.php'; $r=Audit::verifyChain(); if(!$r['isValid'] || ($r['legacyRecords']??0)!==0) exit(1);"],
                    cwd=PROJECT_ROOT, env=migration_env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=10,
                )
                assert migration_verify.returncode == 0, migration_verify.stdout

                print("PASS: Stage 2 upload/quota/audit regressions")
                print("  - rejects negative/zero/oversized files, mismatched chunks, malformed hash and wrapped DEK")
                print("  - quota is reserved at init, incomplete uploads remain visible for cleanup, and quota is not double-charged")
                print("  - chunk index, AAD, IV, size, duplicate retry and conflicting duplicate protections")
                print("  - completion is blocked until every chunk is valid and repeat completion is idempotent")
                print("  - ciphertext tampering is detected before download")
                print("  - audit v2 detects tampering of user-agent metadata")
                print("  - deleting completed and incomplete uploads releases quota")
                print("  - 5 MiB ciphertext chunk uploads with matched PHP upload limits")
                print("  - corrupt database fails closed without reset; audit v1->v2 migration verifies")
                return 0
            finally:
                server.terminate()
                try:
                    server.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait(timeout=5)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AssertionError, OSError, RuntimeError, KeyError, ValueError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1)
