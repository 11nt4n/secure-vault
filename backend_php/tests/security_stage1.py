#!/usr/bin/env python3
"""Stage 1 security regression test; uses only the Python standard library and PHP CLI."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import socket
import sqlite3
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


def request(base: str, path: str, payload=None, headers=None):
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    actual_headers = {"Content-Type": "application/json"}
    actual_headers.update(headers or {})
    req = urllib.request.Request(
        base + path,
        data=data,
        headers=actual_headers,
        method="POST" if data is not None else "GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            raw = response.read()
            parsed = json.loads(raw) if raw else {}
            return response.status, parsed, response.headers
    except urllib.error.HTTPError as error:
        raw = error.read()
        try:
            parsed = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            parsed = {"raw": raw.decode("utf-8", errors="replace")}
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

    with tempfile.TemporaryDirectory(prefix="secure-vault-stage1-") as temporary:
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
        # RFC 6238 SHA-1 vector: time 59s, 6-digit HOTP/TOTP is 287082.
        vector = subprocess.run(
            [php, "-r", "require 'backend_php/utils/Totp.php'; exit(Totp::verify('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ','287082',59,0) ? 0 : 1);"],
            cwd=PROJECT_ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=10,
        )
        assert vector.returncode == 0, f"RFC 6238 TOTP vector failed: {vector.stdout}"

        log_path = private / "server.log"
        with log_path.open("w", encoding="utf-8") as log:
            server = subprocess.Popen(
                [php, "-S", f"127.0.0.1:{port}", "-t", "backend_php", "backend_php/index.php"],
                cwd=PROJECT_ROOT,
                env=env,
                stdout=log,
                stderr=subprocess.STDOUT,
            )
            base = f"http://127.0.0.1:{port}/api"
            try:
                for _ in range(60):
                    if server.poll() is not None:
                        raise RuntimeError(f"PHP server stopped unexpectedly. Inspect {log_path}")
                    try:
                        status, _, _ = request(base, "/health")
                        if status == 200:
                            break
                    except urllib.error.URLError:
                        pass
                    time.sleep(0.15)
                else:
                    raise RuntimeError(f"PHP server did not become ready. Inspect {log_path}")

                # Weak passwords are rejected.
                status, body, _ = request(base, "/auth/register", {
                    "username": "stage1user", "password": "short", "email": "stage1@example.test"
                })
                assert status == 400, (status, body)

                # Client-supplied role=admin must not elevate privilege.
                password = "Sufficiently-Long-Password-90"
                status, body, _ = request(base, "/auth/register", {
                    "username": "stage1user", "password": password,
                    "email": "stage1@example.test", "role": "admin"
                })
                assert status == 201 and body["user"]["role"] == "user", (status, body)

                status, login, _ = request(base, "/auth/login", {
                    "username": "stage1user", "password": password
                })
                assert status == 200 and login["mfaSetupRequired"] is True, (status, login)
                challenge = login["mfaToken"]
                challenge_records = json.loads((private / "data" / "mfa_tokens.json").read_text(encoding="utf-8"))
                remaining_challenge = int(challenge_records[challenge]["expiresAt"]) - int(time.time())
                assert 1180 <= remaining_challenge <= 1200, f"MFA challenge TTL is not 20 minutes: {remaining_challenge}s"

                status, setup, _ = request(base, "/auth/mfa/setup", {"mfaToken": challenge})
                assert status == 200 and setup["otpauthUri"].startswith("otpauth://totp/"), (status, setup)

                good_code = totp(setup["secret"])
                wrong_code = "000000" if good_code != "000000" else "000001"
                status, _, _ = request(base, "/auth/mfa/verify", {
                    "mfaToken": challenge, "code": wrong_code
                })
                assert status == 400, "Incorrect TOTP was accepted"

                status, verified, _ = request(base, "/auth/mfa/verify", {
                    "mfaToken": challenge, "code": good_code
                })
                assert status == 200 and verified["token"], (status, verified)
                assert verified["user"]["mfaEnabled"] is True

                def jwt_payload(token: str) -> dict:
                    encoded = token.split(".")[1]
                    encoded += "=" * ((4 - len(encoded) % 4) % 4)
                    return json.loads(base64.urlsafe_b64decode(encoded.encode("ascii")))

                initial_claims = jwt_payload(verified["token"])
                assert initial_claims["exp"] - initial_claims["iat"] == 8 * 60 * 60

                auth = {"Authorization": "Bearer " + verified["token"]}
                status, me, refreshed_headers = request(base, "/auth/me", headers={**auth, "Origin": "http://localhost:5173"})
                assert status == 200 and me["user"]["id"] == verified["user"]["id"], (status, me)
                refreshed_token = refreshed_headers.get("X-Secure-Vault-Token")
                assert refreshed_token, "Authenticated API response did not rotate the JWT"
                refreshed_claims = jwt_payload(refreshed_token)
                assert refreshed_claims["exp"] - refreshed_claims["iat"] == 8 * 60 * 60
                assert "X-Secure-Vault-Token" in refreshed_headers.get("Access-Control-Expose-Headers", "")
                auth = {"Authorization": "Bearer " + refreshed_token}

                status, _, _ = request(base, "/admin/users", headers=auth)
                assert status == 403, f"Normal user received admin access: {status}"

                # Verify TOTP shared secret is encrypted at rest and password hash is slow-hash format.
                relational_tables = [
                    "users", "vault_profiles", "encrypted_files", "file_chunks",
                    "audit_logs", "auth_rate_limits",
                ]
                with sqlite3.connect(private / "data" / "secure-vault.sqlite") as connection:
                    persisted_records = []
                    for table in relational_tables:
                        rows = connection.execute(f"SELECT payload FROM {table}").fetchall()
                        persisted_records.extend((table, json.loads(payload)) for (payload,) in rows)
                users = [record for table, record in persisted_records if table == "users"]
                user = users[0]
                assert setup["secret"] not in json.dumps(persisted_records), "TOTP secret leaked in plaintext to database"
                assert user["mfa_secret_encrypted"], "No encrypted TOTP secret stored"
                assert user["password_hash"].startswith("$argon2id$") or user["password_hash"].startswith("$2"), user["password_hash"]

                status, login_again, _ = request(base, "/auth/login", {
                    "username": "stage1user", "password": password
                })
                assert status == 200 and login_again["mfaSetupRequired"] is False
                status, _, _ = request(base, "/auth/mfa/verify", {
                    "mfaToken": login_again["mfaToken"], "code": good_code
                })
                assert status == 400, "A previously accepted TOTP code was replayed successfully"

                # Administrator privilege must require a trusted CLI operation.
                promotion = subprocess.run(
                    [php, "backend_php/scripts/promote_admin.php", "stage1user"],
                    cwd=PROJECT_ROOT, env=env, input="stage1user\n", text=True,
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=10,
                )
                assert promotion.returncode == 0, promotion.stdout
                status, admin_login, _ = request(base, "/auth/login", {
                    "username": "stage1user", "password": password
                })
                assert status == 200 and admin_login["mfaSetupRequired"] is False
                # A code from the next time step may be accepted within the configured +1 window.
                admin_code = totp(setup["secret"], int(time.time()) + 30)
                status, admin_session, _ = request(base, "/auth/mfa/verify", {
                    "mfaToken": admin_login["mfaToken"], "code": admin_code
                })
                assert status == 200 and admin_session["user"]["role"] == "admin", (status, admin_session)
                status, admin_users, _ = request(base, "/admin/users", headers={"Authorization": "Bearer " + admin_session["token"]})
                assert status == 200 and len(admin_users["users"]) == 1, (status, admin_users)

                # Reject JWTs missing mandatory exp/iat claims even when correctly signed.
                def b64url(value: bytes) -> str:
                    return base64.urlsafe_b64encode(value).decode().rstrip("=")
                header = b64url(b'{"alg":"HS256","typ":"JWT"}')
                payload = b64url(json.dumps({"id": user["id"]}).encode())
                signing_input = f"{header}.{payload}"
                signature = b64url(hmac.new(env["JWT_SECRET"].encode(), signing_input.encode(), hashlib.sha256).digest())
                invalid_token = signing_input + "." + signature
                status, _, _ = request(base, "/auth/me", headers={"Authorization": "Bearer " + invalid_token})
                assert status == 401, f"JWT without exp/iat was accepted: {status}"

                # Arbitrary web origins must not receive CORS read permission.
                status, _, cors_headers = request(base, "/health", headers={"Origin": "https://attacker.example"})
                assert "Access-Control-Allow-Origin" not in cors_headers

                print("PASS: Stage 1 API security regressions")
                print("  - user registration ignores role=admin and rejects weak passwords")
                print("  - RFC 6238 vector, real TOTP enrollment, wrong-code rejection, and replay prevention")
                print("  - 20-minute MFA challenge and 8-hour sliding JWT renewal")
                print("  - MFA secret encrypted at rest and password stored with a slow hash")
                print("  - non-admin blocked; administrator promotion works only through CLI")
                print("  - malformed JWT rejected")
                print("  - arbitrary CORS origin is not reflected")
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
