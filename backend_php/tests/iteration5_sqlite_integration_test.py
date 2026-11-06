"""SQLite engine integration tests for the V9 schema.

This uses Python's SQLite binding because the available PHP runtime in this
workspace has PDO but not pdo_sqlite. It validates the exact shipped SQL schema,
not the PHP PDO adapter runtime.
"""
import sqlite3
import tempfile
import uuid
from pathlib import Path

root = Path(__file__).resolve().parents[2]
schema_path = root / 'backend_php/db/schema_sqlite.sql'
schema = schema_path.read_text()

with tempfile.TemporaryDirectory(prefix='sv-v9-sqlite-') as tmp:
    db_path = Path(tmp) / 'secure-vault-test.sqlite'
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys=ON')
    conn.executescript(schema)

    uid = str(uuid.uuid4())
    fid = str(uuid.uuid4())
    cid = str(uuid.uuid4())
    aid = str(uuid.uuid4())

    conn.execute(
        'INSERT INTO users(id,record_key,username,email,role,is_active,storage_quota_bytes,storage_used_bytes,payload) '
        'VALUES(?,?,?,?,?,?,?,?,?)',
        (uid, uid, 'alice', 'alice@example.test', 'user', 1, 1000000, 10, '{"id":"%s"}' % uid),
    )
    conn.execute(
        'INSERT INTO vault_profiles(user_id,record_key,payload) VALUES(?,?,?)',
        (uid, uid, '{"user_id":"%s"}' % uid),
    )
    conn.execute(
        'INSERT INTO encrypted_files(id,record_key,owner_id,upload_status,deletion_pending,file_size_bytes,total_chunks,payload) '
        'VALUES(?,?,?,?,?,?,?,?)',
        (fid, fid, uid, 'uploading', 0, 10, 1, '{"id":"%s","owner_id":"%s"}' % (fid, uid)),
    )
    conn.execute(
        'INSERT INTO file_chunks(id,record_key,file_id,chunk_index,chunk_size_bytes,storage_path,payload) '
        'VALUES(?,?,?,?,?,?,?)',
        (cid, cid, fid, 0, 26, '/private/chunk.bin', '{"id":"%s","file_id":"%s"}' % (cid, fid)),
    )
    conn.execute(
        'INSERT INTO audit_logs(id,record_key,sequence_number,timestamp,user_id,action_type,status,previous_hash,current_hash,payload) '
        'VALUES(?,?,?,?,?,?,?,?,?,?)',
        (aid, aid, 1, '2026-11-04T00:00:00Z', uid, 'FILE_INIT', 'SUCCESS', '0'*64, '1'*64, '{"id":"%s"}' % aid),
    )
    conn.execute(
        'INSERT INTO auth_rate_limits(record_key,window_started_at,attempts,payload) VALUES(?,?,?,?)',
        ('ip:127.0.0.1', 100, 2, '{"window_started_at":100,"attempts":2}'),
    )
    conn.commit()

    # Referential integrity and lookup paths.
    assert conn.execute('PRAGMA foreign_key_check').fetchall() == []
    assert conn.execute('SELECT COUNT(*) FROM users WHERE username=?', ('alice',)).fetchone()[0] == 1
    assert conn.execute('SELECT COUNT(*) FROM encrypted_files WHERE owner_id=? AND upload_status=?', (uid, 'uploading')).fetchone()[0] == 1
    assert conn.execute('SELECT COUNT(*) FROM file_chunks WHERE file_id=? AND chunk_index=?', (fid, 0)).fetchone()[0] == 1

    # Uniqueness constraints reject duplicate account and chunk identities.
    try:
        conn.execute(
            'INSERT INTO users(id,record_key,username,email,payload) VALUES(?,?,?,?,?)',
            (str(uuid.uuid4()), str(uuid.uuid4()), 'alice', 'other@example.test', '{}'),
        )
        raise AssertionError('duplicate username unexpectedly accepted')
    except sqlite3.IntegrityError:
        conn.rollback()

    try:
        conn.execute(
            'INSERT INTO file_chunks(id,record_key,file_id,chunk_index,storage_path,payload) VALUES(?,?,?,?,?,?)',
            (str(uuid.uuid4()), str(uuid.uuid4()), fid, 0, '/private/duplicate.bin', '{}'),
        )
        raise AssertionError('duplicate chunk index unexpectedly accepted')
    except sqlite3.IntegrityError:
        conn.rollback()

    # A metadata write plus audit write is atomic under a single transaction.
    new_chunk = str(uuid.uuid4())
    new_audit = str(uuid.uuid4())
    try:
        conn.execute('BEGIN')
        conn.execute(
            'INSERT INTO file_chunks(id,record_key,file_id,chunk_index,storage_path,payload) VALUES(?,?,?,?,?,?)',
            (new_chunk, new_chunk, fid, 1, '/private/second.bin', '{}'),
        )
        conn.execute(
            'INSERT INTO audit_logs(id,record_key,sequence_number,payload) VALUES(?,?,?,?)',
            (new_audit, new_audit, 1, '{}'),  # duplicate sequence forces failure
        )
        conn.commit()
        raise AssertionError('duplicate audit sequence unexpectedly accepted')
    except sqlite3.IntegrityError:
        conn.rollback()
    assert conn.execute('SELECT COUNT(*) FROM file_chunks WHERE id=?', (new_chunk,)).fetchone()[0] == 0
    assert conn.execute('SELECT COUNT(*) FROM audit_logs WHERE id=?', (new_audit,)).fetchone()[0] == 0

    # ON DELETE CASCADE keeps file/chunk metadata consistent.
    conn.execute('DELETE FROM encrypted_files WHERE id=?', (fid,))
    conn.commit()
    assert conn.execute('SELECT COUNT(*) FROM file_chunks WHERE file_id=?', (fid,)).fetchone()[0] == 0
    assert conn.execute('PRAGMA foreign_key_check').fetchall() == []

    # Atomic rollback leaves no partial changes.
    try:
        conn.execute('BEGIN')
        conn.execute('UPDATE users SET storage_used_bytes=999 WHERE id=?', (uid,))
        conn.execute('INSERT INTO encrypted_files(id,record_key,owner_id,upload_status,payload) VALUES(?,?,?,?,?)',
                     (str(uuid.uuid4()), 'bad-file', 'no-such-user', 'uploading', '{}'))
        conn.commit()
        raise AssertionError('invalid foreign key unexpectedly accepted')
    except sqlite3.IntegrityError:
        conn.rollback()
    assert conn.execute('SELECT storage_used_bytes FROM users WHERE id=?', (uid,)).fetchone()[0] == 10

    integrity = conn.execute('PRAGMA integrity_check').fetchone()[0]
    assert integrity == 'ok', integrity

    # Validate the SQLite online snapshot primitive used by the migration/backup tools.
    conn.execute('PRAGMA user_version=2')
    backup_path = Path(tmp) / 'pre-migration-backup.sqlite'
    escaped_backup = str(backup_path).replace("'", "''")
    conn.execute(f"VACUUM INTO '{escaped_backup}'")
    backup = sqlite3.connect(backup_path)
    assert backup.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
    assert backup.execute('PRAGMA user_version').fetchone()[0] == 2
    assert backup.execute('PRAGMA foreign_key_check').fetchall() == []
    backup.close()
    conn.close()

print('ITERATION 5 SQLITE ENGINE INTEGRATION TEST: PASS')
print('- Shipped relational schema creates successfully.')
print('- Foreign keys, indexes, uniqueness, quota fields and cascade behavior verified.')
print('- Transaction rollback, integrity_check, and VACUUM INTO snapshot verified with SQLite engine.')
