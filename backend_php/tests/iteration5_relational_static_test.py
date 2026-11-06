from pathlib import Path

root = Path(__file__).resolve().parents[2]
db = (root / 'backend_php/db/Database.php').read_text()
schema = (root / 'backend_php/db/schema_sqlite.sql').read_text()

required_tables = [
    'users', 'vault_profiles', 'encrypted_files',
    'file_chunks', 'audit_logs', 'auth_rate_limits'
]
for table in required_tables:
    assert f'CREATE TABLE IF NOT EXISTS {table}' in schema, f'missing relational table: {table}'
    assert f"'{table}' => '{table}'" in db or f"case '{table}':" in db, f'missing adapter mapping: {table}'

assert 'PRAGMA user_version = 2' in db, 'schema version migration missing'
assert 'DROP TABLE vault_records' in db, 'legacy table cleanup missing after migration'
assert 'Ambiguous database state' in db, 'ambiguous dual-schema state must fail closed'
assert 'createRelationalMigrationBackup' in db and 'VACUUM INTO' in db, 'pre-migration snapshot is missing'
assert 'ON CONFLICT(id) DO UPDATE' in db, 'entity UPSERT statements missing'
assert 'ON CONFLICT(user_id) DO UPDATE' in db, 'vault profile UPSERT missing'
assert 'ON CONFLICT(record_key) DO UPDATE' in db, 'rate limit UPSERT missing'
assert "['file_chunks','encrypted_files','vault_profiles','users','audit_logs','auth_rate_limits']" in db
assert "['users','vault_profiles','encrypted_files','file_chunks','audit_logs','auth_rate_limits']" in db
assert 'FOREIGN KEY' in schema and 'UNIQUE (file_id, chunk_index)' in schema
preflight = (root / 'backend_php/scripts/production_readiness.php').read_text()
assert 'relational_schema_version' in preflight and 'foreign_key_violations' in preflight
assert 'legacy_generic_table_absent' in preflight
assert 'plaintext_sha256' in db and "unset($record['plaintext_sha256'])" in db
assert 'Duplicate record identity detected' in db, 'duplicate in-memory keys must fail closed'

print('ITERATION 5 RELATIONAL STATIC TEST: PASS')
print('- Six dedicated entity tables are defined and mapped.')
print('- Versioned transactional migration and ambiguous-state guard exist.')
print('- FK-safe delete/insert ordering and indexed UPSERT paths exist.')
print('- Legacy plaintext fingerprint is stripped during migration.')
