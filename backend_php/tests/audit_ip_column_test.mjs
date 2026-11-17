/**
 * Test Suite: audit_ip_column_test.mjs
 * Memverifikasi implementasi Perbaikan 2:
 * 1. Kolom Alamat IP pada Jejak Audit menampilkan alamat IP (IPv4 & IPv6).
 * 2. Username / user_id TIDAK LAGI ditampilkan pada kolom tersebut.
 * 3. Fallback 'Tidak tersedia' muncul saat ip_address bernilai null, undefined, atau string kosong.
 * 4. Header tabel menampilkan 'Alamat IP'.
 * 5. Riwayat log multi-versi (V1, V2, V3) dirender tanpa error.
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, '../..');
const appJsPath = path.join(projectRoot, 'frontend/js/app.js');

let passedTests = 0;
let failedTests = 0;

function assertCondition(condition, testName, detail = '') {
  if (condition) {
    passedTests++;
    console.log(`  [PASS] ${testName}`);
  } else {
    failedTests++;
    console.error(`  [FAIL] ${testName} - ${detail}`);
  }
}

console.log('========================================================');
console.log('  SECURE VAULT AUDIT IP COLUMN VERIFICATION TEST       ');
console.log('========================================================\n');

// 1. Baca source code app.js
const appJs = fs.readFileSync(appJsPath, 'utf8');

// Verifikasi Statis Header & Rendering Regex
assertCondition(
  appJs.includes('<th scope="col">Alamat IP</th>'),
  '1. Header tabel Jejak Audit menggunakan label "Alamat IP"'
);

assertCondition(
  !appJs.includes('<th scope="col">Pengguna / IP</th>') && !appJs.includes('<th scope="col">Pengguna/IP</th>'),
  '2. Header lama "Pengguna / IP" sudah tidak ada lagi'
);

assertCondition(
  appJs.includes('${esc(log.ip_address || \'Tidak tersedia\')}'),
  '3. Rendering sel menggunakan esc(log.ip_address || \'Tidak tersedia\')'
);

assertCondition(
  !appJs.includes('${esc(log.user_id || \'-\')}</span><small class="table-subtext">${esc(log.ip_address || \'-\')}</small>'),
  '4. Format tumpuk username dan IP lama sudah dihapus'
);

// 2. Evaluasi Fungsi Rendering Nyata
// Siapkan sandbox environment untuk mengeksekusi template rendering
const helpers = {
  esc: (v) => String(v ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;'),
  dateText: (ts) => ts || '',
  auditActionLabel: (act) => act || '',
  auditDetailsLabel: (det) => det || '',
  icon: () => '<svg></svg>',
  btn: () => '<button></button>',
  errorBox: () => '',
};

// Buat wrapper runner untuk auditTemplate
const templateFnCode = appJs.match(/function auditTemplate\(\)\s*\{[\s\S]*?\n\}/)[0];
const runnerCode = `
  const state = mockState;
  const { esc, dateText, auditActionLabel, auditDetailsLabel, icon, btn, errorBox } = helpers;
  ${templateFnCode}
  return auditTemplate();
`;

function renderAuditTable(logs) {
  const mockState = {
    audit: {
      logs,
      loading: false,
      action: 'ALL',
      status: 'ALL',
      error: ''
    }
  };
  const fn = new Function('mockState', 'helpers', runnerCode);
  return fn(mockState, helpers);
}

// Dataset uji
const testLogs = [
  {
    sequence_number: 1,
    timestamp: '2026-11-17T01:00:00.000Z',
    user_id: 'super_admin_alice',
    action_type: 'AUTH_LOGIN',
    status: 'SUCCESS',
    ip_address: '192.168.1.10',
    previous_hash: '0'.repeat(64),
    current_hash: 'a'.repeat(64),
    hash_version: 2
  },
  {
    sequence_number: 2,
    timestamp: '2026-11-17T01:05:00.000Z',
    user_id: 'bob_operator',
    action_type: 'FILE_INIT',
    status: 'SUCCESS',
    ip_address: '2001:0db8:85a3:0000:0000:8a2e:0370:7334',
    previous_hash: 'a'.repeat(64),
    current_hash: 'b'.repeat(128),
    hash_version: 3
  },
  {
    sequence_number: 3,
    timestamp: '2026-11-17T01:10:00.000Z',
    user_id: 'charlie_system',
    action_type: 'SYSTEM_MAINTENANCE',
    status: 'SUCCESS',
    ip_address: null,
    previous_hash: 'b'.repeat(128),
    current_hash: 'c'.repeat(128),
    hash_version: 3
  },
  {
    sequence_number: 4,
    timestamp: '2026-11-17T01:15:00.000Z',
    user_id: 'david_user',
    action_type: 'VAULT_LOCK',
    status: 'SUCCESS',
    ip_address: '',
    previous_hash: 'c'.repeat(128),
    current_hash: 'd'.repeat(128),
    hash_version: 3
  }
];

const renderedHtml = renderAuditTable(testLogs);

// Ekstrak semua baris <tr> dalam <tbody>
const tbodyMatch = renderedHtml.match(/<tbody>([\s\S]*?)<\/tbody>/);
assertCondition(!!tbodyMatch, '5. Tabel berhasil merender elemen <tbody>');

const rows = tbodyMatch ? tbodyMatch[1].match(/<tr>([\s\S]*?)<\/tr>/g) || [] : [];
assertCondition(rows.length === 4, `6. Seluruh 4 baris log berhasil dirender (ditemukan: ${rows.length})`);

// Periksa setiap baris secara presisi
function getColumnCells(rowHtml) {
  const cells = rowHtml.match(/<td\b[^>]*>([\s\S]*?)<\/td>/g) || [];
  return cells.map(c => c.replace(/^<td\b[^>]*>|<\/td>$/g, ''));
}

// Baris 1: IPv4
const cellsRow1 = getColumnCells(rows[0] || '');
const ipCol1 = cellsRow1[3] || '';
assertCondition(ipCol1.includes('192.168.1.10'), '7. IPv4 "192.168.1.10" tampil pada kolom Alamat IP');
assertCondition(!ipCol1.includes('super_admin_alice'), '8. Username "super_admin_alice" TIDAK tampil pada kolom Alamat IP');
assertCondition(ipCol1.includes('class="audit-user-id mono"'), '9. Styling monospace (mono) terpasang pada sel Alamat IP');

// Baris 2: IPv6
const cellsRow2 = getColumnCells(rows[1] || '');
const ipCol2 = cellsRow2[3] || '';
assertCondition(ipCol2.includes('2001:0db8:85a3:0000:0000:8a2e:0370:7334'), '10. IPv6 "2001:0db8:85a3:..." tampil pada kolom Alamat IP');
assertCondition(!ipCol2.includes('bob_operator'), '11. Username "bob_operator" TIDAK tampil pada kolom Alamat IP');

// Baris 3: IP null -> Tidak tersedia
const cellsRow3 = getColumnCells(rows[2] || '');
const ipCol3 = cellsRow3[3] || '';
assertCondition(ipCol3.includes('Tidak tersedia'), '12. IP null menampilkan fallback "Tidak tersedia"');
assertCondition(!ipCol3.includes('charlie_system'), '13. Username "charlie_system" TIDAK tampil pada kolom Alamat IP');

// Baris 4: IP string kosong -> Tidak tersedia
const cellsRow4 = getColumnCells(rows[3] || '');
const ipCol4 = cellsRow4[3] || '';
assertCondition(ipCol4.includes('Tidak tersedia'), '14. IP string kosong ("") menampilkan fallback "Tidak tersedia"');
assertCondition(!ipCol4.includes('david_user'), '15. Username "david_user" TIDAK tampil pada kolom Alamat IP');

// Baris 5: XSS sanitasi pada IP
const xssLogs = [{
  sequence_number: 5,
  timestamp: '2026-11-17T02:00:00.000Z',
  user_id: 'attacker',
  action_type: 'AUTH_LOGIN_FAILED',
  status: 'FAILED',
  ip_address: '<script>alert(1)</script>',
  previous_hash: 'd'.repeat(128),
  current_hash: 'e'.repeat(128),
  hash_version: 3
}];
const xssHtml = renderAuditTable(xssLogs);
assertCondition(
  xssHtml.includes('&lt;script&gt;alert(1)&lt;/script&gt;') && !xssHtml.includes('<script>alert(1)</script>'),
  '16. Karakter berbahaya pada alamat IP disanitasi secara aman (XSS protected)'
);

console.log('\n========================================================');
console.log(`  RINGKASAN HASIL TEST: ${passedTests} PASSED, ${failedTests} FAILED`);
console.log('========================================================');

if (failedTests > 0) {
  process.exit(1);
}
process.exit(0);
