/**
 * Test Suite: audit_table_columns_test.mjs
 * Memverifikasi implementasi Perbaikan 3:
 * 1. Header tabel hanya berjumlah lima.
 * 2. Urutan header benar: No., Waktu, Aktivitas, Alamat IP, Status.
 * 3. Header Rantai Hash sudah tidak muncul.
 * 4. Tidak ada rendering previous_hash maupun current_hash pada tabel.
 * 5. Tidak ada teks "Sebelumnya:" dan "Saat ini:" pada tabel.
 * 6. Setiap baris data memiliki tepat lima sel.
 * 7. Kondisi loading menggunakan colspan="5".
 * 8. Kondisi empty state menggunakan colspan="5".
 * 9. Kolom Alamat IP tetap menampilkan IP dengan benar.
 * 10. Kolom Status tetap tampil.
 * 11. Informasi aktivitas tetap tampil.
 * 12. Tidak ada error JavaScript saat rendering.
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
console.log('  SECURE VAULT AUDIT TABLE 5-COLUMN VERIFICATION TEST   ');
console.log('========================================================\n');

// 1. Baca source code app.js
const appJs = fs.readFileSync(appJsPath, 'utf8');

// Sandbox helpers untuk mengeksekusi template rendering
const helpers = {
  esc: (v) => String(v ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;'),
  dateText: (ts) => ts ? '17 Nov 2026, 01:00:00' : '',
  auditActionLabel: (act) => {
    const map = {
      'AUTH_LOGIN': 'Masuk ke akun',
      'FILE_INIT': 'Inisialisasi berkas',
      'SYSTEM_MAINTENANCE': 'Pemeliharaan sistem',
      'VAULT_LOCK': 'Kunci brankas'
    };
    return map[act] || act || 'Aktivitas sistem';
  },
  auditDetailsLabel: (det) => det || '',
  icon: () => '<svg></svg>',
  btn: () => '<button></button>',
  errorBox: () => '',
};

// Ekstrak auditTemplate dari app.js
const templateFnMatch = appJs.match(/function auditTemplate\(\)\s*\{[\s\S]*?\n\}/);
if (!templateFnMatch) {
  console.error('[FATAL] function auditTemplate() tidak ditemukan di app.js');
  process.exit(1);
}

const templateFnCode = templateFnMatch[0];
const runnerCode = `
  const state = mockState;
  const { esc, dateText, auditActionLabel, auditDetailsLabel, icon, btn, errorBox } = helpers;
  ${templateFnCode}
  return auditTemplate();
`;

function renderAuditTable(mockStateOverrides = {}) {
  const defaultState = {
    audit: {
      logs: [],
      loading: false,
      action: 'ALL',
      status: 'ALL',
      error: ''
    }
  };
  const mockState = {
    audit: { ...defaultState.audit, ...mockStateOverrides }
  };
  const fn = new Function('mockState', 'helpers', runnerCode);
  return fn(mockState, helpers);
}

// Dataset uji lengkap (mencakup hash V1/V2 64-hex dan V3 128-hex)
const testLogs = [
  {
    sequence_number: 1,
    timestamp: '2026-11-17T01:00:00.000Z',
    user_id: 'alice_admin',
    action_type: 'AUTH_LOGIN',
    status: 'SUCCESS',
    ip_address: '192.168.1.10',
    details: 'client=web;method=mfa',
    previous_hash: '0'.repeat(64),
    current_hash: 'a1b2c3d4e5f6'.repeat(5) + '1234',
    hash_version: 2
  },
  {
    sequence_number: 2,
    timestamp: '2026-11-17T01:05:00.000Z',
    user_id: 'bob_user',
    action_type: 'FILE_INIT',
    status: 'SUCCESS',
    ip_address: '2001:0db8:85a3:0000:0000:8a2e:0370:7334',
    details: 'name=secret.pdf',
    previous_hash: 'a1b2c3d4e5f6'.repeat(5) + '1234',
    current_hash: '9f8e7d6c5b4a'.repeat(10) + '5678',
    hash_version: 3
  },
  {
    sequence_number: 3,
    timestamp: '2026-11-17T01:10:00.000Z',
    user_id: 'system_daemon',
    action_type: 'SYSTEM_MAINTENANCE',
    status: 'FAILED',
    ip_address: null,
    details: 'reason=timeout',
    previous_hash: '9f8e7d6c5b4a'.repeat(10) + '5678',
    current_hash: 'fedcba9876543210'.repeat(8),
    hash_version: 3
  }
];

// 12 Pemeriksaan Wajib:

// Pengujian 12: Tidak ada error JavaScript saat rendering
let renderedHtml = '';
let renderThrewError = false;
try {
  renderedHtml = renderAuditTable({ logs: testLogs });
} catch (err) {
  renderThrewError = true;
  console.error('Render error:', err);
}
assertCondition(!renderThrewError, '12. Tidak ada error JavaScript saat rendering auditTemplate()');

// Ekstrak thead
const theadMatch = renderedHtml.match(/<thead>[\s\S]*?<\/thead>/);
assertCondition(!!theadMatch, 'Struktur: Elemen <thead> ditemukan');
const theadHtml = theadMatch ? theadMatch[0] : '';

// Ekstrak seluruh th
const thMatches = theadHtml.match(/<th\b[^>]*>([\s\S]*?)<\/th>/g) || [];
const thTexts = thMatches.map(th => th.replace(/^<th\b[^>]*>|<\/th>$/g, '').trim());

// Pengujian 1: Header tabel hanya berjumlah lima
assertCondition(
  thMatches.length === 5,
  '1. Header tabel hanya berjumlah lima (5 kolom)',
  `Ditemukan: ${thMatches.length} kolom: ${JSON.stringify(thTexts)}`
);

// Pengujian 2: Urutan header benar: No., Waktu, Aktivitas, Alamat IP, Status
const expectedHeaders = ['No.', 'Waktu', 'Aktivitas', 'Alamat IP', 'Status'];
const isHeadersOrderCorrect = thTexts.length === 5 && expectedHeaders.every((h, i) => thTexts[i] === h);
assertCondition(
  isHeadersOrderCorrect,
  '2. Urutan header benar: No., Waktu, Aktivitas, Alamat IP, Status',
  `Ditemukan: ${JSON.stringify(thTexts)}`
);

// Pengujian 3: Header Rantai Hash sudah tidak muncul
const hasHashHeader = theadHtml.toLowerCase().includes('rantai hash') || theadHtml.toLowerCase().includes('hash');
assertCondition(
  !hasHashHeader,
  '3. Header Rantai Hash sudah tidak muncul pada thead',
  `Header HTML: ${theadHtml}`
);

// Pengujian 4: Tidak ada rendering previous_hash maupun current_hash pada tabel
let hashLeakFound = false;
for (const log of testLogs) {
  if (renderedHtml.includes(log.previous_hash) || renderedHtml.includes(log.current_hash)) {
    hashLeakFound = true;
    break;
  }
}
assertCondition(
  !hashLeakFound,
  '4. Tidak ada rendering previous_hash maupun current_hash pada tabel'
);

// Pengujian 5: Tidak ada teks "Sebelumnya:" dan "Saat ini:" pada tabel
const hasPreviousText = renderedHtml.includes('Sebelumnya:');
const hasCurrentText = renderedHtml.includes('Saat ini:');
assertCondition(
  !hasPreviousText && !hasCurrentText,
  '5. Tidak ada teks "Sebelumnya:" dan "Saat ini:" pada tabel',
  `Sebelumnya: ${hasPreviousText}, Saat ini: ${hasCurrentText}`
);

// Ekstrak tbody dan baris
const tbodyMatch = renderedHtml.match(/<tbody>([\s\S]*?)<\/tbody>/);
const tbodyHtml = tbodyMatch ? tbodyMatch[0] : '';
const rowMatches = tbodyHtml.match(/<tr>([\s\S]*?)<\/tr>/g) || [];

// Pengujian 6: Setiap baris data memiliki tepat lima sel
let allRowsHaveFiveCells = rowMatches.length === testLogs.length;
for (let i = 0; i < rowMatches.length; i++) {
  const cells = rowMatches[i].match(/<td\b[^>]*>([\s\S]*?)<\/td>/g) || [];
  if (cells.length !== 5) {
    allRowsHaveFiveCells = false;
    console.error(`Row ${i} memiliki ${cells.length} sel (diharapkan: 5)`);
  }
}
assertCondition(
  allRowsHaveFiveCells,
  '6. Setiap baris data memiliki tepat lima sel <td>',
  `Jumlah baris: ${rowMatches.length}`
);

// Pengujian 7: Kondisi loading menggunakan colspan="5"
const loadingHtml = renderAuditTable({ loading: true, logs: [] });
const loadingColspanMatch = loadingHtml.match(/<td\s+colspan="(\d+)"[^>]*class="empty-state">Memuat catatan audit\.\.\.<\/td>/);
assertCondition(
  loadingColspanMatch && loadingColspanMatch[1] === '5',
  '7. Kondisi loading menggunakan colspan="5"',
  `Ditemukan: ${loadingColspanMatch ? loadingColspanMatch[0] : 'Tidak cocok'}`
);

// Pengujian 8: Kondisi empty state menggunakan colspan="5"
const emptyHtml = renderAuditTable({ loading: false, logs: [] });
const emptyColspanMatch = emptyHtml.match(/<td\s+colspan="(\d+)"[^>]*class="empty-state">Belum ada aktivitas yang sesuai dengan filter\.\<\/td>/);
assertCondition(
  emptyColspanMatch && emptyColspanMatch[1] === '5',
  '8. Kondisi empty state menggunakan colspan="5"',
  `Ditemukan: ${emptyColspanMatch ? emptyColspanMatch[0] : 'Tidak cocok'}`
);

// Pengujian 9: Kolom Alamat IP tetap menampilkan IP dengan benar
function getRowCells(rowHtml) {
  const cells = rowHtml.match(/<td\b[^>]*>([\s\S]*?)<\/td>/g) || [];
  return cells.map(c => c.replace(/^<td\b[^>]*>|<\/td>$/g, ''));
}
const cellsRow1 = getRowCells(rowMatches[0] || '');
const cellsRow2 = getRowCells(rowMatches[1] || '');
const cellsRow3 = getRowCells(rowMatches[2] || '');

const ipCol1 = cellsRow1[3] || '';
const ipCol2 = cellsRow2[3] || '';
const ipCol3 = cellsRow3[3] || '';

const ipPass = ipCol1.includes('192.168.1.10') &&
               ipCol2.includes('2001:0db8:85a3:0000:0000:8a2e:0370:7334') &&
               ipCol3.includes('Tidak tersedia');

assertCondition(
  ipPass,
  '9. Kolom Alamat IP tetap menampilkan IP dengan benar (IPv4, IPv6, dan fallback)',
  `Row 1 IP: ${ipCol1}, Row 2 IP: ${ipCol2}, Row 3 IP: ${ipCol3}`
);

// Pengujian 10: Kolom Status tetap tampil
const statusCol1 = cellsRow1[4] || '';
const statusCol3 = cellsRow3[4] || '';
const statusPass = statusCol1.includes('is-success') && statusCol1.includes('Berhasil') &&
                   statusCol3.includes('is-failed') && statusCol3.includes('Gagal');
assertCondition(
  statusPass,
  '10. Kolom Status tetap tampil dengan badge sukses/gagal',
  `Row 1 Status: ${statusCol1}, Row 3 Status: ${statusCol3}`
);

// Pengujian 11: Informasi aktivitas tetap tampil
const actCol1 = cellsRow1[2] || '';
const actCol2 = cellsRow2[2] || '';
const actPass = actCol1.includes('Masuk ke akun') && actCol2.includes('Inisialisasi berkas');
assertCondition(
  actPass,
  '11. Informasi aktivitas tetap tampil pada kolom Aktivitas',
  `Row 1 Act: ${actCol1}, Row 2 Act: ${actCol2}`
);

// Verifikasi Statis CSS (Penyesuaian CSS)
const stylesCss = fs.readFileSync(path.join(projectRoot, 'frontend/styles.css'), 'utf8');
const hasNthChild6 = stylesCss.includes('.audit-console .audit-table th:nth-child(6)');
const minWidth800 = stylesCss.includes('.audit-console .audit-table{min-width:800px');
assertCondition(
  !hasNthChild6,
  '13. CSS: Aturan khusus th:nth-child(6) pada .audit-console sudah dihapus'
);
assertCondition(
  minWidth800,
  '14. CSS: Tabel .audit-table menggunakan min-width: 800px untuk 5 kolom'
);

console.log('\n========================================================');
console.log(`  HASIL PENGUJIAN: ${passedTests} PASSED, ${failedTests} FAILED`);
console.log('========================================================');

if (failedTests > 0) {
  process.exit(1);
}
process.exit(0);
