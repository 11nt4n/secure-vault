import { request, getAuthToken, setAuthToken, clearAuthToken } from './api.js?v=11';
import { createQrSvg } from './qr.js?v=9';
import { encryptChunkOffThread, decryptChunkOffThread, terminateCryptoWorker } from './crypto-worker-client.js?v=9';
import {
  clearVaultKeys, getLoadedMasterKey, getLoadedKek, setLoadedKeys, isVaultKeyLoaded,
  generateSalt, uint8ArrayToB64, b64ToUint8Array, deriveKek,
  generateMasterKey, generateFileDek, wrapMasterKey, unwrapMasterKey, rewrapMasterKeyForPassphrase,
  wrapDek, unwrapDek, encryptText, decryptText, createVerifier,
  verifyPassphrase
} from './crypto.js?v=9';

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
const appRoot = $('#app');
const modalRoot = $('#modal-root');
const toastRoot = $('#toast-root');
const CHUNK_SIZE = 5 * 1024 * 1024;
const MAX_FILE_SIZE = 500 * 1024 * 1024;
const APP_BUILD = 'NATIVE-V3-Folders:06.11.2026';
window.__SECURE_VAULT_BUILD__ = APP_BUILD;
const BLOCKED_EXTENSIONS = new Set(['exe','dll','com','bat','cmd','ps1','vbs','js','jse','wsf','scr','msi','sh','php','phtml','jar','hta','apk']);
const MAGIC = {
  pdf: [[0x25,0x50,0x44,0x46]], png: [[0x89,0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a]],
  jpg: [[0xff,0xd8,0xff]], jpeg: [[0xff,0xd8,0xff]], gif: [[0x47,0x49,0x46,0x38]],
  zip: [[0x50,0x4b,0x03,0x04],[0x50,0x4b,0x05,0x06]], docx: [[0x50,0x4b,0x03,0x04]], xlsx: [[0x50,0x4b,0x03,0x04]]
};

const state = {
  theme: localStorage.getItem('sv_theme_preference') || 'light',
  user: null, activeTab: 'files', unlocked: false, createMenuOpen: false, currentFolderId: null, pendingVaultAction: null,
  login: { username: '', password: '', onboardingStage: '', onboardingChallenge: '', onboardingEmailHint: '', onboardingPasswordToken: '', mfaRequired: false, mfaSetupRequired: false, mfaToken: '', totpCode: '', mfaSecret: '', mfaOtpUri: '', secretCopied: false, loading: false, error: '', notice: '' },
  activation: null,
  files: [], decryptedFiles: [], folders: [], decryptedFolders: [], filesLoading: false, filesError: '', search: '', selectedTag: null, sortBy: 'date', sortAsc: false, dashboardView: 'home', fileLayout: 'grid',
  downloadingId: null, downloadProgress: 0, preview: null,
  audit: { logs: [], loading: false, action: 'ALL', status: 'ALL', error: '' },
  admin: { users: [], stats: null, loading: false, creating: false, error: '', search: '', status: 'all' },
  modal: null, modalLoading: false, modalError: '', modalStage: '',
  vaultProfile: null, selectedFile: null, detailEditing: false, detailName: '', detailTags: '', detailSaving: false,
  upload: { file: null, tags: 'Rahasia, BSSN, Sertifikasi', uploading: false, progress: 0, currentChunk: 0, totalChunks: 0, status: '', error: '' },
  folderForm: { name: '', loading: false, error: '' },
  folderUpload: { uploading: false, current: '', completed: 0, total: 0, progress: 0, error: '' },
  passphrase: { newValue: '', confirm: '', loading: false, error: '', stage: '' },
  toastTimer: null, idleTimer: null
};

const activationMatch = /^#activate=([a-f0-9-]{36})\.([a-f0-9]{64})\.([^&]+)$/i.exec(location.hash);
if (activationMatch) {
  try {
    const username = decodeURIComponent(activationMatch[3]);
    if (/^[A-Za-z0-9_.-]{3,64}$/.test(username)) {
      state.activation = { userId: activationMatch[1], token: activationMatch[2], username, loading: false, error: '' };
      clearAuthToken();
      history.replaceState(null, '', location.pathname + location.search);
    }
  } catch { /* Invalid link remains on the login page. */ }
}

function esc(value = '') {
  return String(value).replace(/[&<>"']/g, ch => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));
}
function bytes(value) {
  const n = Number(value) || 0;
  if (n < 1024) return `${n} B`;
  if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 ** 3) return `${(n / 1024 ** 2).toFixed(2)} MB`;
  return `${(n / 1024 ** 3).toFixed(2)} GB`;
}
function dateText(value) { try { return new Date(value).toLocaleString('id-ID'); } catch { return value || '-'; } }
function errorBox(message, cls = 'error') { return message ? `<div class="notice-${cls}">${esc(message)}</div>` : ''; }
function btn(action, text, cls = 'btn-secondary', extra = '') { return `<button type="button" class="btn ${cls}" data-action="${action}" ${extra}>${text}</button>`; }
function icon(name, size = 16) {
  const paths = {
    lock: '<rect x="3" y="10" width="18" height="11" rx="2"/><path d="M7 10V7a5 5 0 0 1 10 0v3"/>',
    unlock: '<rect x="3" y="10" width="18" height="11" rx="2"/><path d="M7 10V7a5 5 0 0 1 9.5-2"/>',
    key: '<circle cx="8" cy="15" r="5"/><path d="m11.5 11.5 9-9M17 6l2 2m-5 1 2 2"/>',
    shield: '<path d="M12 22s8-4 8-11V5l-8-3-8 3v6c0 7 8 11 8 11Z"/><path d="m9 12 2 2 4-4"/>',
    upload: '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="m17 8-5-5-5 5M12 3v12"/>',
    download: '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="m7 10 5 5 5-5M12 15V3"/>',
    trash: '<path d="M3 6h18M8 6V4h8v2m3 0-1 14H6L5 6m4 4v6m6-6v6"/>',
    file: '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8Z"/><path d="M14 2v6h6M8 13h8m-8 4h8"/>',
    search: '<circle cx="11" cy="11" r="7"/><path d="m20 20-4-4"/>',
    info: '<circle cx="12" cy="12" r="10"/><path d="M12 16v-4m0-4h.01"/>',
    refresh: '<path d="M20 7v5h-5M4 17v-5h5"/><path d="M5.6 9A7 7 0 0 1 18 6l2 6M4 12l2 6a7 7 0 0 0 12.4-3"/>',
    sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2v2m0 16v2M4.93 4.93l1.41 1.41m11.32 11.32 1.41 1.41M2 12h2m16 0h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41"/>',
    moon: '<path d="M20.9 13A9 9 0 0 1 11 3.1 9 9 0 1 0 20.9 13Z"/>',
    laptop: '<rect x="3" y="4" width="18" height="13" rx="2"/><path d="M2 21h20"/>',
    logout: '<path d="M10 17l5-5-5-5m5 5H3"/><path d="M12 3h7a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-7"/>',
    copy: '<rect x="8" y="8" width="13" height="13" rx="2"/><path d="M16 8V5a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h3"/>',
    check: '<path d="m5 12 4 4L19 6"/>',
    alert: '<path d="M10.3 3.9 2.4 18a2 2 0 0 0 1.7 3h15.8a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z"/><path d="M12 9v4m0 4h.01"/>',
    edit: '<path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L8 18l-4 1 1-4Z"/>',
    close: '<path d="m18 6-12 12M6 6l12 12"/>',
    database: '<ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M3 5v14a9 3 0 0 0 18 0V5M3 12a9 3 0 0 0 18 0"/>',
    users: '<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2m7-10a4 4 0 1 0 0-8 4 4 0 0 0 0 8Zm13 10v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75"/>',
    filter: '<path d="M4 6h16M7 12h10m-7 6h4"/>',
    filecode: '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8Z"/><path d="M14 2v6h6M10 13l-2 2 2 2m4-4 2 2-2 2"/>',
    spreadsheet: '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8Z"/><path d="M14 2v6h6M8 13h8m-8 4h8m-5-4v4"/>',
    archive: '<path d="M3 4h18v5H3zM5 9v11h14V9M10 13h4m-2-9v5"/>',
    image: '<rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><path d="m21 15-5-5L5 21"/>',
    arrow: '<path d="M5 12h14m-7-7 7 7-7 7"/>',
    smartphone: '<rect x="5" y="2" width="14" height="20" rx="2"/><path d="M12 18h.01"/>',
    home: '<path d="m3 10 9-7 9 7v10a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1Z"/><path d="M9 21v-7h6v7"/>',
    grid: '<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/>',
    list: '<path d="M9 6h12M9 12h12M9 18h12M3 6h2M3 12h2M3 18h2"/>',
    plus: '<path d="M12 5v14M5 12h14"/>',
    folder: '<path d="M3 7a2 2 0 0 1 2-2h5l2 2h7a2 2 0 0 1 2 2v10H3Z"/>',
    folderPlus: '<path d="M3 7a2 2 0 0 1 2-2h5l2 2h7a2 2 0 0 1 2 2v10H3Z"/><path d="M12 11v6m-3-3h6"/>',
    folderUpload: '<path d="M3 7a2 2 0 0 1 2-2h5l2 2h7a2 2 0 0 1 2 2v10H3Z"/><path d="m12 17 0-6m-3 3 3-3 3 3"/>'
  };
  return `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${paths[name] || paths.file}</svg>`;
}
function showToast(message, type = 'success') {
  clearTimeout(state.toastTimer);
  toastRoot.innerHTML = `<div class="toast ${type === 'success' ? 'toast-success' : 'toast-error'}">${icon(type === 'success' ? 'check' : 'alert', 18)}<span class="toast-message">${esc(message)}</span></div>`;
  state.toastTimer = setTimeout(() => { toastRoot.innerHTML = ''; }, 4000);
}
function applyTheme(theme) {
  state.theme = theme;
  const effective = theme === 'system' ? (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light') : theme;
  document.documentElement.setAttribute('data-theme', effective);
  localStorage.setItem('sv_theme_preference', theme);
  const meta = $('meta[name="theme-color"]');
  if (meta) meta.content = effective === 'dark' ? '#060913' : '#f8fafc';
}
function resetIdleTimer() {
  clearTimeout(state.idleTimer);
  if (!state.user) return;
  state.idleTimer = setTimeout(() => {
    if (isVaultKeyLoaded()) {
      clearVaultKeys(); terminateCryptoWorker(); state.unlocked = false;
      state.decryptedFiles = state.files; state.decryptedFolders = state.folders;
      render();
      showToast('Brankas dikunci otomatis setelah 15 menit tidak aktif. Sesi akun tetap tersimpan.', 'error');
    }
  }, 15 * 60 * 1000);
}

function setAppHistory(view, tab = state.activeTab, replace = false, modal = null) {
  const payload = { secureVaultApp: true, view, tab, modal, dashboardView: state.dashboardView, currentFolderId: state.currentFolderId };
  try {
    if (replace) history.replaceState(payload, '', location.pathname + location.search + location.hash);
    else history.pushState(payload, '', location.pathname + location.search + location.hash);
  } catch { /* History may be unavailable in restricted browser contexts. */ }
}

function handleAppPopState(event) {
  const nav = event.state;
  if (state.user) resetIdleTimer();
  if (state.user) {
    if (nav?.secureVaultApp && nav.view === 'app') {
      const changed = state.activeTab !== nav.tab;
      state.activeTab = ['files', 'audit', 'admin'].includes(nav.tab) && (nav.tab === 'files' || state.user.role === 'admin') ? nav.tab : 'files';
      if (['home', 'files'].includes(nav.dashboardView)) state.dashboardView = nav.dashboardView;
      state.currentFolderId = typeof nav.currentFolderId === 'string' && state.folders.some(folder => folder.id === nav.currentFolderId) ? nav.currentFolderId : null;
      const allowedModals = ['unlock', 'upload', 'new-folder', 'folder-select', 'folder-upload', 'change-pass', 'details', 'preview'];
      const previousModal = state.modal;
      state.modal = allowedModals.includes(nav.modal) ? nav.modal : null;
      if (previousModal === 'unlock' && state.modal !== 'unlock') state.pendingVaultAction = null;
      if (state.modal === 'unlock' && !state.vaultProfile && !state.modalLoading) {
        state.modalLoading = true;
        request('/auth/vault-profile').then(profile => { state.vaultProfile = profile; state.modalLoading = false; render(); })
          .catch(err => { state.modalLoading = false; state.modalError = 'Gagal memeriksa profil brankas: ' + err.message; state.vaultProfile = { hasProfile: true }; render(); });
      }
      render();
      if (changed && state.activeTab === 'files') fetchFiles();
      if (changed && state.activeTab === 'audit') fetchAudit();
      if (changed && state.activeTab === 'admin') fetchAdmin();
      return;
    }
    // Do not navigate an authenticated user back into an obsolete login/MFA screen.
    state.activeTab = 'files';
    state.modal = null;
    setAppHistory('app', 'files', true);
    render();
    return;
  }

  state.modal = null;
  if (nav?.secureVaultApp && nav.view === 'mfa' && state.login.mfaToken) {
    state.login.mfaRequired = true;
  } else {
    state.login.mfaRequired = false;
    state.login.mfaSetupRequired = false;
    state.login.mfaToken = '';
    state.login.totpCode = '';
    state.login.mfaSecret = '';
    state.login.mfaOtpUri = '';
    state.login.secretCopied = false;
    setAppHistory('login', 'files', true);
  }
  render();
}

function headerTemplate() {
  const user = state.user;
  return `<header class="top-header"><div class="container header-inner">
    <div class="brand"><img src="./logo.png" alt="Secure Vault Logo"><div class="brand-text"><span class="brand-name">SECURE<span>VAULT</span></span><p class="brand-subtitle">Encrypted File Storage • Zero-Knowledge Architecture</p></div></div>
    ${user ? `<span class="header-spacer"></span>` : ''}
    <div class="header-controls">
      <div class="theme-toggle" title="Ubah Tema Tampilan">
        ${['light','dark','system'].map((t, i) => `<button data-action="theme" data-theme="${t}" title="${['Tema Terang','Tema Gelap','Otomatis Sesuai Sistem'][i]}" class="${state.theme === t ? 'active' : ''}">${icon(['sun','moon','laptop'][i], 15)}</button>`).join('')}
      </div>
      ${user ? `<div class="user-chip"><div class="user-avatar ${user.role === 'admin' ? 'admin' : ''}">${esc((user.username || '?').charAt(0).toUpperCase())}</div><div><b>${esc(user.username)}</b><small>${esc(String(user.role || 'user').toUpperCase())}</small></div></div>
      ${btn('logout', icon('logout', 15), 'btn-danger btn-sm', 'title="Logout Sesi" aria-label="Logout"')}` : ''}
    </div>
  </div></header>`;
}
function sidebarTemplate() {
  const total = state.files.reduce((sum, file) => sum + Number(file.file_size_bytes || 0), 0);
  const quota = Number(state.user?.storageQuotaBytes) || 5 * 1024 ** 3;
  const percent = Math.min(100, Math.round(total / quota * 100));
  return `<aside class="drive-sidebar" aria-label="Navigasi utama">
    <div class="drive-create-wrap"><button class="drive-new" type="button" data-action="create-menu" aria-haspopup="menu" aria-expanded="${state.createMenuOpen}">${icon('plus', 21)}<span>Baru</span></button><input id="folder-picker" type="file" webkitdirectory directory multiple hidden aria-label="Pilih folder untuk diunggah">
      ${state.createMenuOpen ? `<div class="drive-create-menu" role="menu" aria-label="Buat baru">
        <button type="button" role="menuitem" data-action="new-folder">${icon('folderPlus', 18)}<span>Folder baru</span></button>
        <div class="drive-create-separator"></div>
        <button type="button" role="menuitem" data-action="upload">${icon('upload', 18)}<span>Upload file</span></button>
        <button type="button" role="menuitem" data-action="choose-folder">${icon('folderUpload', 18)}<span>Upload folder</span></button>
      </div>` : ''}</div>
    <nav class="drive-navigation" aria-label="Bagian aplikasi">
      <button type="button" class="drive-nav-item ${state.activeTab === 'files' && state.dashboardView === 'home' ? 'active' : ''}" data-action="dashboard-view" data-view="home">${icon('home', 19)}<span>Beranda</span></button>
      <button type="button" class="drive-nav-item ${state.activeTab === 'files' && state.dashboardView === 'files' ? 'active' : ''}" data-action="dashboard-view" data-view="files">${icon('database', 19)}<span>Brankas Saya</span></button>
      <div class="drive-nav-divider"></div>
      ${state.user.role === 'admin' ? `<button type="button" class="drive-nav-item ${state.activeTab === 'audit' ? 'active' : ''}" data-action="tab" data-tab="audit">${icon('shield', 19)}<span>Jejak Audit</span></button>
      <button type="button" class="drive-nav-item ${state.activeTab === 'admin' ? 'active' : ''}" data-action="tab" data-tab="admin">${icon('users', 19)}<span>Konsol Admin</span></button>` : ''}
    </nav>
    <div class="drive-sidebar-bottom"><div class="drive-storage-label">${icon('database', 18)}<span>Penyimpanan</span></div><progress class="vault-progress storage-progress" max="100" value="${percent}" aria-label="Pemakaian kuota ${percent}%">${percent}%</progress><p>${bytes(total)} dari ${bytes(quota)} digunakan</p>${state.unlocked ? `<span class="drive-vault-state unlocked">${icon('unlock', 15)} Brankas terbuka</span>` : `<button type="button" class="drive-vault-state drive-vault-unlock" data-action="open-unlock" title="Buka kunci brankas">${icon('lock', 15)} Brankas terkunci</button>`}</div>
  </aside>`;
}
function footerTemplate() {
  return `<footer class="institution-footer"><div class="container"><div><img src="./logo.png" alt="Secure Vault"><strong>SECURE VAULT</strong> • Zero-Knowledge Distributed Storage</div><small>Secure Vault • ISO/IEC 15408 dan ISO/IEC 18045 digunakan sebagai referensi desain keamanan.</small></div></footer>`;
}
function otpEnrollmentTemplate(login) {
  let qrMarkup = '';
  let qrError = '';
  try {
    if (login.mfaOtpUri) qrMarkup = createQrSvg(login.mfaOtpUri, 4, 4);
    else qrError = 'QR belum tersedia dari server. Gunakan secret manual di bawah.';
  } catch (error) {
    qrError = error?.message || 'QR tidak dapat dibuat. Gunakan secret manual di bawah.';
  }
  return `<section class="otp-enrollment-card otp-enrollment-centered" aria-label="Pengaturan authenticator">
    <div class="otp-enroll-intro"><span class="otp-enroll-icon">${icon('shield-check',20)}</span><div><strong>Hubungkan aplikasi authenticator</strong><p>Pindai QR di bawah untuk menambahkan Secure Vault ke aplikasi authenticator Anda.</p></div></div>
    <div class="otp-qr-center">
      <div class="otp-qr-frame">${qrMarkup || `<div class="otp-qr-fallback">${icon('smartphone',34)}<span>Gunakan secret manual</span></div>`}</div>
      <span class="otp-qr-caption">SCAN QR CODE</span>
      ${qrError ? `<small class="otp-qr-error">${esc(qrError)}</small>` : ''}
      <div class="otp-privacy-note">${icon('shield',14)} QR dibuat lokal di browser. Secret tidak dikirim ke layanan QR eksternal.</div>
    </div>
    <div class="otp-manual-details" aria-label="Kode setup manual authenticator">
      <strong class="otp-manual-title">${icon('key-round',15)} Kode setup manual</strong>
      <p>Jika tidak bisa memindai QR, tambahkan akun secara manual di aplikasi authenticator.</p>
      <div class="secret-row"><code>${esc(login.mfaSecret)}</code><button type="button" class="btn btn-secondary btn-sm" data-action="copy-secret">${icon(login.secretCopied ? 'check' : 'copy',14)} ${login.secretCopied ? 'Tersalin' : 'Salin kode'}</button></div>
      <small>Jenis TOTP, issuer Secure Vault, akun ${esc(login.username)}, 6 digit, SHA-1, periode 30 detik. Jangan bagikan kode setup ini.</small>
    </div>
    <div class="otp-enroll-instructions">
      <div class="otp-instruction"><span class="otp-instruction-number">1</span><div><strong>Buka authenticator</strong><p>Gunakan Google Authenticator, Microsoft Authenticator, Authy, 1Password, atau aplikasi TOTP lain.</p></div></div>
      <div class="otp-instruction"><span class="otp-instruction-number">2</span><div><strong>Pindai QR Code</strong><p>Pastikan akun Secure Vault berhasil ditambahkan. Format kode adalah TOTP 6 digit dengan rotasi setiap 30 detik.</p></div></div>
      <div class="otp-instruction"><span class="otp-instruction-number">3</span><div><strong>Masukkan kode verifikasi</strong><p>Ketik kode 6 digit yang sedang tampil pada aplikasi untuk menyelesaikan aktivasi.</p></div></div>
    </div>
  </section>`;
}
function loginTemplate() {
  const l = state.login;
  const title = l.onboardingStage === 'email' ? 'Verifikasi Email' : l.onboardingStage === 'password' ? 'Buat Kata Sandi Baru' : l.mfaRequired ? (l.mfaSetupRequired ? 'Aktifkan Authenticator' : 'Verifikasi Dua Faktor (MFA)') : 'Selamat Datang di Secure Vault';
  const subtitle = l.onboardingStage === 'email' ? `Masukkan kode 8 digit yang dikirim ke ${esc(l.onboardingEmailHint)}.` : l.onboardingStage === 'password' ? 'Email berhasil diverifikasi. Ganti kata sandi sementara untuk mengaktifkan akun.' : l.mfaRequired ? (l.mfaSetupRequired ? 'Pindai QR code pada aplikasi authenticator untuk mengamankan akun Anda.' : 'Masukkan kode 6 digit dari aplikasi authenticator Anda untuk melanjutkan.') : 'Masuk dengan akun yang diberikan administrator.';
  return `<section class="login-wrap"><div class="glass-card login-card ${l.mfaSetupRequired ? 'login-card-otp' : ''}"><div class="login-heading"><img src="./logo.png" alt="Secure Vault Logo"><h2>${title}</h2><p>${subtitle}</p></div>
    ${l.notice ? `<div class="inline-notice">${icon('check',18)}<span>${esc(l.notice)}</span></div>` : ''}${errorBox(l.error)}
    ${l.onboardingStage === 'email' ? `<form data-form="onboarding-email" class="form-stack" novalidate>
      <div class="input-group"><label class="input-label">Kode verifikasi email (8 digit)</label><input class="input-control mono otp-input" name="emailCode" type="text" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{8}" maxlength="8" required autofocus></div>
      <button class="btn btn-primary btn-block" type="submit" ${l.loading ? 'disabled' : ''}>${l.loading ? 'Memverifikasi...' : 'Verifikasi Email'}</button>
      <button type="button" class="btn btn-secondary btn-sm btn-block" data-action="onboarding-back">Kembali ke Login</button>
    </form>` : l.onboardingStage === 'password' ? `<form data-form="onboarding-password" class="form-stack" novalidate>
      <div class="input-group"><label class="input-label">Kata sandi baru</label><input class="input-control" name="newPassword" type="password" autocomplete="new-password" minlength="12" required></div>
      <div class="input-group"><label class="input-label">Ulangi kata sandi baru</label><input class="input-control" name="confirmPassword" type="password" autocomplete="new-password" minlength="12" required></div>
      <button class="btn btn-primary btn-block" type="submit" ${l.loading ? 'disabled' : ''}>${l.loading ? 'Menyimpan...' : 'Aktifkan Akun'}</button>
      <button type="button" class="btn btn-secondary btn-sm btn-block" data-action="onboarding-back">Kembali ke Login</button>
    </form>` : l.mfaRequired ? `<form data-form="mfa" class="form-stack" novalidate>
      ${l.mfaSetupRequired ? otpEnrollmentTemplate(l) : ''}
      <div class="input-group"><label class="input-label">${l.mfaSetupRequired ? '3. Masukkan kode 6 digit untuk menyelesaikan aktivasi TOTP' : 'Kode autentikator (6 digit)'}</label><input class="input-control mono otp-input" name="totpCode" type="text" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" required value="${esc(l.totpCode)}" autofocus></div>
      <button class="btn btn-primary btn-block" type="submit" ${l.loading || l.totpCode.length !== 6 || (l.mfaSetupRequired && !l.mfaSecret) ? 'disabled' : ''}>${l.loading ? 'Memverifikasi...' : l.mfaSetupRequired ? 'Aktifkan TOTP & Masuk' : 'Verifikasi & Masuk'} ${icon('arrow',16)}</button>
      <button type="button" class="btn btn-secondary btn-sm btn-block" data-action="mfa-back" ${l.loading ? 'disabled' : ''}>Kembali ke Login</button>
    </form>` : `<form data-form="login" class="form-stack" novalidate>
      <div class="input-group"><label class="input-label">Username</label><input class="input-control" name="username" placeholder="Masukkan username" required autocomplete="username" value="${esc(l.username)}"></div>
      <div class="input-group"><label class="input-label">Kata Sandi</label><input class="input-control" type="password" name="password" placeholder="Masukkan kata sandi" required autocomplete="current-password"></div>
      <button class="btn btn-primary btn-block" type="submit" ${l.loading ? 'disabled' : ''}>${l.loading ? 'Memproses...' : 'Masuk'} ${icon('arrow',16)}</button>
    </form>`}</div></section>`;
}
function activationTemplate() {
  const a = state.activation;
  return `<section class="login-wrap"><div class="glass-card login-card"><div class="login-heading"><img src="./logo.png" alt="Secure Vault Logo"><h2>Aktivasi Akun</h2><p>Verifikasi email dan buat kata sandi untuk ${esc(a.username)}. Setelah itu, masuk dan siapkan OTP authenticator.</p></div>
    ${errorBox(a.error)}
    <form data-form="activate-account" class="form-stack" novalidate>
      <div class="input-group"><label class="input-label">Kata sandi baru</label><input class="input-control" name="newPassword" type="password" autocomplete="new-password" minlength="12" required autofocus></div>
      <div class="input-group"><label class="input-label">Ulangi kata sandi baru</label><input class="input-control" name="confirmPassword" type="password" autocomplete="new-password" minlength="12" required></div>
      <button class="btn btn-primary btn-block" type="submit" ${a.loading ? 'disabled' : ''}>${a.loading ? 'Mengaktifkan...' : 'Buat Kata Sandi & Aktifkan Akun'}</button>
    </form><button type="button" class="btn btn-secondary btn-sm btn-block" data-action="activation-back">Kembali ke Login</button></div></section>`;
}
function alertTemplate(message) { return message ? `<div class="dashboard-alert">${icon('alert',18)}<span>${esc(message)}</span></div>` : ''; }
function fileIcon(name) {
  const ext = (name || '').split('.').pop()?.toLowerCase();
  if (ext === 'pdf') return `<span class="file-icon-rose">${icon('file',18)}</span>`;
  if (['doc','docx','txt'].includes(ext)) return `<span class="file-icon-cyan">${icon('file',18)}</span>`;
  if (['xls','xlsx','csv'].includes(ext)) return `<span class="file-icon-emerald">${icon('spreadsheet',18)}</span>`;
  if (['zip','tar','gz','7z'].includes(ext)) return `<span class="file-icon-indigo">${icon('archive',18)}</span>`;
  if (['png','jpg','jpeg','svg','gif','webp'].includes(ext)) return `<span class="file-icon-emerald">${icon('image',18)}</span>`;
  if (['key','pem','crt'].includes(ext)) return `<span class="file-icon-amber">${icon('key',18)}</span>`;
  return `<span class="file-icon-cyan">${icon('filecode',18)}</span>`;
}
function visibleFiles() {
  const items = state.decryptedFiles.filter(file => {
    const name = (file.decryptedFileName || file.encrypted_file_name || '').toLowerCase();
    return (file.parent_folder_id || null) === state.currentFolderId
      && name.includes(state.search.toLowerCase()) && (!state.selectedTag || (file.tags || []).includes(state.selectedTag));
  });
  items.sort((a,b) => {
    if (state.sortBy === 'date') { const d = new Date(b.created_at) - new Date(a.created_at); return state.sortAsc ? -d : d; }
    if (state.sortBy === 'name') { const d = (a.decryptedFileName || a.encrypted_file_name).toLowerCase().localeCompare((b.decryptedFileName || b.encrypted_file_name).toLowerCase()); return state.sortAsc ? d : -d; }
    const d = Number(a.file_size_bytes) - Number(b.file_size_bytes); return state.sortAsc ? d : -d;
  });
  return items;
}
function visibleFolders() {
  return state.decryptedFolders.filter(folder => (folder.parent_folder_id || null) === state.currentFolderId
    && (folder.decryptedFileName || folder.encrypted_file_name || '').toLowerCase().includes(state.search.toLowerCase()))
    .sort((a,b) => (a.decryptedFileName || '').localeCompare(b.decryptedFileName || ''));
}
function folderBreadcrumbs() {
  const crumbs = [];
  const visited = new Set();
  let id = state.currentFolderId;
  while (id && crumbs.length < 20 && !visited.has(id)) {
    visited.add(id);
    const folder = state.decryptedFolders.find(entry => entry.id === id);
    if (!folder) break;
    crumbs.unshift(folder);
    id = folder.parent_folder_id || null;
  }
  return crumbs;
}
function dashboardTemplate() {
  const allTags = [...new Set(state.decryptedFiles.filter(f => (f.parent_folder_id || null) === state.currentFolderId).flatMap(f => f.tags || []))];
  const list = visibleFiles();
  const folderList = visibleFolders();
  const breadcrumbs = folderBreadcrumbs();
  const currentFolder = breadcrumbs[breadcrumbs.length - 1];
  const title = currentFolder ? (state.unlocked ? currentFolder.decryptedFileName : 'Folder terenkripsi') : state.dashboardView === 'files' ? 'Brankas Saya' : 'Selamat datang di Secure Vault';
  const folderCards = folderList.map(folder => {
    const name = state.unlocked ? (folder.decryptedFileName || 'Folder') : 'Folder terenkripsi';
    return `<div class="drive-folder-card"><button type="button" class="drive-folder-open" data-action="folder-open" data-id="${esc(folder.id)}" title="Buka ${esc(name)}">${icon('folder',21)}<span>${esc(name)}</span></button><button type="button" class="drive-folder-delete" data-action="delete-folder" data-id="${esc(folder.id)}" title="Hapus folder kosong" aria-label="Hapus ${esc(name)}" ${state.unlocked ? '' : 'disabled'}>${icon('trash',15)}</button></div>`;
  }).join('');
  const gridCards = list.map(file => {
    const isBusy = state.downloadingId === file.id;
    const unavailable = file.upload_status === 'uploading' || Boolean(file.deletion_pending);
    const name = state.unlocked ? (file.decryptedFileName || file.encrypted_file_name) : 'Nama berkas terenkripsi';
    return `<article class="drive-file-card"><div class="drive-file-card-head">${fileIcon(state.unlocked ? name : '')}<strong title="${esc(name)}">${esc(name)}</strong><button type="button" class="drive-card-more" data-action="file-details" data-id="${esc(file.id)}" title="Detail berkas" aria-label="Detail ${esc(name)}" ${unavailable ? 'disabled' : ''}>${icon('info',17)}</button></div><div class="drive-file-preview">${icon(state.unlocked ? 'file' : 'lock', 42)}<span>${state.unlocked ? esc((name.split('.').pop() || 'BERKAS').toUpperCase()) : 'TERENKRIPSI'}</span></div><div class="drive-file-card-foot"><small>${esc(dateText(file.created_at))} · ${bytes(file.file_size_bytes)}</small><div><button type="button" data-action="preview-file" data-id="${esc(file.id)}" title="Pratinjau" aria-label="Pratinjau ${esc(name)}" ${isBusy || unavailable ? 'disabled' : ''}>${icon('file',16)}</button><button type="button" data-action="download-file" data-id="${esc(file.id)}" title="Unduh" aria-label="Unduh ${esc(name)}" ${isBusy || unavailable ? 'disabled' : ''}>${isBusy ? `${state.downloadProgress}%` : icon('download',16)}</button></div></div></article>`;
  }).join('');
  const hasFilter = Boolean(state.search || state.selectedTag);
  const emptyTitle = hasFilter ? 'Tidak ada berkas yang cocok' : currentFolder ? 'Folder masih kosong' : 'Brankas masih kosong';
  const emptyCopy = hasFilter ? 'Coba kata pencarian atau filter lain.' : currentFolder ? 'Buat subfolder atau unggah berkas ke folder ini.' : 'Buat folder atau unggah berkas pertama Anda. Data dienkripsi sebelum disimpan.';
  const emptyAction = hasFilter ? '' : btn(state.unlocked ? 'upload' : 'open-unlock', `${icon(state.unlocked ? 'plus' : 'key',16)} ${state.unlocked ? 'Unggah berkas' : 'Buka brankas'}`, 'btn-primary');
  const emptyMarkup = `<div class="drive-grid-empty"><div class="drive-empty-art">${icon(hasFilter ? 'search' : 'file', 42)}</div><h3>${emptyTitle}</h3><p>${emptyCopy}</p>${emptyAction}</div>`;
  return `<div class="container page-container drive-dashboard">
    ${state.currentFolderId ? `<div class="drive-breadcrumbs"><button type="button" data-action="folder-root">${icon('home',15)} Brankas Saya</button>${breadcrumbs.map(folder => `<span>/</span><button type="button" data-action="folder-open" data-id="${esc(folder.id)}">${esc(state.unlocked ? folder.decryptedFileName : 'Folder terenkripsi')}</button>`).join('')}</div>` : ''}
    <div class="drive-page-heading"><div><h1>${title}</h1><p>Berkas Anda dienkripsi di perangkat sebelum disimpan.</p></div>${state.unlocked ? `<div class="drive-vault-controls" aria-label="Kontrol brankas"><span class="badge badge-emerald">${icon('unlock', 13)} RAM Active</span>${btn('lock-vault', `${icon('lock',14)} Kunci`, 'btn-secondary btn-sm')}${btn('open-passphrase', `${icon('refresh',13)} Re-Wrap`, 'btn-outline btn-sm')}</div>` : ''}</div>
    <div class="drive-search-row"><div class="search-wrap">${icon('search',20)}<input id="file-search" class="input-control" type="search" aria-label="Cari berkas" placeholder="Telusuri berkas di brankas" value="${esc(state.search)}"></div><button class="drive-refresh" type="button" data-action="refresh-files" title="Muat ulang berkas" aria-label="Muat ulang berkas">${icon('refresh',18)}</button></div>
    <div class="drive-filter-row"><label class="drive-sort-label" for="sort-by">Urutkan</label><select id="sort-by" class="input-control sort-select"><option value="date" ${state.sortBy==='date'?'selected':''}>Tanggal</option><option value="name" ${state.sortBy==='name'?'selected':''}>Nama</option><option value="size" ${state.sortBy==='size'?'selected':''}>Ukuran</option></select><button class="drive-sort-direction" type="button" data-action="sort-direction" title="Balik urutan" aria-label="Balik urutan">${icon('arrow',16)}</button><span class="drive-filter-spacer"></span><span class="drive-file-count">${list.length} berkas</span><div class="drive-layout-toggle" role="group" aria-label="Tampilan berkas"><button type="button" data-action="file-layout" data-layout="list" class="${state.fileLayout === 'list' ? 'active' : ''}" title="Tampilan daftar" aria-label="Tampilan daftar" aria-pressed="${state.fileLayout === 'list'}">${icon('list',18)}</button><button type="button" data-action="file-layout" data-layout="grid" class="${state.fileLayout === 'grid' ? 'active' : ''}" title="Tampilan kartu" aria-label="Tampilan kartu" aria-pressed="${state.fileLayout === 'grid'}">${icon('grid',18)}</button></div></div>
    ${allTags.length ? `<div class="tag-filters"><span>Filter tag:</span><button class="badge ${state.selectedTag === null ? 'badge-cyan' : 'badge-muted'}" data-action="tag-filter" data-tag="">Semua</button>${allTags.map(tag => `<button class="badge ${state.selectedTag === tag ? 'badge-cyan' : 'badge-muted'}" data-action="tag-filter" data-tag="${esc(tag)}">#${esc(tag)}</button>`).join('')}</div>` : ''}
    ${alertTemplate(state.filesError)}
    ${folderList.length ? `<div class="drive-section-heading"><h2>Folder</h2><span>${folderList.length} folder</span></div><div class="drive-folder-grid">${folderCards}</div>` : ''}
    <div class="drive-section-heading"><h2>${state.currentFolderId ? 'Berkas dalam folder' : 'Berkas saya'}</h2><span>${state.unlocked ? 'Nama berkas didekripsi secara lokal' : 'Buka brankas untuk melihat nama berkas'}</span></div>
    <div class="drive-grid-view ${state.fileLayout === 'grid' ? '' : 'drive-list-hidden'}">${state.filesLoading ? '<div class="drive-grid-message">Memuat berkas terenkripsi...</div>' : list.length ? `<div class="drive-file-grid">${gridCards}</div>` : folderList.length ? '<div class="drive-grid-message">Belum ada berkas di lokasi ini.</div>' : emptyMarkup}</div>
    <div class="glass-card table-card ${state.fileLayout === 'grid' || (!list.length && folderList.length) ? 'drive-list-hidden' : ''}"><div class="table-scroll"><table class="data-table files-table"><thead><tr><th>Nama Berkas</th><th>Ukuran</th><th>Potongan (Chunks)</th><th>Label / Tag</th><th>Tanggal Unggah</th><th class="text-right">Aksi</th></tr></thead><tbody>
      ${state.filesLoading ? '<tr><td colspan="6" class="empty-state">Memuat daftar berkas terenkripsi...</td></tr>' : list.length === 0 ? `<tr><td colspan="6"><div class="empty-vault"><div class="empty-icon">${icon('file',30)}</div><h4>${emptyTitle}</h4><p>${emptyCopy}</p>${emptyAction}</div></td></tr>` : list.map(file => {
        const isBusy = state.downloadingId === file.id;
        const filename = state.unlocked ? (file.decryptedFileName || file.encrypted_file_name) : '•••••••••••••••••••• (Terenkripsi)';
        const deleting = Boolean(file.deletion_pending);
        const incomplete = file.upload_status === 'uploading';
        const statusLabel = deleting ? '<span class="badge badge-amber">Penghapusan tertunda</span>' : incomplete ? '<span class="badge badge-amber">Unggahan belum lengkap</span>' : `<span class="badge badge-cyan">${esc(file.total_chunks)} chunk (${(Number(file.file_size_bytes)/(1024*1024)).toFixed(1)} MB)</span>`;
        return `<tr><td><div class="file-name-cell"><div class="file-type-icon">${fileIcon(file.decryptedFileName || '')}</div><div><b>${esc(filename)}</b><small class="mono">ID: ${esc(file.id.substring(0, 8))}…</small></div></div></td><td>${(Number(file.file_size_bytes)/(1024*1024)).toFixed(2)} MB</td><td>${statusLabel}</td><td>${state.unlocked && file.tags?.length ? file.tags.map(tag=>`<span class="badge badge-emerald tag-badge">#${esc(tag)}</span>`).join(' ') : '<span class="muted">-</span>'}</td><td class="date-cell">${esc(dateText(file.created_at))}</td><td><div class="file-actions"><button class="btn btn-secondary btn-sm" data-action="preview-file" data-id="${esc(file.id)}" ${isBusy || incomplete || deleting?'disabled':''}>${icon('file',13)} Pratinjau</button><button class="btn btn-primary btn-sm" data-action="download-file" data-id="${esc(file.id)}" ${isBusy || incomplete || deleting?'disabled':''}>${isBusy ? `${state.downloadProgress}%` : `${icon('download',13)} Unduh`}</button><button class="btn btn-secondary btn-sm icon-btn" data-action="file-details" data-id="${esc(file.id)}" title="Spesifikasi Kriptografis" ${incomplete || deleting?'disabled':''}>${icon('info',14)}</button><button class="btn btn-danger btn-sm icon-btn" data-action="delete-file" data-id="${esc(file.id)}" title="${deleting?'Lanjutkan penghapusan':'Hapus Berkas'}">${icon('trash',14)}</button></div></td></tr>`;
      }).join('')}
    </tbody></table></div></div>
  </div>`;
}
const AUDIT_ACTION_LABELS = {
  USER_REGISTER: 'Akun baru didaftarkan',
  AUTH_LOGIN: 'Masuk ke akun',
  AUTH_LOGIN_FAILED: 'Gagal masuk ke akun',
  AUTH_CREDENTIALS_VERIFIED: 'Nama pengguna dan kata sandi benar',
  AUTH_MFA_ENROLLED: 'Authenticator berhasil diaktifkan',
  AUTH_MFA_SUCCESS: 'Kode autentikator berhasil diverifikasi',
  AUTH_MFA_FAILED: 'Kode autentikator gagal diverifikasi',
  AUTH_LOGOUT: 'Keluar dari akun',
  VAULT_SETUP: 'Brankas dibuat',
  VAULT_REWRAP_MK: 'Kata sandi brankas diubah',
  FOLDER_CREATE: 'Folder dibuat',
  FOLDER_DELETE: 'Folder dihapus',
  FILE_INIT: 'Unggah berkas dimulai',
  FILE_CHUNK_UPLOAD: 'Bagian berkas diunggah',
  FILE_UPLOAD_COMPLETE: 'Unggah berkas selesai',
  FILE_DOWNLOAD: 'Berkas diunduh',
  FILE_DELETE_PENDING: 'Penghapusan berkas dimulai',
  FILE_DELETE: 'Berkas dihapus',
  FILE_METADATA_UPDATE: 'Nama atau label berkas diubah',
  FILE_UPLOAD_INTEGRITY_FAILURE: 'Pemeriksaan berkas gagal saat diunggah',
  FILE_DOWNLOAD_INTEGRITY_FAILURE: 'Pemeriksaan berkas gagal saat diunduh',
  ADMIN_UPDATE_QUOTA: 'Batas penyimpanan pengguna diubah',
  ADMIN_REVOKE_USER_SESSION: 'Sesi pengguna dihentikan administrator',
  ADMIN_ACCOUNT_DEACTIVATED: 'Akun pengguna dinonaktifkan administrator',
  ADMIN_ACCOUNT_REACTIVATED: 'Akun pengguna diaktifkan kembali administrator',
  ADMIN_DELETE_USER: 'Akun pengguna dihapus administrator',
  ADMIN_ROLE_PROMOTION: 'Pengguna dijadikan administrator',
  ADMIN_CREATE_USER: 'Administrator membuat akun pengguna',
  AUTH_ACTIVATION_LINK_SENT: 'Tautan aktivasi email dikirim',
  ADMIN_RESEND_ACTIVATION_LINK: 'Administrator mengirim ulang tautan aktivasi',
  AUTH_EMAIL_CODE_SENT: 'Kode verifikasi email dikirim',
  AUTH_EMAIL_VERIFY_FAILED: 'Kode verifikasi email salah',
  AUTH_EMAIL_VERIFIED: 'Email berhasil diverifikasi',
  AUTH_ONBOARDING_COMPLETE: 'Akun pengguna diaktifkan'
};
function auditActionLabel(action) {
  return AUDIT_ACTION_LABELS[action] || 'Aktivitas sistem lainnya';
}
function auditDetailsLabel(details) {
  if (!details) return '';
  const labels = {
    size_bytes: 'Ukuran berkas',
    file_size_bytes: 'Ukuran berkas',
    ciphertext_bytes: 'Data terenkripsi',
    quota_bytes: 'Batas penyimpanan',
    total_chunks: 'Jumlah bagian',
    chunk_index: 'Bagian ke',
    fields: 'Yang diubah',
    upload_status: 'Kondisi unggahan'
  };
  return details.split(';').map(part => {
    const [key, value] = part.split('=');
    if (!labels[key] || !value) return '';
    if (key.endsWith('_bytes')) return `${labels[key]}: ${bytes(Number(value))}`;
    if (key === 'chunk_index') return `${labels[key]}: ${Number(value) + 1}`;
    if (key === 'fields') return `${labels[key]}: ${value.split(',').map(field => ({name: 'nama', tags: 'label'}[field] || 'informasi berkas')).join(', ')}`;
    if (key === 'upload_status') return `${labels[key]}: ${value === 'completed' ? 'selesai' : 'belum selesai'}`;
    return `${labels[key]}: ${value}`;
  }).filter(Boolean).join(' · ');
}
function auditTemplate() {
  const a = state.audit;
  const filtered = a.logs.filter(log => (a.action === 'ALL' || log.action_type === a.action) && (a.status === 'ALL' || log.status === a.status));
  const actions = [...new Set(a.logs.map(log => log.action_type))].sort((left, right) => auditActionLabel(left).localeCompare(auditActionLabel(right), 'id'));
  const successful = a.logs.filter(log => log.status === 'SUCCESS').length;
  const failed = a.logs.filter(log => log.status === 'FAILED').length;
  return `<div class="container page-container drive-dashboard admin-console audit-console"><div class="drive-page-heading admin-page-head"><div><h1>Jejak Audit</h1><p>Pantau seluruh aktivitas sistem yang tercatat.</p></div><div class="drive-heading-actions">${btn('refresh-audit', `${icon('refresh',16)} Perbarui data`, 'btn-secondary btn-sm')}</div></div>
    ${errorBox(a.error)}
    <div class="drive-section-heading admin-section-heading"><h2>Ringkasan audit</h2><span>Seluruh catatan aktivitas sistem</span></div>
    <section class="admin-overview" aria-label="Ringkasan audit">
      <div class="admin-metric"><div class="admin-metric-copy"><strong>${a.logs.length}</strong><span class="admin-metric-label">Total aktivitas</span><small>Catatan dalam rantai audit</small></div><span class="admin-metric-icon" aria-hidden="true">${icon('database',22)}</span></div>
      <div class="admin-metric"><div class="admin-metric-copy"><strong>${successful}</strong><span class="admin-metric-label">Berhasil</span><small>Aktivitas selesai</small></div><span class="admin-metric-icon is-green" aria-hidden="true">${icon('check',22)}</span></div>
      <div class="admin-metric"><div class="admin-metric-copy"><strong>${failed}</strong><span class="admin-metric-label">Gagal</span><small>Aktivitas tidak selesai</small></div><span class="admin-metric-icon is-amber" aria-hidden="true">${icon('alert',22)}</span></div>
    </section>
    <section class="admin-table-card audit-table-card" aria-labelledby="audit-log-title"><div class="drive-section-heading admin-table-heading"><h2 id="audit-log-title">Daftar aktivitas</h2><span>${filtered.length} dari ${a.logs.length} catatan</span></div><div class="admin-table-tools audit-table-tools"><label class="admin-filter-wrap" for="audit-action"><span>Aktivitas</span><select id="audit-action"><option value="ALL">Semua aktivitas</option>${actions.map(x=>`<option value="${esc(x)}" ${a.action===x?'selected':''}>${esc(auditActionLabel(x))}</option>`).join('')}</select></label><label class="admin-filter-wrap" for="audit-status"><span>Status</span><select id="audit-status"><option value="ALL">Semua status</option><option value="SUCCESS" ${a.status==='SUCCESS'?'selected':''}>Berhasil</option><option value="FAILED" ${a.status==='FAILED'?'selected':''}>Gagal</option></select></label></div><div class="table-scroll"><table class="data-table admin-table audit-table"><thead><tr><th scope="col">No.</th><th scope="col">Waktu</th><th scope="col">Aktivitas</th><th scope="col">Alamat IP</th><th scope="col">Status</th></tr></thead><tbody>${a.loading ? '<tr><td colspan="5" class="empty-state">Memuat catatan audit...</td></tr>' : !filtered.length ? '<tr><td colspan="5" class="empty-state">Belum ada aktivitas yang sesuai dengan filter.</td></tr>' : filtered.map(log=>`<tr><td><span class="audit-sequence">#${esc(log.sequence_number)}</span></td><td>${esc(dateText(log.timestamp))}</td><td><strong class="audit-action-name">${esc(auditActionLabel(log.action_type))}</strong>${auditDetailsLabel(log.details) ? `<small class="table-subtext">${esc(auditDetailsLabel(log.details))}</small>` : ''}</td><td><span class="audit-user-id mono">${esc(log.ip_address || 'Tidak tersedia')}</span></td><td><span class="audit-status ${log.status==='SUCCESS'?'is-success':'is-failed'}">${log.status==='SUCCESS'?'Berhasil':log.status==='FAILED'?'Gagal':esc(log.status)}</span></td></tr>`).join('')}</tbody></table></div></section>
  </div>`;
}
function adminUserRow(u) {
  const protectedAdmin = u.role === 'admin';
  const quotaGb = (Number(u.storage_quota_bytes) / (1024 ** 3)).toFixed(1);
  const usedMb = (Number(u.storage_used_bytes) / (1024 ** 2)).toFixed(1);
  const accountStatus = u.onboarding_pending ? 'MENUNGGU AKTIVASI' : u.is_active ? 'AKTIF' : 'DINONAKTIFKAN';
  const emailStatus = u.email_verified_at ? `Email terverifikasi: ${esc(dateText(u.email_verified_at))}` : u.onboarding_pending ? 'Email belum diverifikasi' : 'Verifikasi email tidak tercatat';
  const action = protectedAdmin ? '' : u.is_active
    ? btn('admin-revoke', `${icon('lock', 13)} Cabut Sesi & Nonaktifkan`, 'btn-danger btn-sm', `data-id="${esc(u.id)}"`)
    : (u.onboarding_pending ? '' : btn('admin-reactivate', `${icon('check', 13)} Aktifkan Akun`, 'btn-secondary btn-sm', `data-id="${esc(u.id)}"`))
      + btn('admin-delete-user', `${icon('trash', 13)} Hapus Akun`, 'btn-danger btn-sm', `data-id="${esc(u.id)}" data-username="${esc(u.username)}"`);
  const resend = !protectedAdmin && u.onboarding_pending && !u.email_verified_at ? btn('admin-resend-code', `${icon('refresh', 13)} Kirim Ulang Aktivasi`, 'btn-secondary btn-sm', `data-id="${esc(u.id)}"`) : '';
  return `<tr class="${protectedAdmin ? 'admin-protected-row' : ''}"><td><div class="admin-person"><span class="admin-person-meta"><strong>${esc(u.username)}</strong><small title="${esc(u.email)}">${esc(u.email)}</small></span></div></td><td><span class="admin-role ${protectedAdmin ? 'is-admin' : ''}">${protectedAdmin ? 'Administrator' : 'Pengguna'}</span></td><td><strong class="admin-cell-value">${quotaGb} GB</strong><small class="admin-cell-note">${usedMb} MB digunakan</small></td><td><span class="admin-account-status ${u.onboarding_pending ? 'is-pending' : u.is_active ? 'is-active' : 'is-inactive'}"><span aria-hidden="true"></span>${accountStatus}</span><small class="admin-cell-note">${emailStatus}</small></td><td class="admin-actions-cell">${protectedAdmin ? '<span class="admin-protected-label">Akun terlindungi</span>' : `<div class="admin-row-actions">${btn('admin-quota', `${icon('database', 13)} Kuota`, 'btn-secondary btn-sm', `data-id="${esc(u.id)}" data-quota="${quotaGb}"`)}${resend}${action}</div>`}</td></tr>`;
}
function adminVisibleUsers() {
  const a = state.admin;
  const search = a.search.trim().toLocaleLowerCase('id-ID');
  return a.users.filter(u => {
    const status = u.onboarding_pending ? 'pending' : u.is_active ? 'active' : 'inactive';
    return (a.status === 'all' || a.status === status) && (!search || `${u.username} ${u.email}`.toLocaleLowerCase('id-ID').includes(search));
  });
}
function refreshAdminTable() {
  const visible = adminVisibleUsers();
  const body = $('.admin-table tbody');
  if (body) body.innerHTML = visible.length ? visible.map(adminUserRow).join('') : `<tr><td colspan="5" class="empty-state">${state.admin.users.length ? 'Tidak ada akun yang sesuai dengan pencarian atau filter.' : 'Belum ada akun pengguna.'}</td></tr>`;
  const count = $('.admin-result-count');
  if (count) count.textContent = `${visible.length} dari ${state.admin.users.length} akun`;
}
function adminTemplate() {
  const a = state.admin; const s = a.stats;
  const total = a.users.length;
  const active = a.users.filter(u => !u.onboarding_pending && u.is_active).length;
  const pending = a.users.filter(u => u.onboarding_pending).length;
  const inactive = total - active - pending;
  const allocated = a.users.reduce((sum, u) => sum + Math.max(0, Number(u.storage_quota_bytes) || 0), 0);
  const used = a.users.reduce((sum, u) => sum + Math.max(0, Number(u.storage_used_bytes) || 0), 0);
  const usedPercent = allocated ? Math.min(100, used / allocated * 100) : 0;
  const usedPercentLabel = `${usedPercent.toLocaleString('id-ID', { maximumFractionDigits: 2 })}%`;
  const activeWidth = total ? active / total * 640 : 0;
  const pendingWidth = total ? pending / total * 640 : 0;
  const inactiveWidth = total ? 640 - activeWidth - pendingWidth : 0;
  const statusLabel = `Status akun: ${active} aktif, ${pending} menunggu aktivasi, ${inactive} nonaktif`;
  const visible = adminVisibleUsers();
  return `<div class="container page-container drive-dashboard admin-console"><div class="drive-page-heading admin-page-head"><div><h1>Konsol Admin</h1><p>Kelola akun, pantau kapasitas, dan periksa status sistem.</p></div><div class="drive-heading-actions">${btn('refresh-admin', `${icon('refresh',16)} Perbarui data`, 'btn-secondary btn-sm')}</div></div>
    ${errorBox(a.error)}
    <div class="drive-section-heading admin-section-heading"><h2>Ringkasan sistem</h2><span>Status akun dan penyimpanan</span></div>
    <section class="admin-overview" aria-label="Ringkasan sistem">
      <div class="admin-metric"><div class="admin-metric-copy"><strong>${total}</strong><span class="admin-metric-label">Total akun</span><small>Termasuk administrator</small></div><span class="admin-metric-icon" aria-hidden="true">${icon('users',22)}</span></div>
      <div class="admin-metric"><div class="admin-metric-copy"><strong>${active}</strong><span class="admin-metric-label">Akun aktif</span><small>Siap digunakan</small></div><span class="admin-metric-icon is-green" aria-hidden="true">${icon('check',22)}</span></div>
      <div class="admin-metric"><div class="admin-metric-copy"><strong>${pending}</strong><span class="admin-metric-label">Menunggu aktivasi</span><small>Perlu verifikasi email</small></div><span class="admin-metric-icon is-amber" aria-hidden="true">${icon('refresh',22)}</span></div>
      <div class="admin-metric"><div class="admin-metric-copy"><strong>${inactive}</strong><span class="admin-metric-label">Akun nonaktif</span><small>Akses dibatasi</small></div><span class="admin-metric-icon is-slate" aria-hidden="true">${icon('lock',22)}</span></div>
    </section>
    <section class="admin-insights" aria-label="Status akun dan penyimpanan"><div class="admin-insight-card"><div class="admin-card-heading"><h2>Distribusi status akun</h2><span class="admin-card-total">${total} akun</span></div><svg class="admin-status-chart" viewBox="0 0 640 28" role="img" aria-label="${statusLabel}" preserveAspectRatio="none"><title>${statusLabel}</title><rect width="640" height="28" class="admin-chart-track"/><rect width="${activeWidth}" height="28" class="admin-chart-active"/><rect x="${activeWidth}" width="${pendingWidth}" height="28" class="admin-chart-pending"/><rect x="${activeWidth + pendingWidth}" width="${inactiveWidth}" height="28" class="admin-chart-inactive"/></svg><div class="admin-chart-legend"><span><i class="is-active"></i>Aktif <b>${active}</b></span><span><i class="is-pending"></i>Menunggu <b>${pending}</b></span><span><i class="is-inactive"></i>Nonaktif <b>${inactive}</b></span></div></div>
      <div class="admin-insight-card"><div class="admin-card-heading"><h2>Kapasitas teralokasi</h2><span class="admin-card-total">${usedPercentLabel}</span></div><div class="admin-capacity-values"><strong>${bytes(used)}</strong><span>digunakan dari ${bytes(allocated)}</span></div><progress class="vault-progress admin-capacity-progress" max="100" value="${usedPercent}" aria-label="Pemakaian penyimpanan ${usedPercentLabel}"></progress><div class="admin-capacity-footer"><span>${Number(s?.totalFiles || 0)} berkas terenkripsi</span><span>${Number(s?.auditChainLength || 0)} catatan audit</span></div></div></section>
    <section class="admin-create-card" aria-labelledby="admin-create-title"><div class="admin-create-intro"><span class="admin-create-icon">${icon('users',20)}</span><div><h2 id="admin-create-title">Buat akun pengguna</h2><p>Tautan aktivasi dikirim ke email. Pengguna membuat kata sandi sendiri sebelum login.</p></div></div><form data-form="admin-create-user" class="admin-create-form"><div class="input-group"><label class="input-label">Username</label><input class="input-control" name="username" minlength="3" maxlength="64" pattern="[A-Za-z0-9_.-]+" placeholder="Nama pengguna" required autocomplete="off"></div><div class="input-group"><label class="input-label">Email pengguna</label><input class="input-control" name="email" type="email" placeholder="nama@perusahaan.com" required autocomplete="off"></div><button class="btn btn-primary" type="submit" ${a.creating?'disabled':''}>${a.creating?'Membuat akun...':`${icon('plus',16)} Buat akun`}</button></form></section>
    <section class="admin-table-card" aria-labelledby="admin-users-title"><div class="drive-section-heading admin-table-heading"><h2 id="admin-users-title">Daftar akun pengguna</h2><span class="admin-result-count">${visible.length} dari ${total} akun</span></div><div class="admin-table-tools"><label class="admin-search-wrap">${icon('search',19)}<span class="sr-only">Cari username atau email</span><input id="admin-search" type="search" placeholder="Cari username atau email" value="${esc(a.search)}" autocomplete="off"></label><label class="admin-filter-wrap"><span>Status</span><select id="admin-status-filter" aria-label="Filter status akun"><option value="all" ${a.status==='all'?'selected':''}>Semua status</option><option value="active" ${a.status==='active'?'selected':''}>Aktif</option><option value="pending" ${a.status==='pending'?'selected':''}>Menunggu aktivasi</option><option value="inactive" ${a.status==='inactive'?'selected':''}>Nonaktif</option></select></label></div><div class="table-scroll"><table class="data-table admin-table"><thead><tr><th scope="col">Akun</th><th scope="col">Peran</th><th scope="col">Penyimpanan</th><th scope="col">Status</th><th scope="col">Tindakan</th></tr></thead><tbody>${a.loading ? '<tr><td colspan="5" class="empty-state">Memuat daftar pengguna...</td></tr>' : visible.length ? visible.map(adminUserRow).join('') : `<tr><td colspan="5" class="empty-state">${total ? 'Tidak ada akun yang sesuai dengan pencarian atau filter.' : 'Belum ada akun pengguna.'}</td></tr>`}</tbody></table></div></section>
  </div>`;
}
function modalShell(title, subtitle, content, width = '600px') {
  return `<div class="modal-overlay" data-action="overlay-close"><div class="modal-content ${width === '560px' ? 'modal-narrow' : width === '640px' ? 'modal-wide' : 'modal-default'}" data-modal-inner><div class="modal-header"><div><h3>${title}</h3><p>${subtitle}</p><small class="build-stamp">${APP_BUILD}</small></div><button class="modal-close" type="button" data-action="close-modal" aria-label="Tutup">${icon('close',20)}</button></div>${content}</div></div>`;
}
function unlockModalTemplate() {
  const p = state.vaultProfile || {};
  const isInit = !p.hasProfile;
  return modalShell(isInit ? 'Inisialisasi Brankas Pribadi' : 'Buka Kunci Brankas Pribadi', isInit ? 'Buat passphrase rahasia untuk brankas Zero-Knowledge Anda.' : 'Masukkan passphrase brankas untuk membuka Master Key (MK) di RAM browser.',
    `<div class="zero-warning">${icon('shield',22)}<div><strong>Peringatan Nol-Pemulihan (Zero-Knowledge Guarantee):</strong><br>Passphrase Anda tidak pernah dikirim ke server. Jika Anda lupa passphrase, data berkas tidak dapat dipulihkan oleh administrator sistem maupun pihak mana pun.</div></div>
    <div data-modal-error>${errorBox(state.modalError)}</div>
    <div class="stage-status ${state.modalLoading && state.modalStage ? 'is-visible' : ''}" data-progress-stage role="status" aria-live="polite">${state.modalLoading && state.modalStage ? `${icon('refresh',17)} ${esc(state.modalStage)}` : ''}</div>
    <form data-form="${isInit?'vault-init':'vault-unlock'}" class="form-stack" novalidate><div class="input-group"><label class="input-label">${isInit?'Passphrase Brankas Baru':'Passphrase Brankas'}</label><input class="input-control" name="passphrase" type="password" placeholder="${isInit?'Minimal 12 karakter':'Masukkan passphrase brankas'}" required ${isInit?'minlength="12"':''} autocomplete="current-password"></div>
    ${isInit ? `<div class="input-group"><label class="input-label">Konfirmasi Passphrase</label><input class="input-control" name="confirmPassphrase" type="password" placeholder="Ketik ulang passphrase" required minlength="12" autocomplete="new-password"></div>` : ''}
    <div class="modal-actions"><button type="button" class="btn btn-secondary" data-action="close-modal" data-progress-cancel ${state.modalLoading?'disabled':''}>Batal</button><button type="submit" class="btn btn-primary" data-progress-submit ${state.modalLoading?'disabled':''} data-idle-label="${isInit?'Inisialisasi & Buka Brankas':'Buka Kunci Brankas'}" data-loading-label="${isInit?'Menginisialisasi...':'Mendekripsi KEK...'}">${state.modalLoading?(isInit?'Menginisialisasi...':'Mendekripsi KEK...'):(isInit?'Inisialisasi & Buka Brankas':'Buka Kunci Brankas')}</button></div></form>`, '600px');
}
function uploadModalTemplate() {
  const u = state.upload;
  return modalShell('Unggah Berkas Terenkripsi', 'Chunking 5 MB • AES-256-GCM + AAD • Zero-Knowledge',
    `${errorBox(u.error)}<div class="drop-zone" id="drop-zone" data-action="choose-file"><input type="file" id="upload-file" hidden ${u.uploading?'disabled':''}><div class="drop-icon">${icon('lock',28)}</div><strong>${u.file ? esc(u.file.name) : 'Tarik & letakkan berkas di sini atau klik untuk memilih'}</strong><p>${u.file ? `${(u.file.size/(1024*1024)).toFixed(2)} MB — Siap dienkripsi` : 'Batas ukuran berkas: 500 MB (MVP). Berkas dienkripsi di peramban sebelum dikirim.'}</p><button type="button" class="btn btn-secondary btn-sm" data-action="choose-file" ${u.uploading?'disabled':''}>Pilih Berkas</button></div>
    <div class="input-group upload-tags-group"><label class="input-label">Label / Tag Virtual Terenkripsi (Pisahkan dengan koma)</label><input class="input-control" id="upload-tags" value="${esc(u.tags)}" ${u.uploading?'disabled':''}></div>
    ${u.uploading ? `<div class="upload-progress"><div class="progress-copy"><strong>${esc(u.status)}</strong><span>${u.progress}%</span></div><progress class="vault-progress upload-vault-progress" max="100" value="${u.progress}" aria-label="Progres unggah ${u.progress}%">${u.progress}%</progress><small>Setiap potongan 5 MB dienkripsi secara independen dengan kunci DEK acak dan tag AAD anti-penukaran.</small></div>` : '<div class="upload-note">Batas ukuran berkas: 500 MB (MVP). Berkas dienkripsi di peramban sebelum dikirim.</div>'}
    <div class="modal-actions"><button type="button" class="btn btn-secondary" data-action="close-modal" ${u.uploading?'disabled':''}>Batal</button><button type="button" class="btn btn-primary" data-action="start-upload" ${!u.file||u.uploading||!state.unlocked?'disabled':''}>${u.uploading?'Mengunggah...':`${icon('shield',15)} Enkripsi Sisi-Klien & Unggah`}</button></div>`, '640px');
}
function folderModalTemplate() {
  const form = state.folderForm;
  return modalShell('Folder baru', 'Nama folder dienkripsi di perangkat sebelum disimpan.',
    `${errorBox(form.error)}<form data-form="create-folder" class="form-stack"><div class="input-group"><label class="input-label" for="folder-name">Nama folder</label><input id="folder-name" name="folderName" class="input-control" maxlength="120" required value="${esc(form.name)}" placeholder="Masukkan nama folder" autocomplete="off"></div><div class="modal-actions"><button type="button" class="btn btn-secondary" data-action="close-modal" ${form.loading ? 'disabled' : ''}>Batal</button><button type="submit" class="btn btn-primary" ${form.loading ? 'disabled' : ''}>${form.loading ? 'Membuat...' : 'Buat folder'}</button></div></form>`, '560px');
}
function folderSelectModalTemplate() {
  return modalShell('Pilih folder', 'Pilih folder dari perangkat untuk diunggah secara terenkripsi.',
    `<p class="folder-select-hint">Struktur subfolder dipertahankan. Maksimal 1.000 berkas per pilihan dan 500 MB per berkas. Folder kosong dapat dibuat melalui menu “Folder baru”.</p><div class="modal-actions"><button type="button" class="btn btn-secondary" data-action="close-modal">Batal</button><button type="button" class="btn btn-primary" data-action="choose-folder">${icon('folderUpload',16)} Pilih folder</button></div>`, '560px');
}
function folderUploadModalTemplate() {
  const u = state.folderUpload;
  return modalShell('Upload folder', 'Setiap nama folder dan berkas dienkripsi sebelum dikirim.',
    `${errorBox(u.error)}<div class="folder-upload-status"><strong>${esc(u.current || 'Menyiapkan folder...')}</strong><p>${u.completed} dari ${u.total} berkas selesai</p><progress class="vault-progress upload-vault-progress" max="100" value="${u.progress}" aria-label="Progres upload folder ${u.progress}%">${u.progress}%</progress>${u.error ? '<p>Berkas yang sudah selesai tetap tersimpan. Periksa isi folder sebelum mencoba lagi.</p>' : ''}</div><div class="modal-actions"><button type="button" class="btn btn-secondary" data-action="close-modal" ${u.uploading ? 'disabled' : ''}>Tutup</button></div>`, '560px');
}
function changePassModalTemplate() {
  const p = state.passphrase;
  return modalShell('Ganti Passphrase (Re-Wrap MK)', 'Membungkus ulang 1 Master Key tanpa re-enkripsi berkas', `<div data-pass-error>${errorBox(p.error)}</div><div class="stage-status ${p.loading && p.stage ? 'is-visible' : ''}" data-pass-stage role="status" aria-live="polite">${p.loading && p.stage ? esc(p.stage) : ''}</div><form data-form="change-pass" class="form-stack" novalidate><div class="input-group"><label class="input-label">Passphrase Brankas Baru</label><input class="input-control" name="newPassphrase" type="password" placeholder="Minimal 12 karakter" minlength="12" required></div><div class="input-group"><label class="input-label">Konfirmasi Passphrase Baru</label><input class="input-control" name="confirmPassphrase" type="password" placeholder="Ulangi passphrase baru" minlength="12" required></div><div class="modal-actions"><button type="button" class="btn btn-secondary" data-action="close-modal" data-pass-cancel>Batal</button><button type="submit" class="btn btn-primary" data-pass-submit data-idle-label="Bungkus Ulang MK" data-loading-label="Memproses..." ${p.loading?'disabled':''}>${p.loading?'Memproses...':'Bungkus Ulang MK'}</button></div></form>`, '560px');
}
function detailsModalTemplate() {
  const f = state.selectedFile;
  if (!f) return '';
  const tags = f.tags || [];
  return modalShell('Spesifikasi Kriptografis Berkas', 'Arsitektur Envelope Encryption Sisi-Klien (Referensi Desain)', `${errorBox(state.modalError)}
    ${state.detailEditing ? `<div class="edit-meta-form"><div class="input-group"><label class="input-label">Nama Berkas Baru</label><input class="input-control" id="detail-name" value="${esc(state.detailName)}"></div><div class="input-group"><label class="input-label">Tag Virtual Baru (Pisahkan koma)</label><input class="input-control" id="detail-tags" value="${esc(state.detailTags)}"></div><div class="modal-actions"><button class="btn btn-secondary btn-sm" data-action="detail-cancel">Batal</button><button class="btn btn-primary btn-sm" data-action="detail-save" ${state.detailSaving?'disabled':''}>${state.detailSaving?'Mengenkripsi & Menyimpan...':'Simpan Perubahan'}</button></div></div>` : `<div class="detail-file-heading"><div><h4>${esc(f.decryptedFileName || 'Nama Berkas Terenkripsi')}</h4><div>${tags.map(tag=>`<span class="badge badge-emerald tag-badge">#${esc(tag)}</span>`).join(' ')}</div></div><button class="btn btn-secondary btn-sm" data-action="detail-edit">${icon('edit',13)} Edit Nama & Tag</button></div>`}
    <div class="technical-specs"><div><small>File ID (UUID v4)</small><code>${esc(f.id)}</code></div><div><small>Wrapped DEK (256-bit AES-KW dibungkus Master Key)</small><code class="wrapped-key">${esc(f.wrapped_dek)}</code></div><div class="spec-grid"><div><small>Ukuran Berkas</small><b>${(Number(f.file_size_bytes)/(1024*1024)).toFixed(2)} MB</b></div><div><small>Skema Chunking</small><b>${esc(f.total_chunks)} chunk × 5 MB (AES-256-GCM)</b></div></div><div><small>Formula Pengikatan AAD</small><code>AAD = {file_id}-{chunk_index} (Anti-Swap Urutan)</code></div></div>
    <div class="modal-actions"><button class="btn btn-secondary" data-action="close-modal">Tutup</button></div>`, '700px');
}
function previewModalTemplate() {
  const p = state.preview;
  if (!p) return '';
  let body = '';
  if (p.kind === 'image') body = `<div class="preview-image-wrap"><img src="${p.url}" alt="${esc(p.name)}"></div>`;
  else if (p.kind === 'pdf') body = `<iframe title="Pratinjau ${esc(p.name)}" src="${p.url}" referrerpolicy="no-referrer" class="preview-pdf"></iframe>`;
  else body = `<pre class="preview-text">${esc(p.textContent || '')}</pre>`;
  return `<div class="modal-overlay" data-action="preview-overlay"><div class="modal-content preview-modal" data-modal-inner><div class="preview-header"><strong>${esc(p.name)}</strong><button class="btn btn-secondary btn-sm" data-action="close-preview">Tutup</button></div>${body}</div></div>`;
}
function render() {
  applyTheme(state.theme);
  const main = state.activation ? activationTemplate() : !state.user ? loginTemplate() : state.user.role === 'admin' && state.activeTab === 'audit' ? auditTemplate() : state.user.role === 'admin' && state.activeTab === 'admin' ? adminTemplate() : dashboardTemplate();
  appRoot.innerHTML = `<div class="app-shell ${state.user && !state.activation ? 'drive-app-shell' : ''}">${headerTemplate()}${state.user && !state.activation ? `<div class="drive-app-body">${sidebarTemplate()}<main class="app-main">${main}</main></div>` : `<main class="app-main">${main}</main>${footerTemplate()}`}</div>`;
  let modal = '';
  if (state.modal === 'unlock') modal = unlockModalTemplate();
  if (state.modal === 'upload') modal = uploadModalTemplate();
  if (state.modal === 'new-folder') modal = folderModalTemplate();
  if (state.modal === 'folder-select') modal = folderSelectModalTemplate();
  if (state.modal === 'folder-upload') modal = folderUploadModalTemplate();
  if (state.modal === 'change-pass') modal = changePassModalTemplate();
  if (state.modal === 'details') modal = detailsModalTemplate();
  if (state.modal === 'preview') modal = previewModalTemplate();
  modalRoot.innerHTML = modal;
}

async function checkCurrentUser() {
  try {
    const result = await request('/auth/me');
    state.user = result.user;
    setAppHistory('app', 'files', true);
    resetIdleTimer();
    await fetchFiles();
    render();
  } catch {
    clearAuthToken(); state.user = null; render();
  }
}
function loginSuccess(user) {
  state.user = user; state.login = { ...state.login, onboardingStage:'', onboardingChallenge:'', onboardingPasswordToken:'', mfaRequired:false, password:'', totpCode:'', mfaSecret:'', mfaOtpUri:'', secretCopied:false, error:'', notice:'' };
  state.activeTab = 'files';
  setAppHistory('app', 'files');
  resetIdleTimer();
  showToast(`Selamat datang, ${user.username}! Otentikasi Zero-Trust terverifikasi.`);
  fetchFiles(); render();
  setTimeout(() => openModal('unlock'), 300);
}
function logout() {
  void request('/auth/logout', { method: 'POST' }).catch(() => undefined);
  clearTimeout(state.idleTimer); clearAuthToken(); clearVaultKeys(); terminateCryptoWorker(); state.user = null; state.unlocked = false;
  state.files = []; state.decryptedFiles = []; state.folders = []; state.decryptedFolders = []; state.currentFolderId = null; state.pendingVaultAction = null; state.activeTab = 'files'; setAppHistory('login', 'files', true); render();
  showToast('Logout berhasil. Kunci RAM & token sesi telah dimusnahkan.');
}
function openModal(name) {
  state.modal = name; state.modalError = ''; state.modalStage = ''; state.modalLoading = false;
  setAppHistory('app', state.activeTab, false, name);
  if (name === 'unlock') {
    state.vaultProfile = null;
    state.modalLoading = true; render();
    request('/auth/vault-profile').then(profile => { state.vaultProfile = profile; state.modalLoading = false; render(); }).catch(err => { if (!state.user) return; state.modalLoading = false; state.modalError = 'Gagal memeriksa profil brankas: ' + err.message; state.vaultProfile = { hasProfile: true }; render(); });
  } else if (name === 'upload') {
    state.upload = { file:null, tags:'Rahasia, BSSN, Sertifikasi', uploading:false, progress:0, currentChunk:0, totalChunks:0, status:'', error:'' };
    render();
  } else if (name === 'new-folder') {
    state.folderForm = { name:'', loading:false, error:'' }; render();
  } else if (name === 'change-pass') {
    state.passphrase = { newValue:'', confirm:'', loading:false, error:'', stage:'' }; render();
  } else render();
}
function closeModal() {
  if (state.modal === 'preview') { closePreview(); return; }
  if ((state.modal === 'upload' && state.upload.uploading) || (state.modal === 'folder-upload' && state.folderUpload.uploading) || (state.modal === 'new-folder' && state.folderForm.loading)) return;
  if (state.modal === 'unlock') state.pendingVaultAction = null;
  if (history.state?.secureVaultApp && history.state.view === 'app' && history.state.modal) {
    history.back();
    return;
  }
  state.modal = null; state.modalError = ''; state.modalLoading = false;
  setAppHistory('app', state.activeTab, true, null);
  render();
}
function closePreview() {
  if (history.state?.secureVaultApp && history.state.view === 'app' && history.state.modal === 'preview') {
    history.back();
    return;
  }
  if (state.preview?.url) URL.revokeObjectURL(state.preview.url);
  state.preview = null;
  if (state.modal === 'preview') state.modal = null;
  render();
}
async function fetchFiles() {
  if (!state.user) return;
  state.filesLoading = true; state.filesError = '';
  if (state.activeTab === 'files') render();
  try {
    const [fileResult, folderResult] = await Promise.all([request('/files'), request('/folders')]);
    state.files = fileResult.files || [];
    state.folders = folderResult.folders || [];
    if (state.currentFolderId && !state.folders.some(folder => folder.id === state.currentFolderId)) state.currentFolderId = null;
    await decryptFileMetadata();
  } catch (err) { state.filesError = err.message || 'Gagal memuat daftar berkas.'; }
  finally { state.filesLoading = false; if (state.activeTab === 'files') render(); }
}
async function decryptFileMetadata() {
  if (!state.unlocked || !getLoadedMasterKey()) { state.decryptedFiles = state.files; state.decryptedFolders = state.folders; return; }
  const masterKey = getLoadedMasterKey();
  async function decryptEntries(entries) {
    const list = [];
    for (const file of entries) {
    try {
      const dek = await unwrapDek(file.wrapped_dek, masterKey);
      let name = file.encrypted_file_name;
      if (name.includes(':')) { const [cipher, iv] = name.split(':'); name = await decryptText(cipher, iv, dek); }
      let tags = [];
      if (file.encrypted_tags?.includes(':')) { const [cipher, iv] = file.encrypted_tags.split(':'); tags = (await decryptText(cipher, iv, dek)).split(',').map(t=>t.trim()).filter(Boolean); }
      list.push({ ...file, decryptedFileName:name, tags });
    } catch { list.push({ ...file, decryptedFileName:'[Gagal dekripsi nama berkas]', tags:[] }); }
    }
    return list;
  }
  state.decryptedFiles = await decryptEntries(state.files);
  state.decryptedFolders = await decryptEntries(state.folders);
}
async function toggleVaultLock() {
  clearVaultKeys(); terminateCryptoWorker(); state.unlocked = false; state.decryptedFiles = state.files; state.decryptedFolders = state.folders; render();
  showToast('Brankas berhasil dikunci. Seluruh kunci di RAM telah dibersihkan secara mutlak.');
}
function updateVaultModalProgress(message, mode = 'init') {
  state.modalStage = message;
  const stage = modalRoot.querySelector('[data-progress-stage]');
  if (stage) {
    stage.innerHTML = `${icon('refresh',17)} ${esc(message)}`;
    stage.classList.add('is-visible');
  }
  const error = modalRoot.querySelector('[data-modal-error]');
  if (error) error.innerHTML = '';
  const submit = modalRoot.querySelector('[data-progress-submit]');
  if (submit) {
    submit.disabled = true;
    submit.textContent = submit.dataset.loadingLabel || (mode === 'unlock' ? 'Mendekripsi KEK...' : 'Menginisialisasi...');
  }
  const cancel = modalRoot.querySelector('[data-progress-cancel]');
  if (cancel) cancel.disabled = true;
}

function setVaultModalError(message) {
  state.modalLoading = false;
  state.modalError = String(message || 'Proses brankas gagal.');
  const error = modalRoot.querySelector('[data-modal-error]');
  if (error) error.innerHTML = errorBox(state.modalError);
  const stage = modalRoot.querySelector('[data-progress-stage]');
  if (stage) { stage.classList.remove('is-visible'); stage.innerHTML = ''; }
  const submit = modalRoot.querySelector('[data-progress-submit]');
  if (submit) { submit.disabled = false; submit.textContent = submit.dataset.idleLabel || 'Coba kembali'; }
  const cancel = modalRoot.querySelector('[data-progress-cancel]');
  if (cancel) cancel.disabled = false;
}

function updateChangePassProgress(message) {
  state.passphrase.stage = message;
  const stage = modalRoot.querySelector('[data-pass-stage]');
  if (stage) { stage.textContent = message; stage.classList.add('is-visible'); }
  const error = modalRoot.querySelector('[data-pass-error]');
  if (error) error.innerHTML = '';
  const submit = modalRoot.querySelector('[data-pass-submit]');
  if (submit) { submit.disabled = true; submit.textContent = submit.dataset.loadingLabel || 'Memproses...'; }
  const cancel = modalRoot.querySelector('[data-pass-cancel]');
  if (cancel) cancel.disabled = true;
}

function setChangePassError(message) {
  state.passphrase.loading = false;
  state.passphrase.error = String(message || 'Gagal mengganti passphrase.');
  const error = modalRoot.querySelector('[data-pass-error]');
  if (error) error.innerHTML = errorBox(state.passphrase.error);
  const stage = modalRoot.querySelector('[data-pass-stage]');
  if (stage) { stage.classList.remove('is-visible'); stage.textContent = ''; }
  const submit = modalRoot.querySelector('[data-pass-submit]');
  if (submit) { submit.disabled = false; submit.textContent = submit.dataset.idleLabel || 'Bungkus Ulang MK'; }
  const cancel = modalRoot.querySelector('[data-pass-cancel]');
  if (cancel) cancel.disabled = false;
}

async function handleUnlock(form) {
  if (state.modalLoading) return;
  const passphrase = form.elements.passphrase.value;
  if (!passphrase) { setVaultModalError('Passphrase brankas wajib diisi.'); return; }
  state.modalLoading = true; state.modalError = ''; updateVaultModalProgress('Menurunkan KEK dengan Argon2id WASM (64 MiB, 3 iterasi)...', 'unlock');
  const started = performance.now();
  try {
    const p = state.vaultProfile || {};
    const kek = await deriveKek(passphrase, b64ToUint8Array(p.argon2Salt), message => updateVaultModalProgress(message, 'unlock'));
    updateVaultModalProgress('Argon2id selesai. Membuka Master Key 256-bit via AES-KW...', 'unlock');
    let masterKey;
    try {
      masterKey = await unwrapMasterKey(p.wrappedMasterKey, kek);
    } catch {
      throw new Error('Passphrase brankas salah atau data kunci tidak cocok. Periksa kembali passphrase Anda.');
    }
    updateVaultModalProgress('Memvalidasi encrypted verifier string...', 'unlock');
    if (!await verifyPassphrase(masterKey, p.verifierCiphertext || '', p.verifierIv || '', p.verifierWrappedDek || '')) {
      throw new Error('Passphrase brankas salah atau verifier tidak cocok. Periksa kembali passphrase Anda.');
    }
    state.modalStage = `Berhasil dibuka dalam ${((performance.now()-started)/1000).toFixed(2)}s! Kunci disimpan di RAM (non-extractable).`;
    setLoadedKeys(kek, masterKey); state.unlocked = true;
    await decryptFileMetadata(); state.modalLoading = false; state.modal = null; setAppHistory('app', state.activeTab, true, null); render();
    showToast('Brankas berhasil dibuka! Master Key aktif di RAM non-extractable.');
    if (state.pendingVaultAction) { const next = state.pendingVaultAction; state.pendingVaultAction = null; openModal(next === 'new-folder' ? 'new-folder' : 'folder-select'); }
  } catch (err) { setVaultModalError(err.message || 'Gagal membuka brankas.'); }
}
async function handleInitializeVault(form) {
  if (state.modalLoading) return;
  const passphrase = form.elements.passphrase.value;
  const confirmation = form.elements.confirmPassphrase.value;
  if (!passphrase) { setVaultModalError('Passphrase brankas wajib diisi.'); return; }
  if (!confirmation) { setVaultModalError('Konfirmasi passphrase wajib diisi.'); return; }
  if (passphrase !== confirmation) { setVaultModalError('Konfirmasi passphrase tidak cocok.'); return; }
  if (passphrase.length < 12) { setVaultModalError('Passphrase minimal 12 karakter. Gunakan frasa sandi unik yang panjang.'); return; }
  state.modalLoading = true; state.modalError = ''; updateVaultModalProgress('Menghasilkan salt acak 16-byte unik...', 'init');
  try {
    const salt = generateSalt(16); const saltB64 = uint8ArrayToB64(salt);
    updateVaultModalProgress('Menurunkan KEK dengan Argon2id WASM (64 MiB, 3 iterasi)...', 'init');
    const kek = await deriveKek(passphrase, salt, message => updateVaultModalProgress(message, 'init'));
    updateVaultModalProgress('Argon2id selesai. Menghasilkan Master Key 256-bit baru...', 'init');
    const generated = await generateMasterKey();
    updateVaultModalProgress('Membungkus Master Key dengan KEK (AES-KW)...', 'init');
    const wrapped = await wrapMasterKey(generated, kek);
    const masterKey = await unwrapMasterKey(wrapped, kek);
    updateVaultModalProgress('Membuat encrypted verifier...', 'init');
    const verifier = await createVerifier(masterKey);
    updateVaultModalProgress('Menyimpan konfigurasi brankas Zero-Knowledge ke server...', 'init');
    await request('/auth/setup-vault', { method:'POST', body:JSON.stringify({ argon2Salt:saltB64, wrappedMasterKey:wrapped, verifierCiphertext:verifier.verifierCiphertext, verifierIv:verifier.verifierIv, verifierWrappedDek:verifier.verifierWrappedDek }) });
    state.vaultProfile = {
      hasProfile: true,
      argon2Salt: saltB64,
      wrappedMasterKey: wrapped,
      verifierCiphertext: verifier.verifierCiphertext,
      verifierIv: verifier.verifierIv,
      verifierWrappedDek: verifier.verifierWrappedDek
    };
    setLoadedKeys(kek, masterKey); state.unlocked = true; await decryptFileMetadata(); state.modalLoading = false; state.modal = null; setAppHistory('app', state.activeTab, true, null); render();
    showToast('Brankas berhasil diinisialisasi dan dibuka.');
    if (state.pendingVaultAction) { const next = state.pendingVaultAction; state.pendingVaultAction = null; openModal(next === 'new-folder' ? 'new-folder' : 'folder-select'); }
  } catch (err) { setVaultModalError(err.message || 'Gagal menginisialisasi brankas.'); }
}
async function handleChangePassphrase(form) {
  const next = form.elements.newPassphrase.value;
  const confirm = form.elements.confirmPassphrase.value;
  const masterKey = getLoadedMasterKey();
  const oldKek = getLoadedKek();
  const currentWrappedMasterKey = state.vaultProfile?.wrappedMasterKey;
  if (!masterKey || !oldKek || !currentWrappedMasterKey) {
    setChangePassError('Material kunci brankas tidak lengkap. Kunci brankas, buka kembali, lalu ulangi perubahan passphrase.');
    return;
  }
  if (!next) { setChangePassError('Passphrase baru wajib diisi.'); return; }
  if (!confirm) { setChangePassError('Konfirmasi passphrase baru wajib diisi.'); return; }
  if (next.length < 12) { setChangePassError('Passphrase baru minimal 12 karakter.'); return; }
  if (next !== confirm) { setChangePassError('Konfirmasi passphrase baru tidak cocok.'); return; }

  state.passphrase.loading = true;
  state.passphrase.error = '';
  updateChangePassProgress('1/4: Menghasilkan salt 16-byte unik baru...');
  try {
    const salt = generateSalt(16);
    const saltB64 = uint8ArrayToB64(salt);
    updateChangePassProgress('2/4: Menurunkan KEK baru via Argon2id WASM (64 MiB, 3 iterasi)...');
    const kek = await deriveKek(next, salt, message => updateChangePassProgress(message));
    updateChangePassProgress('3/4: Membuka salinan sementara Master Key dan membungkusnya dengan KEK baru...');
    const rewrapped = await rewrapMasterKeyForPassphrase(currentWrappedMasterKey, oldKek, kek);
    updateChangePassProgress('4/4: Memperbarui verifier dan menyimpan ke server...');
    await request('/auth/rewrap-master-key', { method:'POST', body:JSON.stringify({
      argon2Salt:saltB64,
      wrappedMasterKey:rewrapped.wrappedMasterKeyB64,
      verifierCiphertext:rewrapped.verifier.verifierCiphertext,
      verifierIv:rewrapped.verifier.verifierIv,
      verifierWrappedDek:rewrapped.verifier.verifierWrappedDek
    }) });
    // Keep the active session key non-extractable after the temporary re-wrap copy is released.
    setLoadedKeys(kek, rewrapped.sessionMasterKey);
    state.vaultProfile = {
      ...(state.vaultProfile || {}),
      argon2Salt: saltB64,
      wrappedMasterKey: rewrapped.wrappedMasterKeyB64,
      verifierCiphertext: rewrapped.verifier.verifierCiphertext,
      verifierIv: rewrapped.verifier.verifierIv,
      verifierWrappedDek: rewrapped.verifier.verifierWrappedDek
    };
    state.passphrase.loading = false;
    state.modal = null;
    setAppHistory('app', state.activeTab, true, null);
    render();
    showToast('Passphrase berhasil diganti & Master Key telah di-wrap ulang dengan KEK baru.');
  } catch (err) {
    setChangePassError(err.message || 'Gagal mengganti passphrase.');
  }
}
async function validateUploadFile(file) {
  const ext = file.name.split('.').pop()?.toLowerCase() || '';
  if (BLOCKED_EXTENSIONS.has(ext)) return 'Jenis file executable/script diblokir demi keamanan.';
  if (/[\\/:*?"<>|\x00-\x1f]/.test(file.name) || file.name.length > 180) return 'Nama file mengandung karakter berbahaya atau terlalu panjang.';
  if (MAGIC[ext]) {
    const head = new Uint8Array(await file.slice(0,16).arrayBuffer());
    if (!MAGIC[ext].some(signature => signature.every((byte,i)=>head[i]===byte))) return 'Signature file tidak cocok dengan ekstensi. Upload dibatalkan.';
  }
  return null;
}
async function selectUploadFile(file) {
  if (!file) return;
  if (!file.size) { state.upload.error='Berkas kosong belum didukung. Pilih berkas dengan ukuran minimal 1 byte.'; state.upload.file=null; render(); return; }
  if (file.size > MAX_FILE_SIZE) { state.upload.error=`Ukuran berkas (${(file.size/(1024*1024)).toFixed(1)} MB) melebihi batas MVP 500 MB.`; state.upload.file=null; render(); return; }
  const issue = await validateUploadFile(file);
  if (issue) { state.upload.error=issue; state.upload.file=null; render(); return; }
  state.upload.file=file; state.upload.error=''; render();
}
function validateFolderName(name) {
  const value = String(name || '').trim();
  if (!value || value.length > 120 || value === '.' || value === '..' || /[\\/:*?"<>|\x00-\x1f]/.test(value)) {
    throw new Error('Nama folder harus 1–120 karakter dan tidak boleh mengandung karakter path.');
  }
  return value;
}
async function createEncryptedFolder(name, parentFolderId) {
  const masterKey = getLoadedMasterKey();
  if (!masterKey) throw new Error('Buka kunci brankas sebelum membuat folder.');
  const dek = await generateFileDek();
  const wrappedDek = await wrapDek(dek, masterKey);
  const encrypted = await encryptText(validateFolderName(name), dek);
  const result = await request('/folders', { method:'POST', body:JSON.stringify({
    encryptedFolderName:`${encrypted.ciphertextB64}:${encrypted.ivB64}`, wrappedDek, parentFolderId
  }) });
  return result.folderId;
}
async function saveNewFolder(form) {
  if (state.folderForm.loading) return;
  state.folderForm.name = String(new FormData(form).get('folderName') || '').trim();
  state.folderForm.error = '';
  try {
    validateFolderName(state.folderForm.name);
    state.folderForm.loading = true; render();
    await createEncryptedFolder(state.folderForm.name, state.currentFolderId);
    state.folderForm.loading = false; state.modal = null;
    setAppHistory('app', state.activeTab, true, null);
    await fetchFiles(); showToast('Folder berhasil dibuat.');
  } catch (err) { state.folderForm.loading = false; state.folderForm.error = err.message || 'Gagal membuat folder.'; render(); }
}
async function uploadEncryptedFile(file, parentFolderId, tags, onProgress) {
  const masterKey = getLoadedMasterKey();
  if (!masterKey) throw new Error('Brankas terkunci. Buka kunci sebelum mengunggah.');
  onProgress('Membuat kunci enkripsi berkas...', 0);
  const dek = await generateFileDek();
  const wrappedDek = await wrapDek(dek, masterKey);
  const encryptedName = await encryptText(file.name, dek);
  const encryptedTags = await encryptText(tags, dek);
  const totalChunks = Math.ceil(file.size / CHUNK_SIZE);
  onProgress('Menyiapkan unggahan terenkripsi...', 5);
  const init = await request('/files/init', { method:'POST', body:JSON.stringify({
    encryptedFileName:`${encryptedName.ciphertextB64}:${encryptedName.ivB64}`,
    encryptedTags:`${encryptedTags.ciphertextB64}:${encryptedTags.ivB64}`,
    fileSizeBytes:file.size, totalChunks, wrappedDek, parentFolderId
  }) });
  const fileId = init.fileId;
  for (let i = 0; i < totalChunks; i++) {
    onProgress(`Mengenkripsi dan mengunggah chunk ${i + 1}/${totalChunks}...`, 5 + Math.round(i / totalChunks * 90));
    const start = i * CHUNK_SIZE;
    const chunkBuffer = await file.slice(start, Math.min(start + CHUNK_SIZE, file.size)).arrayBuffer();
    const encrypted = await encryptChunkOffThread(chunkBuffer, dek, fileId, i);
    const body = new FormData();
    body.append('fileId', fileId); body.append('chunkIndex', String(i));
    body.append('ivBase64', encrypted.ivB64); body.append('aadString', encrypted.aad);
    body.append('chunkBlob', new Blob([encrypted.ciphertext]));
    await request(`/files/${fileId}/chunk/${i}`, { method:'POST', body });
    onProgress(`Chunk ${i + 1}/${totalChunks} selesai.`, 5 + Math.round((i + 1) / totalChunks * 90));
  }
  await request(`/files/${fileId}/complete`, { method:'POST' });
  onProgress('Berkas selesai diunggah.', 100);
}
async function startUpload() {
  const file = state.upload.file;
  if (!getLoadedMasterKey()) { state.upload.error='Brankas terkunci! Silakan buka brankas terlebih dahulu.'; render(); return; }
  if (!file) { state.upload.error='Pilih berkas yang akan dienkripsi.'; render(); return; }
  state.upload.uploading = true; state.upload.error = ''; state.upload.progress = 0; render();
  try {
    await uploadEncryptedFile(file, state.currentFolderId, state.upload.tags, (status, progress) => {
      state.upload.status = status; state.upload.progress = progress; render();
    });
    state.modal = null; setAppHistory('app', state.activeTab, true, null);
    await fetchFiles(); showToast('Berkas berhasil dienkripsi sisi-klien dan diunggah.');
  } catch (err) { state.upload.uploading = false; state.upload.error = err.message || 'Gagal mengenkripsi atau mengunggah berkas.'; render(); }
}
async function startFolderUpload(files) {
  if (!getLoadedMasterKey()) { openModal('unlock'); return; }
  const entries = Array.from(files, file => ({ file, parts: String(file.webkitRelativePath || '').split('/') }));
  if (!entries.length) { showToast('Folder kosong tidak dapat dipilih oleh browser. Buat folder secara manual.', 'error'); return; }
  if (entries.length > 1000) { showToast('Pilih folder dengan maksimal 1.000 berkas per unggahan.', 'error'); return; }
  try {
    for (const entry of entries) {
      if (entry.parts.length < 2 || entry.parts.length > 21 || entry.parts.some((part, i) => i < entry.parts.length - 1 && !part)) {
        throw new Error('Struktur folder yang dipilih tidak valid atau terlalu dalam.');
      }
      for (const name of entry.parts.slice(0, -1)) validateFolderName(name);
      if (!entry.file.size || entry.file.size > MAX_FILE_SIZE) throw new Error(`Berkas ${entry.file.name} kosong atau melebihi batas 500 MB.`);
      const issue = await validateUploadFile(entry.file);
      if (issue) throw new Error(`${entry.file.name}: ${issue}`);
    }
  } catch (err) { showToast(err.message || 'Folder tidak dapat diunggah.', 'error'); return; }
  state.folderUpload = { uploading:true, current:'Membuat struktur folder...', completed:0, total:entries.length, progress:0, error:'' };
  if (state.modal === 'folder-select') { state.modal = 'folder-upload'; setAppHistory('app', state.activeTab, true, 'folder-upload'); render(); }
  else openModal('folder-upload');
  const folderIds = new Map();
  const destinationFolderId = state.currentFolderId;
  try {
    const paths = new Set();
    for (const entry of entries) for (let depth = 1; depth < entry.parts.length; depth++) paths.add(entry.parts.slice(0, depth).join('/'));
    for (const path of [...paths].sort((a,b) => a.split('/').length - b.split('/').length)) {
      const parts = path.split('/');
      const parentPath = parts.slice(0, -1).join('/');
      const parentId = parentPath ? folderIds.get(parentPath) : destinationFolderId;
      state.folderUpload.current = `Membuat folder ${parts[parts.length - 1]}...`; render();
      folderIds.set(path, await createEncryptedFolder(parts[parts.length - 1], parentId));
    }
    for (const entry of entries) {
      const parentPath = entry.parts.slice(0, -1).join('/');
      const parentId = folderIds.get(parentPath);
      state.folderUpload.current = `Mengunggah ${entry.file.name}...`; render();
      await uploadEncryptedFile(entry.file, parentId, '', (_status, fileProgress) => {
        state.folderUpload.progress = Math.round((state.folderUpload.completed + fileProgress / 100) / entries.length * 100);
        render();
      });
      state.folderUpload.completed++;
      state.folderUpload.progress = Math.round(state.folderUpload.completed / entries.length * 100);
      render();
    }
    state.folderUpload.uploading = false; state.modal = null;
    setAppHistory('app', state.activeTab, true, null);
    await fetchFiles(); showToast(`${entries.length} berkas berhasil diunggah dalam folder terenkripsi.`);
  } catch (err) {
    state.folderUpload.uploading = false;
    state.folderUpload.error = err.message || 'Upload folder gagal.';
    state.folderUpload.current = 'Upload terhenti';
    await fetchFiles(); render();
  }
}
async function forEachDecryptedChunk(file, onChunk, onProgress) {
  const masterKey = getLoadedMasterKey();
  if (!masterKey) throw new Error('Brankas terkunci.');
  const fileSize = Number(file.file_size_bytes);
  const totalChunks = Number(file.total_chunks);
  const expectedChunks = Math.ceil(fileSize / CHUNK_SIZE);
  if (!Number.isSafeInteger(fileSize) || fileSize < 1 || fileSize > MAX_FILE_SIZE
      || !Number.isSafeInteger(totalChunks) || totalChunks < 1 || totalChunks > 100
      || totalChunks !== expectedChunks) {
    throw new Error('Metadata ukuran atau jumlah chunk berkas tidak valid. Unduhan dihentikan.');
  }

  const dek = await unwrapDek(file.wrapped_dek, masterKey);
  let processedBytes = 0;
  for (let i = 0; i < totalChunks; i++) {
    const meta = await request(`/files/${file.id}/chunk/${i}/meta`);
    const ciphertext = await request(`/files/${file.id}/chunk/${i}/data`);
    const plaintext = await decryptChunkOffThread(ciphertext, meta.ivBase64, dek, file.id, i);
    try {
      const expectedPlainLength = Math.min(CHUNK_SIZE, fileSize - processedBytes);
      if (plaintext.byteLength !== expectedPlainLength) {
        throw new Error(`Ukuran plaintext chunk #${i} tidak sesuai metadata berkas.`);
      }
      const plaintextLength = plaintext.byteLength;
      await onChunk(plaintext, i);
      processedBytes += plaintextLength;
    } finally {
      try { plaintext.fill(0); } catch { /* a stream implementation may detach a consumed view */ }
    }
    if (onProgress) onProgress(Math.round((i + 1) / totalChunks * 100));
  }
  if (processedBytes !== fileSize) throw new Error('Ukuran hasil dekripsi tidak sama dengan ukuran berkas yang tercatat.');
  return { processedBytes };
}

async function getDecryptedFileBytes(file, onProgress) {
  // Preview is capped at 50 MiB; Blob parts avoid retaining a second JS byte-array copy.
  const blobParts = [];
  await forEachDecryptedChunk(file, async (plaintext) => {
    blobParts.push(new Blob([plaintext]));
  }, onProgress);
  return { blob: new Blob(blobParts) };
}

function safeSuggestedFilename(name) {
  const cleaned = String(name || 'downloaded-file').replace(/[\\/\\\\<>:\"|?*\x00-\x1F]/g, '_').replace(/^\.+$/, 'downloaded-file').slice(0, 180);
  return cleaned || 'downloaded-file';
}

async function downloadFile(file) {
  if(file.upload_status==='uploading'){state.filesError='Berkas belum selesai diunggah. Hapus unggahan yang terputus atau unggah ulang berkas tersebut.';render();return;}
  if(!getLoadedMasterKey()){openModal('unlock');return;}

  const suggestedName = safeSuggestedFilename(file.decryptedFileName || 'downloaded-file');
  let pickerPromise = null;
  if (typeof window.showSaveFilePicker === 'function') {
    try {
      // Must be invoked synchronously from the user's click before the first await.
      pickerPromise = window.showSaveFilePicker({ suggestedName });
    } catch (error) {
      state.filesError = error.message || 'Dialog penyimpanan tidak dapat dibuka.';
      render();
      return;
    }
  } else if (Number(file.file_size_bytes) > 100 * 1024 * 1024) {
    const proceed = confirm('Browser ini tidak mendukung unduhan streaming langsung ke file. Unduhan besar akan memakai Blob dan dapat menggunakan RAM yang besar. Lanjutkan?');
    if (!proceed) return;
  }

  state.downloadingId=file.id;state.downloadProgress=0;state.filesError='';render();
  let writable = null;
  try {
    let saveHandle = null;
    if (pickerPromise) {
      saveHandle = await pickerPromise;
      writable = await saveHandle.createWritable();
    }

    if (writable) {
      await forEachDecryptedChunk(file, async (plaintext) => {
        await writable.write(plaintext);
      }, p=>{state.downloadProgress=p; if(state.activeTab==='files') render();});
      await writable.close();
      writable = null;
      showToast('Berkas berhasil didekripsi dan ditulis bertahap ke file tujuan.');
    } else {
      const blobParts = [];
      await forEachDecryptedChunk(file, async (plaintext) => {
        blobParts.push(new Blob([plaintext]));
      }, p=>{state.downloadProgress=p; if(state.activeTab==='files') render();});
      const blob = new Blob(blobParts, { type: 'application/octet-stream' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a'); a.href=url; a.download=suggestedName;
      document.body.appendChild(a); a.click(); a.remove();
      setTimeout(()=>URL.revokeObjectURL(url), 30000);
      showToast('Berkas berhasil didekripsi. Browser memakai jalur Blob; RAM dapat meningkat untuk file besar.');
    }
  } catch(err){
    if (writable) { try { await writable.abort(); } catch { /* preserve the original failure */ } }
    if (err?.name !== 'AbortError') state.filesError=err.message||'Gagal mengunduh atau mendekripsi berkas.';
  }
  finally{state.downloadingId=null;state.downloadProgress=0;render();}
}
async function previewFile(file) {
  if(file.upload_status==='uploading'){state.filesError='Berkas belum selesai diunggah. Hapus unggahan yang terputus atau unggah ulang berkas tersebut.';render();return;}
  if(!getLoadedMasterKey()){openModal('unlock');return;}
  state.downloadingId=file.id;state.downloadProgress=0;state.filesError='';render();
  try {
    const masterKey=getLoadedMasterKey();const dek=await unwrapDek(file.wrapped_dek,masterKey);
    let name=file.decryptedFileName||'';
    if(!name&&file.encrypted_file_name.includes(':')){const [c,iv]=file.encrypted_file_name.split(':');name=await decryptText(c,iv,dek);}
    name=name||'preview';const ext=name.split('.').pop()?.toLowerCase()||'';
    const mimeMap={pdf:['application/pdf','pdf'],png:['image/png','image'],jpg:['image/jpeg','image'],jpeg:['image/jpeg','image'],gif:['image/gif','image'],webp:['image/webp','image'],bmp:['image/bmp','image'],avif:['image/avif','image'],txt:['text/plain','text'],csv:['text/csv','text'],json:['application/json','text'],md:['text/markdown','text']};
    if(!mimeMap[ext])throw new Error('Pratinjau tersedia untuk PDF, gambar (PNG/JPG/GIF/WebP/BMP/AVIF), TXT, CSV, JSON, dan Markdown.');
    if(Number(file.file_size_bytes)>50*1024*1024)throw new Error('Ukuran berkas melebihi batas pratinjau 50 MiB. Gunakan fitur unduh untuk membuka berkas ini.');
    const {blob}=await getDecryptedFileBytes(file,p=>{state.downloadProgress=p; if(state.activeTab==='files') render();});
    const [mime,kind]=mimeMap[ext];
    if(state.preview?.url)URL.revokeObjectURL(state.preview.url);
    if(kind==='text')state.preview={name,mime,kind,textContent:await blob.text()};
    else state.preview={name,mime,kind,url:URL.createObjectURL(new Blob([blob],{type:mime}))};
    state.modal='preview';setAppHistory('app',state.activeTab,false,'preview');
  }catch(err){state.filesError=err.message||'Gagal mempratinjau atau mendekripsi berkas.';}
  finally{state.downloadingId=null;state.downloadProgress=0;render();}
}
async function deleteFile(fileId) {
  if(!confirm('Hapus berkas ini secara permanen dari penyimpanan fisik dan basis data?'))return;
  try{await request(`/files/${fileId}`,{method:'DELETE'});await fetchFiles();showToast('Berkas berhasil dihapus.');}
  catch(err){state.filesError=err.message||'Gagal menghapus berkas.';render();}
}
async function saveFileMetadata() {
  const file=state.selectedFile;const masterKey=getLoadedMasterKey();
  state.detailName=$('#detail-name')?.value??state.detailName;state.detailTags=$('#detail-tags')?.value??state.detailTags;
  if(!masterKey){state.modalError='Brankas terkunci! Buka brankas untuk mengubah metadata.';render();return;}
  state.detailSaving=true;state.modalError='';render();
  try{
    const dek=await unwrapDek(file.wrapped_dek,masterKey);const name=await encryptText(state.detailName,dek);const tags=await encryptText(state.detailTags,dek);
    await request(`/files/${file.id}/metadata`,{method:'PATCH',body:JSON.stringify({encryptedFileName:`${name.ciphertextB64}:${name.ivB64}`,encryptedTags:`${tags.ciphertextB64}:${tags.ivB64}`})});
    state.detailEditing=false;state.modal=null;setAppHistory('app',state.activeTab,true,null);await fetchFiles();showToast('Metadata berkas terenkripsi berhasil diperbarui.');
  }catch(err){state.detailSaving=false;state.modalError=err.message||'Gagal memperbarui metadata.';render();}
}
async function fetchAudit() {
  state.audit.loading=true;state.audit.error='';render();
  try{const result=await request('/audit');state.audit.logs=result.logs||[];}
  catch(err){state.audit.error=err.message||'Gagal memuat audit trail.';}
  finally{state.audit.loading=false;render();}
}
async function fetchAdmin() {
  state.admin.loading=true;state.admin.error='';render();
  try{const [u,s]=await Promise.all([request('/admin/users'),request('/admin/stats')]);state.admin.users=u.users||[];state.admin.stats=s.stats||null;}
  catch(err){state.admin.error=err.message||'Gagal memuat data konsol admin.';}
  finally{state.admin.loading=false;render();}
}
async function updateQuota(button) {
  const id=button.dataset.id;const current=button.dataset.quota;const input=prompt(`Masukkan kuota baru dalam GB (saat ini: ${current} GB):`,current);
  if(!input||Number.isNaN(Number(input))||Number(input)<=0)return;
  try{await request(`/admin/users/${id}/quota`,{method:'PATCH',body:JSON.stringify({storageQuotaBytes:Number(input)*1024**3})});await fetchAdmin();showToast(`Kuota pengguna berhasil diperbarui menjadi ${input} GB.`);}
  catch(err){state.admin.error=err.message||'Gagal memperbarui kuota.';render();}
}
async function revokeSession(id) {
  if(!confirm('Cabut semua sesi dan nonaktifkan akun ini? Pengguna tidak dapat masuk atau beraktivitas sampai admin mengaktifkannya kembali. Akun dan berkas tetap tersimpan.'))return;
  try{await request(`/admin/users/${id}/revoke`,{method:'POST'});await fetchAdmin();showToast('Akun dinonaktifkan dan semua sesi dicabut.');}
  catch(err){state.admin.error=err.message||'Gagal menonaktifkan akun.';render();}
}
async function reactivateAccount(id) {
  if(!confirm('Aktifkan kembali akun ini? Pengguna dapat masuk menggunakan kata sandi dan MFA.'))return;
  try{await request(`/admin/users/${id}/reactivate`,{method:'POST'});await fetchAdmin();showToast('Akun diaktifkan kembali. Pengguna dapat masuk dengan sesi baru.');}
  catch(err){state.admin.error=err.message||'Gagal mengaktifkan akun.';render();}
}
async function resendVerificationCode(id) {
  try{await request(`/admin/users/${id}/resend-verification`,{method:'POST'});await fetchAdmin();showToast('Tautan aktivasi baru dikirim. Minta pengguna memeriksa Kotak Masuk dan Spam.');}
  catch(err){state.admin.error=err.message||'Gagal mengirim ulang tautan aktivasi.';render();}
}
async function deleteAccount(id, username) {
  const confirmation = prompt(`Hapus akun ${username} secara permanen beserta semua berkas dan foldernya? Tindakan ini tidak dapat dibatalkan.\n\nKetik username ${username} untuk konfirmasi:`);
  if(confirmation === null)return;
  if(confirmation !== username){showToast('Username konfirmasi tidak cocok. Akun tidak dihapus.','error');return;}
  try{await request(`/admin/users/${id}`,{method:'DELETE',body:JSON.stringify({confirmUsername:username})});await fetchAdmin();showToast(`Akun ${username} dan seluruh data brankasnya berhasil dihapus.`);}
  catch(err){state.admin.error=err.message||'Gagal menghapus akun.';render();}
}

// Delegated UI events keep the page framework-free while preserving every action.
document.addEventListener('click', async event => {
  if(state.createMenuOpen && !event.target.closest('.drive-create-wrap')){state.createMenuOpen=false;$('.drive-create-menu')?.remove();$('.drive-new')?.setAttribute('aria-expanded','false');}
  const button=event.target.closest('[data-action]');if(!button)return;
  const action=button.dataset.action;
  if(action==='create-menu'){state.createMenuOpen=!state.createMenuOpen;render();if(state.createMenuOpen)$('.drive-create-menu [data-action="new-folder"]')?.focus();return;}
  if(action==='overlay-close' && event.target===button){closeModal();return;}
  if(action==='preview-overlay' && event.target===button){closePreview();return;}
  if(action==='close-modal'){closeModal();return;}
  if(action==='close-preview'){closePreview();return;}
  if(action==='theme'){applyTheme(button.dataset.theme);render();return;}
  if(action==='dashboard-view'){state.activeTab='files';state.dashboardView=button.dataset.view;state.currentFolderId=null;state.search='';state.selectedTag=null;state.sortBy='date';state.sortAsc=false;setAppHistory('app','files');render();fetchFiles();return;}
  if(action==='folder-root'){state.currentFolderId=null;state.search='';state.selectedTag=null;setAppHistory('app','files');render();return;}
  if(action==='folder-open'){if(state.folders.some(folder=>folder.id===button.dataset.id)){state.currentFolderId=button.dataset.id;state.search='';state.selectedTag=null;setAppHistory('app','files');render();}return;}
  if(action==='delete-folder'){const folder=state.decryptedFolders.find(item=>item.id===button.dataset.id);if(!folder||!state.unlocked)return;if(!confirm(`Hapus folder kosong "${folder.decryptedFileName || 'Folder'}"?`))return;try{await request(`/folders/${folder.id}`,{method:'DELETE'});await fetchFiles();showToast('Folder berhasil dihapus.');}catch(err){showToast(err.message||'Folder gagal dihapus.','error');}return;}
  if(action==='file-layout'){state.fileLayout=button.dataset.layout;render();return;}
  if(action==='tab'){if(button.dataset.tab!=='files'&&state.user?.role!=='admin')return;state.activeTab=button.dataset.tab;setAppHistory('app',state.activeTab);render();if(state.activeTab==='files')fetchFiles();if(state.activeTab==='audit')fetchAudit();if(state.activeTab==='admin')fetchAdmin();return;}
  if(action==='logout'){logout();return;}
  if(action==='lock-vault'){toggleVaultLock();return;}
  if(action==='open-unlock'){openModal('unlock');return;}
  if(action==='open-passphrase'){openModal('change-pass');return;}
  if(action==='new-folder'){state.createMenuOpen=false;if(!state.unlocked){state.pendingVaultAction='new-folder';openModal('unlock');return;}openModal('new-folder');return;}
  if(action==='choose-folder'){state.createMenuOpen=false;$('.drive-create-menu')?.remove();$('.drive-new')?.setAttribute('aria-expanded','false');if(!state.unlocked){state.pendingVaultAction='choose-folder';openModal('unlock');return;}const picker=$('#folder-picker');if(!picker||!('webkitdirectory' in picker)){showToast('Browser ini tidak mendukung pemilihan folder. Gunakan Chrome atau Edge.','error');return;}picker.click();return;}
  if(action==='upload'){state.createMenuOpen=false;if(!state.unlocked){openModal('unlock');return;}openModal('upload');return;}
  if(action==='refresh-files'){fetchFiles();return;}
  if(action==='refresh-audit'){fetchAudit();return;}
  if(action==='refresh-admin'){fetchAdmin();return;}
  if(action==='sort-direction'){state.sortAsc=!state.sortAsc;render();return;}
  if(action==='tag-filter'){state.selectedTag=button.dataset.tag||null;render();return;}
  if(action==='preview-file'){const file=state.decryptedFiles.find(f=>f.id===button.dataset.id)||state.files.find(f=>f.id===button.dataset.id);if(file)previewFile(file);return;}
  if(action==='download-file'){const file=state.decryptedFiles.find(f=>f.id===button.dataset.id)||state.files.find(f=>f.id===button.dataset.id);if(file)downloadFile(file);return;}
  if(action==='file-details'){const file=state.decryptedFiles.find(f=>f.id===button.dataset.id)||state.files.find(f=>f.id===button.dataset.id);if(file){state.selectedFile=file;state.detailEditing=false;state.detailName=file.decryptedFileName||'';state.detailTags=(file.tags||[]).join(', ');state.modalError='';state.modal='details';setAppHistory('app',state.activeTab,false,'details');render();}return;}
  if(action==='delete-file'){deleteFile(button.dataset.id);return;}
  if(action==='onboarding-back'){state.login.onboardingStage='';state.login.onboardingChallenge='';state.login.onboardingPasswordToken='';state.login.error='';state.login.password='';render();return;}
  if(action==='activation-back'){state.activation=null;render();return;}
  if(action==='mfa-back'){if(history.state?.secureVaultApp&&history.state.view==='mfa'){history.back();return;}state.login.mfaRequired=false;state.login.mfaSetupRequired=false;state.login.mfaToken='';state.login.totpCode='';state.login.mfaSecret='';state.login.mfaOtpUri='';state.login.secretCopied=false;state.login.error='';state.login.notice='';render();return;}
  if(action==='copy-secret'){try{await navigator.clipboard.writeText(state.login.mfaSecret);state.login.secretCopied=true;render();}catch{state.login.error='Secret tidak dapat disalin otomatis. Salin secret yang ditampilkan secara manual.';render();}return;}
  if(action==='choose-file'){$('#upload-file')?.click();return;}
  if(action==='start-upload'){startUpload();return;}
  if(action==='detail-edit'){state.detailEditing=true;render();return;}
  if(action==='detail-cancel'){state.detailEditing=false;render();return;}
  if(action==='detail-save'){saveFileMetadata();return;}
  if(action==='admin-quota'){updateQuota(button);return;}
  if(action==='admin-revoke'){revokeSession(button.dataset.id);return;}
  if(action==='admin-reactivate'){reactivateAccount(button.dataset.id);return;}
  if(action==='admin-resend-code'){resendVerificationCode(button.dataset.id);return;}
  if(action==='admin-delete-user'){deleteAccount(button.dataset.id,button.dataset.username);return;}
});
document.addEventListener('keydown', event => {
  if(event.key==='Escape' && state.createMenuOpen){state.createMenuOpen=false;$('.drive-create-menu')?.remove();const trigger=$('.drive-new');trigger?.setAttribute('aria-expanded','false');trigger?.focus();}
});

document.addEventListener('submit', async event => {
  const form=event.target;const type=form.dataset.form;if(!type)return;event.preventDefault();
  if(type==='activate-account'){
    const data=new FormData(form);const password=String(data.get('newPassword')||'');
    if(password.length<12||password!==String(data.get('confirmPassword')||'')){state.activation.error='Kata sandi minimal 12 karakter dan konfirmasi harus sama.';render();return;}
    const activation=state.activation;activation.loading=true;activation.error='';render();
    try{await request('/auth/activate',{method:'POST',body:JSON.stringify({userId:activation.userId,token:activation.token,newPassword:password})});state.activation=null;state.login.username=activation.username;state.login.notice='Akun aktif. Masuk dengan kata sandi baru untuk melanjutkan ke OTP authenticator.';}
    catch(err){activation.error=err.message||'Gagal mengaktifkan akun.';}
    finally{activation.loading=false;render();}
    return;
  }
  if(type==='login'){
    const data=new FormData(form);
    state.login.username=String(data.get('username')||'').trim();
    state.login.password=String(data.get('password')||'');
    state.login.error=''; state.login.notice='';
    if (!state.login.username) { state.login.error='Username wajib diisi.'; render(); return; }
    if (!state.login.password) { state.login.error='Kata sandi wajib diisi.'; render(); return; }
    state.login.loading=true; render();
    try{
        const result=await request('/auth/login',{method:'POST',body:JSON.stringify({username:state.login.username,password:state.login.password})});
        if(result.onboardingRequired&&result.passwordToken){state.login.password='';state.login.onboardingPasswordToken=result.passwordToken;state.login.onboardingStage='password';}
        else if(result.onboardingRequired&&result.challenge){state.login.password='';state.login.onboardingChallenge=result.challenge;state.login.onboardingEmailHint=result.emailHint||'email terdaftar';state.login.onboardingStage='email';}
        else if(result.mfaRequired&&result.mfaToken){state.login.password='';state.login.mfaToken=result.mfaToken;state.login.mfaSetupRequired=Boolean(result.mfaSetupRequired);state.login.totpCode='';if(result.mfaSetupRequired){const setup=await request('/auth/mfa/setup',{method:'POST',body:JSON.stringify({mfaToken:result.mfaToken})});state.login.mfaSecret=setup.secret;state.login.mfaOtpUri=setup.otpauthUri||'';}else{state.login.mfaSecret='';state.login.mfaOtpUri='';}state.login.mfaRequired=true;setAppHistory('mfa');}
        else if(result.token&&result.user)throw new Error('Respons autentikasi tidak lengkap. Silakan periksa konfigurasi server.');
        else throw new Error('Server tidak mengembalikan tantangan MFA yang valid.');
    }catch(err){state.login.error=err.message||'Gagal memproses autentikasi.';}
    finally{state.login.loading=false;render();}
  }
  if(type==='onboarding-email'){
    const code=String(new FormData(form).get('emailCode')||'').trim();
    if(!/^[0-9]{8}$/.test(code)){state.login.error='Masukkan kode email 8 digit.';render();return;}
    state.login.loading=true;state.login.error='';render();
    try{const result=await request('/auth/onboarding/verify-email',{method:'POST',body:JSON.stringify({username:state.login.username,challenge:state.login.onboardingChallenge,code})});state.login.onboardingChallenge='';state.login.onboardingPasswordToken=result.passwordToken;state.login.onboardingStage='password';}
    catch(err){state.login.error=err.message||'Kode email tidak valid.';}
    finally{state.login.loading=false;render();}
  }
  if(type==='onboarding-password'){
    const data=new FormData(form);const password=String(data.get('newPassword')||'');
    if(password.length<12||password!==String(data.get('confirmPassword')||'')){state.login.error='Kata sandi minimal 12 karakter dan konfirmasi harus sama.';render();return;}
    state.login.loading=true;state.login.error='';render();
    try{await request('/auth/onboarding/set-password',{method:'POST',body:JSON.stringify({username:state.login.username,passwordToken:state.login.onboardingPasswordToken,newPassword:password})});state.login.onboardingPasswordToken='';state.login.onboardingStage='';state.login.notice='Akun aktif. Masuk dengan kata sandi baru, lalu siapkan authenticator.';}
    catch(err){state.login.error=err.message||'Gagal mengaktifkan akun.';}
    finally{state.login.loading=false;render();}
  }
  if(type==='mfa'){
    state.login.totpCode=String(new FormData(form).get('totpCode')||'').replace(/\D/g,'').slice(0,6);
    if (state.login.totpCode.length !== 6) { state.login.error='Kode autentikator harus terdiri dari 6 digit angka.'; render(); return; }
    state.login.loading=true;state.login.error='';render();
    try{const result=await request('/auth/mfa/verify',{method:'POST',body:JSON.stringify({mfaToken:state.login.mfaToken,code:state.login.totpCode})});setAuthToken(result.token);loginSuccess(result.user);}
    catch(err){state.login.error=err.message||'Kode autentikator tidak valid.';state.login.loading=false;render();}
  }
  if(type==='vault-unlock')handleUnlock(form);
  if(type==='vault-init')handleInitializeVault(form);
  if(type==='change-pass')handleChangePassphrase(form);
  if(type==='create-folder')saveNewFolder(form);
  if(type==='admin-create-user'){
    const data=new FormData(form);const username=String(data.get('username')||'').trim();const email=String(data.get('email')||'').trim();
    state.admin.creating=true;state.admin.error='';render();
    try{await request('/admin/users',{method:'POST',body:JSON.stringify({username,email})});await fetchAdmin();showToast('Akun dibuat. Tautan aktivasi dikirim ke email pengguna.');}
    catch(err){state.admin.error=err.message||'Gagal membuat akun.';}
    finally{state.admin.creating=false;render();}
  }
});

document.addEventListener('change', event => {
  if(event.target.id==='upload-file'){selectUploadFile(event.target.files?.[0]);return;}
  if(event.target.id==='folder-picker'){const files=Array.from(event.target.files||[]);event.target.value='';startFolderUpload(files);return;}
  if(event.target.id==='sort-by'){state.sortBy=event.target.value;render();return;}
  if(event.target.id==='audit-action'){state.audit.action=event.target.value;render();return;}
  if(event.target.id==='audit-status'){state.audit.status=event.target.value;render();return;}
  if(event.target.id==='admin-status-filter'){state.admin.status=event.target.value;refreshAdminTable();return;}
});
document.addEventListener('input', event => {
  if(event.target.id==='admin-search'){
    state.admin.search=event.target.value;
    refreshAdminTable();
    return;
  }
  if(event.target.id==='file-search'){
    const pos=event.target.selectionStart;state.search=event.target.value;
    const table=$('.files-table tbody');if(table){const rows=visibleFiles();const wrapper=$('.table-card');const oldScroll=wrapper?.scrollTop;render();const input=$('#file-search');input?.focus();input?.setSelectionRange(pos,pos);if(wrapper&&oldScroll)wrapper.scrollTop=oldScroll;}
  }
  if(event.target.name==='totpCode'){state.login.totpCode=event.target.value.replace(/\D/g,'').slice(0,6);event.target.value=state.login.totpCode;const submit=$('[data-form="mfa"] button[type="submit"]');if(submit)submit.disabled=state.login.totpCode.length!==6||(state.login.mfaSetupRequired&&!state.login.mfaSecret);}
  if(event.target.id==='upload-tags')state.upload.tags=event.target.value;
});
document.addEventListener('dragover', event => {if(event.target.closest('#drop-zone')){event.preventDefault();$('#drop-zone')?.classList.add('drag-over');}});
document.addEventListener('dragleave', event => {if(event.target.closest('#drop-zone'))$('#drop-zone')?.classList.remove('drag-over');});
document.addEventListener('drop', event => {const zone=event.target.closest('#drop-zone');if(zone){event.preventDefault();zone.classList.remove('drag-over');selectUploadFile(event.dataTransfer.files?.[0]);}});
window.addEventListener('pointerdown',resetIdleTimer,{passive:true});window.addEventListener('touchstart',resetIdleTimer,{passive:true});window.addEventListener('keydown',resetIdleTimer);window.addEventListener('wheel',resetIdleTimer,{passive:true});window.addEventListener('click',resetIdleTimer);window.addEventListener('popstate',handleAppPopState);
window.addEventListener('auth:unauthorized',(event)=>{clearTimeout(state.idleTimer);state.user=null;state.modal=null;state.modalLoading=false;state.modalError='';state.modalStage='';state.vaultProfile=null;clearVaultKeys();terminateCryptoWorker();state.unlocked=false;state.files=[];state.decryptedFiles=[];state.folders=[];state.decryptedFolders=[];state.currentFolderId=null;state.pendingVaultAction=null;state.login.mfaRequired=false;state.login.mfaToken='';state.login.mfaSecret='';state.login.mfaOtpUri='';setAppHistory('login','files',true);render();showToast(event.detail?.message || 'Sesi tidak lagi valid. Silakan login kembali.','error');});
window.addEventListener('storage',()=>{if(state.theme==='system')applyTheme('system');});
if(state.theme==='system')matchMedia('(prefers-color-scheme: dark)').addEventListener('change',()=>applyTheme('system'));
if (!history.state?.secureVaultApp) setAppHistory('login', 'files', true);
applyTheme(state.theme);render();
if(getAuthToken()&&!state.activation)checkCurrentUser();
