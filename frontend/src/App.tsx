import React, { useState, useEffect, useRef } from 'react';
import { Navbar } from './components/Navbar';
import { Login } from './components/Login';
import { VaultDashboard } from './components/VaultDashboard';
import { VaultUnlockModal } from './components/VaultUnlockModal';
import { FileUploader } from './components/FileUploader';
import { FileDetailsModal } from './components/FileDetailsModal';
import { AuditLogViewer } from './components/AuditLogViewer';
import { AdminConsole } from './components/AdminConsole';
import { ChangePassphraseModal } from './components/ChangePassphraseModal';
import { User, EncryptedFile } from './types';
import { request, getAuthToken, clearAuthToken } from './utils/api';
import { clearVaultKeys, isVaultKeyLoaded } from './utils/crypto';
import { ThemeMode, getStoredTheme, applyTheme } from './utils/theme';
import { CheckCircle2, AlertTriangle } from 'lucide-react';

export const App: React.FC = () => {
  const [theme, setTheme] = useState<ThemeMode>(getStoredTheme);
  const [user, setUser] = useState<User | null>(null);
  const [isVaultUnlocked, setIsVaultUnlocked] = useState(false);
  const [activeTab, setActiveTab] = useState<'files' | 'audit' | 'admin'>('files');

  // Modals state
  const [isUnlockModalOpen, setIsUnlockModalOpen] = useState(false);
  const [isUploadModalOpen, setIsUploadModalOpen] = useState(false);
  const [isChangePassModalOpen, setIsChangePassModalOpen] = useState(false);
  const [selectedFileForDetails, setSelectedFileForDetails] = useState<EncryptedFile | null>(null);

  // Toast
  const [toast, setToast] = useState<{ message: string; type: 'success' | 'error' } | null>(null);

  // 15-minute idle timer for Zero-Trust session & RAM key clearing
  const idleTimerRef = useRef<NodeJS.Timeout | null>(null);

  const showToast = (message: string, type: 'success' | 'error' = 'success') => {
    setToast({ message, type });
    setTimeout(() => setToast(null), 4000);
  };

  const resetIdleTimer = () => {
    if (idleTimerRef.current) clearTimeout(idleTimerRef.current);
    // 15 minutes = 900,000 ms
    idleTimerRef.current = setTimeout(() => {
      if (isVaultKeyLoaded()) {
        clearVaultKeys();
        setIsVaultUnlocked(false);
        showToast('Waktu hening 15 menit tercapai. Brankas terkunci otomatis & kunci di RAM dibersihkan.', 'error');
      }
    }, 15 * 60 * 1000);
  };

  useEffect(() => {
    const handleActivity = () => resetIdleTimer();
    window.addEventListener('mousemove', handleActivity);
    window.addEventListener('keydown', handleActivity);
    resetIdleTimer();

    return () => {
      window.removeEventListener('mousemove', handleActivity);
      window.removeEventListener('keydown', handleActivity);
      if (idleTimerRef.current) clearTimeout(idleTimerRef.current);
    };
  }, []);

  useEffect(() => {
    const token = getAuthToken();
    if (token) {
      checkCurrentUser();
    }

    const handleUnauthorized = () => {
      setUser(null);
      clearVaultKeys();
      setIsVaultUnlocked(false);
      showToast('Sesi kedaluwarsa. Silakan login kembali.', 'error');
    };

    window.addEventListener('auth:unauthorized', handleUnauthorized);
    return () => window.removeEventListener('auth:unauthorized', handleUnauthorized);
  }, []);

  const checkCurrentUser = async () => {
    try {
      const res = await request<{ user: User }>('/auth/me');
      setUser(res.user);
    } catch {
      clearAuthToken();
      setUser(null);
    }
  };

  const handleLoginSuccess = (loggedInUser: User) => {
    setUser(loggedInUser);
    showToast(`Selamat datang, ${loggedInUser.username}! Otentikasi Zero-Trust terverifikasi.`);
    // Prompt to unlock vault right after login
    setTimeout(() => {
      setIsUnlockModalOpen(true);
    }, 300);
  };

  const handleLockVault = () => {
    clearVaultKeys();
    setIsVaultUnlocked(false);
    showToast('Brankas berhasil dikunci. Seluruh kunci di RAM telah dibersihkan secara mutlak.');
  };

  const handleLogout = () => {
    clearAuthToken();
    clearVaultKeys();
    setUser(null);
    setIsVaultUnlocked(false);
    showToast('Logout berhasil. Kunci RAM & token sesi telah dimusnahkan.');
  };

  // Theme effect & listener for system changes
  useEffect(() => {
    applyTheme(theme);

    if (theme === 'system') {
      const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
      const handleChange = () => {
        applyTheme('system');
      };
      mediaQuery.addEventListener('change', handleChange);
      return () => mediaQuery.removeEventListener('change', handleChange);
    }
  }, [theme]);

  const handleThemeChange = (newTheme: ThemeMode) => {
    setTheme(newTheme);
    applyTheme(newTheme);
  };

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
      <Navbar
        user={user}
        isVaultUnlocked={isVaultUnlocked}
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        onOpenUnlockModal={() => setIsUnlockModalOpen(true)}
        onLockVault={handleLockVault}
        onOpenChangePassModal={() => setIsChangePassModalOpen(true)}
        onLogout={handleLogout}
        currentTheme={theme}
        onThemeChange={handleThemeChange}
      />

      <main style={{ flex: 1 }}>
        {!user ? (
          <Login onLoginSuccess={handleLoginSuccess} />
        ) : (
          <>
            {activeTab === 'files' && (
              <VaultDashboard
                user={user}
                isVaultUnlocked={isVaultUnlocked}
                onOpenUploadModal={() => setIsUploadModalOpen(true)}
                onOpenUnlockModal={() => setIsUnlockModalOpen(true)}
                onSelectFileDetails={(file) => setSelectedFileForDetails(file)}
              />
            )}

            {activeTab === 'audit' && <AuditLogViewer />}

            {activeTab === 'admin' && user.role === 'admin' && <AdminConsole />}
          </>
        )}
      </main>

      {/* Institutional Footer */}
      <footer style={{
        padding: '1.25rem 0',
        borderTop: '1px solid var(--border-subtle)',
        background: 'var(--header-bg)',
        backdropFilter: 'blur(16px)',
        textAlign: 'center',
        fontSize: '0.75rem',
        color: 'var(--text-muted)',
        transition: 'background-color 0.25s ease',
      }}>
        <div className="container" style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem', alignItems: 'center' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
            <img src="/logo.png" alt="Secure Vault" style={{ width: '18px', height: '18px', objectFit: 'contain' }} />
            <strong>SECURE VAULT</strong> &bull; Zero-Knowledge Distributed Storage Prototype
          </div>
          <div style={{ fontSize: '0.7rem' }}>
            Pusat Sertifikasi Teknologi Keamanan Siber dan Sandi &bull; Badan Siber dan Sandi Negara (BSSN) &bull; Standar Evaluasi ISO/IEC 15408 & ISO/IEC 18045
          </div>
        </div>
      </footer>

      {/* Modals */}
      <VaultUnlockModal
        isOpen={isUnlockModalOpen}
        onClose={() => setIsUnlockModalOpen(false)}
        onUnlocked={() => {
          setIsVaultUnlocked(true);
          showToast('Brankas berhasil dibuka! Master Key aktif di RAM non-extractable.');
        }}
      />

      <FileUploader
        isOpen={isUploadModalOpen}
        onClose={() => setIsUploadModalOpen(false)}
        onUploadSuccess={() => {
          showToast('Berkas berhasil dienkripsi sisi-klien dan diunggah.');
        }}
      />

      <FileDetailsModal
        file={selectedFileForDetails}
        onClose={() => setSelectedFileForDetails(null)}
        onUpdated={() => {
          showToast('Metadata berkas terenkripsi berhasil diperbarui.');
          setSelectedFileForDetails(null);
        }}
      />

      <ChangePassphraseModal
        isOpen={isChangePassModalOpen}
        onClose={() => setIsChangePassModalOpen(false)}
        onSuccess={() => {
          showToast('Passphrase berhasil diganti & Master Key telah di-wrap ulang dengan KEK baru.');
        }}
      />

      {/* Toast Notification */}
      {toast && (
        <div className="toast" style={{
          borderColor: toast.type === 'success' ? 'var(--accent-emerald)' : 'var(--accent-rose)',
        }}>
          {toast.type === 'success' ? (
            <CheckCircle2 size={18} color="var(--accent-emerald)" />
          ) : (
            <AlertTriangle size={18} color="var(--accent-rose)" />
          )}
          <span style={{ fontSize: '0.85rem', color: 'var(--text-primary)' }}>{toast.message}</span>
        </div>
      )}
    </div>
  );
};
