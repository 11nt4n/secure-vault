import React, { useState, useEffect } from 'react';
import { Lock, Key, AlertTriangle, CheckCircle2, ShieldAlert, Cpu } from 'lucide-react';
import {
  deriveKek,
  generateSalt,
  generateMasterKey,
  wrapMasterKey,
  unwrapMasterKey,
  createVerifier,
  verifyPassphrase,
  setLoadedKeys,
  uint8ArrayToB64,
  b64ToUint8Array,
} from '../utils/crypto';
import { request } from '../utils/api';

interface VaultUnlockModalProps {
  isOpen: boolean;
  onClose: () => void;
  onUnlocked: () => void;
}

export const VaultUnlockModal: React.FC<VaultUnlockModalProps> = ({
  isOpen,
  onClose,
  onUnlocked,
}) => {
  const [passphrase, setPassphrase] = useState('securePassphrase2026!');
  const [confirmPassphrase, setConfirmPassphrase] = useState('securePassphrase2026!');
  const [isInitializing, setIsInitializing] = useState(false);
  const [profileExists, setProfileExists] = useState(false);
  const [argon2SaltB64, setArgon2SaltB64] = useState('');
  const [wrappedMasterKeyB64, setWrappedMasterKeyB64] = useState('');
  const [verifierCiphertext, setVerifierCiphertext] = useState('');
  const [verifierIv, setVerifierIv] = useState('');
  const [verifierWrappedDek, setVerifierWrappedDek] = useState('');

  const [loading, setLoading] = useState(false);
  const [stage, setStage] = useState('');
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (isOpen) {
      checkVaultProfile();
    }
  }, [isOpen]);

  const checkVaultProfile = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await request<{
        hasProfile: boolean;
        argon2Salt?: string;
        wrappedMasterKey?: string;
        verifierCiphertext?: string;
        verifierIv?: string;
        verifierWrappedDek?: string;
      }>('/auth/vault-profile');

      if (res.hasProfile && res.argon2Salt && res.wrappedMasterKey) {
        setProfileExists(true);
        setArgon2SaltB64(res.argon2Salt);
        setWrappedMasterKeyB64(res.wrappedMasterKey);
        setVerifierCiphertext(res.verifierCiphertext || '');
        setVerifierIv(res.verifierIv || '');
        setVerifierWrappedDek(res.verifierWrappedDek || '');
      } else {
        setProfileExists(false);
        setIsInitializing(true);
      }
    } catch (err: any) {
      setError('Gagal memeriksa profil brankas: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleUnlock = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!passphrase) return;

    setError(null);
    setLoading(true);
    const startTime = performance.now();

    try {
      setStage('Menurunkan KEK via Argon2id WASM (m=64 MiB, t=3, p=1)...');
      const salt = b64ToUint8Array(argon2SaltB64);
      const kek = await deriveKek(passphrase, salt);

      setStage('Membuka kunci Master Key 256-bit via AES-KW...');
      const masterKey = await unwrapMasterKey(wrappedMasterKeyB64, kek);

      setStage('Memvalidasi encrypted verifier string...');
      const isValid = await verifyPassphrase(masterKey, verifierCiphertext, verifierIv, verifierWrappedDek);

      if (!isValid) {
        throw new Error('Passphrase brankas salah! Validasi verifier string gagal.');
      }

      const elapsed = ((performance.now() - startTime) / 1000).toFixed(2);
      setStage(`Berhasil dibuka dalam ${elapsed}s! Kunci disimpan di RAM (non-extractable).`);

      // Store in memory
      setLoadedKeys(kek, masterKey);

      setTimeout(() => {
        onUnlocked();
        onClose();
      }, 400);
    } catch (err: any) {
      setError(err.message || 'Gagal membuka brankas.');
    } finally {
      setLoading(false);
    }
  };

  const handleInitialize = async (e: React.FormEvent) => {
    e.preventDefault();
    if (passphrase !== confirmPassphrase) {
      setError('Konfirmasi passphrase tidak cocok.');
      return;
    }
    if (passphrase.length < 8) {
      setError('Passphrase minimal 8 karakter.');
      return;
    }

    setError(null);
    setLoading(true);

    try {
      setStage('Menghasilkan Salt acak 16-byte unik...');
      const salt = generateSalt(16);
      const saltB64 = uint8ArrayToB64(salt);

      setStage('Menurunkan KEK via Argon2id WASM...');
      const kek = await deriveKek(passphrase, salt);

      setStage('Menghasilkan Master Key 256-bit baru...');
      const masterKey = await generateMasterKey();

      setStage('Membungkus Master Key dengan KEK (AES-KW)...');
      const wrappedMk = await wrapMasterKey(masterKey, kek);

      setStage('Membuat Encrypted Verifier String...');
      const verifier = await createVerifier(masterKey);

      setStage('Menyimpan konfigurasi brankas Zero-Knowledge ke peladen...');
      await request('/auth/setup-vault', {
        method: 'POST',
        body: JSON.stringify({
          argon2Salt: saltB64,
          wrappedMasterKey: wrappedMk,
          verifierCiphertext: verifier.verifierCiphertext,
          verifierIv: verifier.verifierIv,
          verifierWrappedDek: verifier.verifierWrappedDek,
        }),
      });

      // Save to RAM
      setLoadedKeys(kek, masterKey);

      onUnlocked();
      onClose();
    } catch (err: any) {
      setError(err.message || 'Gagal menginisialisasi brankas.');
    } finally {
      setLoading(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="modal-overlay">
      <div className="modal-content" style={{ padding: '2.5rem' }}>
        <div style={{ textAlign: 'center', marginBottom: '1.75rem' }}>
          <div style={{
            width: '54px',
            height: '54px',
            borderRadius: '16px',
            background: 'rgba(56, 189, 248, 0.15)',
            border: '1px solid var(--border-card)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            margin: '0 auto 1rem',
          }}>
            {profileExists ? <Key size={28} color="var(--accent-cyan)" /> : <Lock size={28} color="var(--accent-amber)" />}
          </div>
          <h2 style={{ fontSize: '1.45rem', marginBottom: '0.35rem' }}>
            {profileExists ? 'Buka Kunci Brankas Pribadi' : 'Inisialisasi Brankas Pribadi'}
          </h2>
          <p style={{ fontSize: '0.825rem', color: 'var(--text-secondary)' }}>
            {profileExists
              ? 'Masukkan passphrase brankas untuk membuka Master Key (MK) di RAM browser.'
              : 'Buat passphrase rahasia untuk brankas Zero-Knowledge Anda.'}
          </p>
        </div>

        {/* Zero-Recovery Warning Callout */}
        <div style={{
          display: 'flex',
          gap: '0.75rem',
          padding: '0.85rem 1rem',
          borderRadius: 'var(--radius-md)',
          background: 'var(--badge-amber-bg)',
          border: '1px solid var(--accent-amber)',
          marginBottom: '1.5rem',
        }}>
          <ShieldAlert size={22} color="var(--accent-amber)" style={{ flexShrink: 0 }} />
          <div style={{ fontSize: '0.775rem', color: 'var(--text-secondary)', lineHeight: 1.4 }}>
            <strong style={{ color: 'var(--accent-amber)' }}>Peringatan Nol-Pemulihan (Zero-Knowledge Guarantee):</strong><br />
            Passphrase Anda tidak pernah dikirim ke server. Jika Anda lupa passphrase, data berkas tidak dapat dipulihkan oleh administrator sistem maupun pihak mana pun.
          </div>
        </div>

        {error && (
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
            padding: '0.75rem 1rem',
            borderRadius: 'var(--radius-md)',
            background: 'var(--badge-rose-bg)',
            border: '1px solid var(--accent-rose)',
            color: 'var(--accent-rose)',
            fontSize: '0.825rem',
            marginBottom: '1.25rem',
          }}>
            <AlertTriangle size={18} />
            <span>{error}</span>
          </div>
        )}

        {/* Derivation Stage Status */}
        {loading && stage && (
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: '0.6rem',
            padding: '0.75rem 1rem',
            borderRadius: 'var(--radius-md)',
            background: 'rgba(56, 189, 248, 0.1)',
            border: '1px solid var(--border-card)',
            color: 'var(--accent-cyan)',
            fontSize: '0.8rem',
            marginBottom: '1.25rem',
          }}>
            <Cpu size={18} style={{ animation: 'spin 2s linear infinite' }} />
            <span>{stage}</span>
          </div>
        )}

        {profileExists ? (
          <form onSubmit={handleUnlock} style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
            <div className="input-group">
              <label className="input-label">
                <span>Passphrase Brankas</span>
                <span style={{ color: 'var(--accent-cyan)' }}>Demo: securePassphrase2026!</span>
              </label>
              <input
                type="password"
                value={passphrase}
                onChange={(e) => setPassphrase(e.target.value)}
                className="input-control"
                placeholder="Masukkan passphrase brankas"
                required
                autoFocus
              />
            </div>

            <div style={{ display: 'flex', gap: '0.75rem', marginTop: '0.5rem' }}>
              <button type="button" onClick={onClose} className="btn btn-secondary" style={{ flex: 1 }} disabled={loading}>
                Batal
              </button>
              <button type="submit" className="btn btn-primary" style={{ flex: 2 }} disabled={loading}>
                {loading ? 'Mendekripsi KEK...' : 'Buka Kunci Brankas'}
              </button>
            </div>
          </form>
        ) : (
          <form onSubmit={handleInitialize} style={{ display: 'flex', flexDirection: 'column', gap: '1.15rem' }}>
            <div className="input-group">
              <label className="input-label">Passphrase Brankas Baru</label>
              <input
                type="password"
                value={passphrase}
                onChange={(e) => setPassphrase(e.target.value)}
                className="input-control"
                placeholder="Minimal 8 karakter"
                required
              />
            </div>

            <div className="input-group">
              <label className="input-label">Konfirmasi Passphrase</label>
              <input
                type="password"
                value={confirmPassphrase}
                onChange={(e) => setConfirmPassphrase(e.target.value)}
                className="input-control"
                placeholder="Ketik ulang passphrase"
                required
              />
            </div>

            <div style={{ display: 'flex', gap: '0.75rem', marginTop: '0.5rem' }}>
              <button type="button" onClick={onClose} className="btn btn-secondary" style={{ flex: 1 }} disabled={loading}>
                Batal
              </button>
              <button type="submit" className="btn btn-primary" style={{ flex: 2 }} disabled={loading}>
                {loading ? 'Menginisialisasi...' : 'Inisialisasi & Buka Brankas'}
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
};
