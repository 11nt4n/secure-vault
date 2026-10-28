import React, { useState } from 'react';
import { KeyRound, ShieldCheck, X, AlertTriangle, RefreshCw } from 'lucide-react';
import {
  getLoadedMasterKey,
  deriveKek,
  generateSalt,
  wrapMasterKey,
  createVerifier,
  setLoadedKeys,
  uint8ArrayToB64,
} from '../utils/crypto';
import { request } from '../utils/api';

interface ChangePassphraseModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess: () => void;
}

export const ChangePassphraseModal: React.FC<ChangePassphraseModalProps> = ({
  isOpen,
  onClose,
  onSuccess,
}) => {
  const [newPassphrase, setNewPassphrase] = useState('');
  const [confirmPassphrase, setConfirmPassphrase] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [stage, setStage] = useState('');

  if (!isOpen) return null;

  const handleRewrap = async (e: React.FormEvent) => {
    e.preventDefault();
    const masterKey = getLoadedMasterKey();
    if (!masterKey) {
      setError('Brankas terkunci! Anda harus membuka brankas terlebih dahulu.');
      return;
    }
    if (newPassphrase.length < 8) {
      setError('Passphrase baru minimal 8 karakter.');
      return;
    }
    if (newPassphrase !== confirmPassphrase) {
      setError('Konfirmasi passphrase baru tidak cocok.');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      setStage('1/4: Menghasilkan Salt 16-byte unik baru...');
      const newSalt = generateSalt(16);
      const newSaltB64 = uint8ArrayToB64(newSalt);

      setStage('2/4: Menurunkan KEK baru via Argon2id WASM...');
      const newKek = await deriveKek(newPassphrase, newSalt);

      setStage('3/4: Membungkus ulang (Re-wrap) Master Key dengan KEK baru via AES-KW...');
      const newWrappedMk = await wrapMasterKey(masterKey, newKek);

      setStage('4/4: Memperbarui verifier string & menyimpan ke peladen...');
      const verifier = await createVerifier(masterKey);

      await request('/auth/rewrap-master-key', {
        method: 'POST',
        body: JSON.stringify({
          argon2Salt: newSaltB64,
          wrappedMasterKey: newWrappedMk,
          verifierCiphertext: verifier.verifierCiphertext,
          verifierIv: verifier.verifierIv,
          verifierWrappedDek: verifier.verifierWrappedDek,
        }),
      });

      // Update RAM state with new KEK
      setLoadedKeys(newKek, masterKey);

      onSuccess();
      onClose();
    } catch (err: any) {
      setError(err.message || 'Gagal mengganti passphrase.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="modal-overlay">
      <div className="modal-content" style={{ padding: '2rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.5rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
            <div style={{
              width: '38px',
              height: '38px',
              borderRadius: '10px',
              background: 'rgba(56, 189, 248, 0.15)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}>
              <RefreshCw size={20} color="var(--accent-cyan)" />
            </div>
            <div>
              <h3 style={{ fontSize: '1.2rem' }}>Ganti Passphrase (Re-Wrap MK)</h3>
              <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                Membungkus ulang 1 Master Key tanpa re-enkripsi berkas
              </p>
            </div>
          </div>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}>
            <X size={20} />
          </button>
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
            fontSize: '0.8rem',
            marginBottom: '1rem',
          }}>
            <AlertTriangle size={18} />
            <span>{error}</span>
          </div>
        )}

        {stage && (
          <p style={{ fontSize: '0.8rem', color: 'var(--accent-cyan)', marginBottom: '1rem' }}>
            {stage}
          </p>
        )}

        <form onSubmit={handleRewrap} style={{ display: 'flex', flexDirection: 'column', gap: '1.15rem' }}>
          <div className="input-group">
            <label className="input-label">Passphrase Brankas Baru</label>
            <input
              type="password"
              value={newPassphrase}
              onChange={(e) => setNewPassphrase(e.target.value)}
              className="input-control"
              placeholder="Minimal 8 karakter"
              required
            />
          </div>

          <div className="input-group">
            <label className="input-label">Konfirmasi Passphrase Baru</label>
            <input
              type="password"
              value={confirmPassphrase}
              onChange={(e) => setConfirmPassphrase(e.target.value)}
              className="input-control"
              placeholder="Ulangi passphrase baru"
              required
            />
          </div>

          <div style={{ display: 'flex', gap: '0.75rem', marginTop: '0.5rem' }}>
            <button type="button" onClick={onClose} className="btn btn-secondary" style={{ flex: 1 }}>
              Batal
            </button>
            <button type="submit" disabled={loading} className="btn btn-primary" style={{ flex: 2 }}>
              <ShieldCheck size={16} />
              {loading ? 'Memproses...' : 'Bungkus Ulang MK'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
