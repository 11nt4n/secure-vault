import React, { useState } from 'react';
import { Lock, User, ArrowRight, Smartphone, AlertTriangle, Copy, CheckCircle2 } from 'lucide-react';
import { request, setAuthToken } from '../utils/api';
import { User as UserType } from '../types';

interface LoginProps {
  onLoginSuccess: (user: UserType, token: string) => void;
}

interface MfaSetupResponse {
  secret: string;
  otpauthUri: string;
  issuer: string;
  message: string;
}

export const Login: React.FC<LoginProps> = ({ onLoginSuccess }) => {
  const [isRegister, setIsRegister] = useState(false);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [email, setEmail] = useState('');

  const [mfaRequired, setMfaRequired] = useState(false);
  const [mfaSetupRequired, setMfaSetupRequired] = useState(false);
  const [mfaToken, setMfaToken] = useState('');
  const [totpCode, setTotpCode] = useState('');
  const [mfaSecret, setMfaSecret] = useState('');
  const [secretCopied, setSecretCopied] = useState(false);

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const resetMfaFlow = () => {
    setMfaRequired(false);
    setMfaSetupRequired(false);
    setMfaToken('');
    setTotpCode('');
    setMfaSecret('');
    setSecretCopied(false);
    setError(null);
    setNotice(null);
  };

  const handleLoginSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setNotice(null);
    setLoading(true);

    try {
      if (isRegister) {
        await request<{ user: UserType; message: string }>('/auth/register', {
          method: 'POST',
          body: JSON.stringify({ username, password, email }),
        });
        setIsRegister(false);
        setPassword('');
        setNotice('Registrasi berhasil. Silakan masuk dan aktifkan TOTP menggunakan aplikasi authenticator.');
      } else {
        const res = await request<{
          mfaRequired?: boolean;
          mfaSetupRequired?: boolean;
          mfaToken?: string;
          token?: string;
          user?: UserType;
        }>('/auth/login', {
          method: 'POST',
          body: JSON.stringify({ username, password }),
        });

        if (res.mfaRequired && res.mfaToken) {
          // Password validation is complete; clear the raw password before the TOTP step.
          setPassword('');
          setMfaToken(res.mfaToken);
          setMfaSetupRequired(Boolean(res.mfaSetupRequired));
          setTotpCode('');
          if (res.mfaSetupRequired) {
            const setup = await request<MfaSetupResponse>('/auth/mfa/setup', {
              method: 'POST',
              body: JSON.stringify({ mfaToken: res.mfaToken }),
            });
            setMfaSecret(setup.secret);
          } else {
            setMfaSecret('');
          }
          setMfaRequired(true);
        } else if (res.token && res.user) {
          // The PHP API should never issue a session before MFA has been verified.
          throw new Error('Respons autentikasi tidak lengkap. Silakan periksa konfigurasi server.');
        } else {
          throw new Error('Server tidak mengembalikan tantangan MFA yang valid.');
        }
      }
    } catch (err: any) {
      setError(err.message || 'Gagal memproses autentikasi.');
    } finally {
      setLoading(false);
    }
  };

  const handleMfaSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      const res = await request<{ token: string; user: UserType }>('/auth/mfa/verify', {
        method: 'POST',
        body: JSON.stringify({ mfaToken, code: totpCode }),
      });
      setAuthToken(res.token);
      setPassword('');
      setTotpCode('');
      setMfaSecret('');
      onLoginSuccess(res.user, res.token);
    } catch (err: any) {
      setError(err.message || 'Kode autentikator tidak valid.');
    } finally {
      setLoading(false);
    }
  };

  const copySecret = async () => {
    try {
      await navigator.clipboard.writeText(mfaSecret);
      setSecretCopied(true);
    } catch {
      setError('Secret tidak dapat disalin otomatis. Salin secret yang ditampilkan secara manual.');
    }
  };

  return (
    <div style={{
      minHeight: 'calc(100vh - 70px)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      padding: '2rem 1rem',
    }}>
      <div className="glass-card" style={{ width: '100%', maxWidth: '460px', padding: '2.5rem' }}>
        <div style={{ textAlign: 'center', marginBottom: '2rem' }}>
          <img
            src="/logo.png"
            alt="Secure Vault Logo"
            style={{
              width: '74px', height: '74px', objectFit: 'contain', display: 'block',
              margin: '0 auto 1.25rem', filter: 'drop-shadow(0 4px 16px var(--accent-cyan-glow))',
            }}
          />
          <h2 style={{ fontSize: '1.6rem', marginBottom: '0.35rem' }}>
            {mfaRequired
              ? (mfaSetupRequired ? 'Aktifkan Authenticator' : 'Verifikasi Dua Faktor (MFA)')
              : isRegister
                ? 'Daftar Akun Secure Vault'
                : 'Selamat Datang di Secure Vault'}
          </h2>
          <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
            {mfaRequired
              ? (mfaSetupRequired
                ? 'Pindai QR code pada aplikasi authenticator untuk mengamankan akun Anda.'
                : 'Masukkan kode 6 digit dari aplikasi authenticator Anda untuk melanjutkan.')
              : (isRegister
                ? 'Buat akun baru untuk mulai mengamankan berkas dengan enkripsi zero-knowledge.'
                : 'Silakan masuk ke akun Anda untuk mengakses brankas berkas terenkripsi.')}
          </p>
        </div>

        {notice && !error && (
          <div style={{
            display: 'flex', alignItems: 'center', gap: '0.6rem', padding: '0.8rem 1rem',
            borderRadius: 'var(--radius-md)', background: 'rgba(56, 189, 248, 0.08)',
            border: '1px solid var(--border-card)', color: 'var(--text-primary)',
            fontSize: '0.825rem', marginBottom: '1.5rem',
          }}>
            <CheckCircle2 size={18} style={{ flexShrink: 0 }} />
            <span>{notice}</span>
          </div>
        )}

        {error && (
          <div style={{
            display: 'flex', alignItems: 'center', gap: '0.6rem', padding: '0.8rem 1rem',
            borderRadius: 'var(--radius-md)', background: 'var(--badge-rose-bg)',
            border: '1px solid var(--accent-rose)', color: 'var(--accent-rose)',
            fontSize: '0.825rem', marginBottom: '1.5rem',
          }}>
            <AlertTriangle size={18} style={{ flexShrink: 0 }} />
            <span>{error}</span>
          </div>
        )}

        {mfaRequired ? (
          <form onSubmit={handleMfaSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
            {mfaSetupRequired && (
              <div style={{
                padding: '1rem', borderRadius: 'var(--radius-md)', background: 'rgba(56, 189, 248, 0.08)',
                border: '1px solid var(--border-card)', fontSize: '0.825rem', color: 'var(--text-secondary)', lineHeight: 1.5,
              }}>
                <p style={{ marginTop: 0 }}><strong>1. Tambahkan akun secara manual</strong></p>
                <p>Di aplikasi authenticator, buat akun TOTP baru dengan issuer <strong>Secure Vault</strong>, nama akun <strong>{username}</strong>, dan secret berikut:</p>
                <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', margin: '0.75rem 0', flexWrap: 'wrap' }}>
                  <code style={{ fontSize: '0.95rem', letterSpacing: '0.08em', overflowWrap: 'anywhere', color: 'var(--text-primary)' }}>{mfaSecret}</code>
                  <button type="button" onClick={copySecret} className="btn btn-secondary btn-sm" aria-label="Salin secret TOTP">
                    {secretCopied ? <CheckCircle2 size={14} /> : <Copy size={14} />}
                    {secretCopied ? 'Tersalin' : 'Salin'}
                  </button>
                </div>
                <p style={{ marginBottom: 0 }}>Gunakan TOTP, 6 digit, dengan periode 30 detik. Simpan akun authenticator dengan aman. Secret ini hanya ditampilkan pada tahap aktivasi.</p>
              </div>
            )}

            <div className="input-group">
              <label className="input-label">
                {mfaSetupRequired ? '2. Masukkan kode untuk mengaktifkan TOTP' : 'Kode autentikator (6 digit)'}
              </label>
              <div style={{ position: 'relative' }}>
                <Smartphone size={18} color="var(--text-muted)" style={{ position: 'absolute', left: '1rem', top: '50%', transform: 'translateY(-50%)' }} />
                <input
                  type="text"
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  pattern="[0-9]{6}"
                  maxLength={6}
                  value={totpCode}
                  onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                  className="input-control mono"
                  style={{ paddingLeft: '2.8rem', fontSize: '1.25rem', letterSpacing: '0.3em', textAlign: 'center' }}
                  required
                  autoFocus
                />
              </div>
            </div>

            <button type="submit" className="btn btn-primary" style={{ width: '100%', padding: '0.8rem' }} disabled={loading || totpCode.length !== 6 || (mfaSetupRequired && !mfaSecret)}>
              {loading ? 'Memverifikasi...' : mfaSetupRequired ? 'Aktifkan TOTP & Masuk' : 'Verifikasi & Masuk'}
              <ArrowRight size={16} />
            </button>
            <button type="button" onClick={resetMfaFlow} className="btn btn-secondary btn-sm" style={{ width: '100%' }} disabled={loading}>
              Kembali ke Login
            </button>
          </form>
        ) : (
          <form onSubmit={handleLoginSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '1.15rem' }}>
            <div className="input-group">
              <label className="input-label">Username</label>
              <div style={{ position: 'relative' }}>
                <User size={18} color="var(--text-muted)" style={{ position: 'absolute', left: '1rem', top: '50%', transform: 'translateY(-50%)' }} />
                <input type="text" value={username} onChange={(e) => setUsername(e.target.value)} className="input-control" style={{ paddingLeft: '2.8rem' }} placeholder="Masukkan username" required autoComplete="username" />
              </div>
            </div>

            {isRegister && (
              <div className="input-group">
                <label className="input-label">Email</label>
                <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} className="input-control" placeholder="nama@contoh.id" required autoComplete="email" />
              </div>
            )}

            <div className="input-group">
              <label className="input-label">Kata Sandi</label>
              <div style={{ position: 'relative' }}>
                <Lock size={18} color="var(--text-muted)" style={{ position: 'absolute', left: '1rem', top: '50%', transform: 'translateY(-50%)' }} />
                <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} className="input-control" style={{ paddingLeft: '2.8rem' }} placeholder="Masukkan kata sandi" required minLength={isRegister ? 12 : undefined} autoComplete={isRegister ? 'new-password' : 'current-password'} />
              </div>
              {isRegister && <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', margin: '0.4rem 0 0' }}>Minimal 12 karakter. Gunakan kata sandi unik yang tidak dipakai di layanan lain.</p>}
            </div>

            <button type="submit" className="btn btn-primary" style={{ width: '100%', padding: '0.8rem', marginTop: '0.5rem' }} disabled={loading || (isRegister && password.length < 12)}>
              {loading ? 'Memproses...' : isRegister ? 'Daftar Akun Baru' : 'Masuk & Lanjutkan MFA'}
              <ArrowRight size={16} />
            </button>

            <div style={{ textAlign: 'center', marginTop: '0.5rem' }}>
              <button type="button" onClick={() => { setIsRegister(!isRegister); setError(null); setNotice(null); setPassword(''); }} style={{ background: 'none', border: 'none', color: 'var(--accent-cyan)', cursor: 'pointer', fontSize: '0.825rem', fontWeight: 600 }}>
                {isRegister ? 'Sudah memiliki akun? Masuk di sini' : 'Belum memiliki akun? Daftarkan akun baru'}
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
};
