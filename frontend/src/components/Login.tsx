import React, { useState } from 'react';
import { Shield, Lock, User, KeyRound, CheckCircle2, AlertTriangle, ArrowRight, Smartphone } from 'lucide-react';
import { request, setAuthToken } from '../utils/api';
import { User as UserType } from '../types';

interface LoginProps {
  onLoginSuccess: (user: UserType, token: string) => void;
}

export const Login: React.FC<LoginProps> = ({ onLoginSuccess }) => {
  const [isRegister, setIsRegister] = useState(false);
  const [username, setUsername] = useState('user');
  const [password, setPassword] = useState('user123');
  const [email, setEmail] = useState('evaluator@bssn.go.id');
  const [role, setRole] = useState<'user' | 'admin'>('user');

  // MFA state
  const [mfaRequired, setMfaRequired] = useState(false);
  const [mfaToken, setMfaToken] = useState('');
  const [totpCode, setTotpCode] = useState('');
  const [tempUser, setTempUser] = useState<UserType | null>(null);

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleLoginSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      if (isRegister) {
        const res = await request<{ user: UserType; message: string }>('/auth/register', {
          method: 'POST',
          body: JSON.stringify({ username, password, email, role }),
        });
        setIsRegister(false);
        setError('Registrasi berhasil! Silakan login dengan akun baru Anda.');
      } else {
        const res = await request<{
          mfaRequired?: boolean;
          mfaToken?: string;
          token?: string;
          user?: UserType;
        }>('/auth/login', {
          method: 'POST',
          body: JSON.stringify({ username, password }),
        });

        if (res.mfaRequired && res.mfaToken) {
          setMfaRequired(true);
          setMfaToken(res.mfaToken);
          setTempUser(res.user || null);
          setTotpCode('123456'); // Pre-fill default demo TOTP
        } else if (res.token && res.user) {
          setAuthToken(res.token);
          onLoginSuccess(res.user, res.token);
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
      onLoginSuccess(res.user, res.token);
    } catch (err: any) {
      setError(err.message || 'Kode MFA tidak valid.');
    } finally {
      setLoading(false);
    }
  };

  const setDemoAccount = (accType: 'admin' | 'user') => {
    if (accType === 'admin') {
      setUsername('admin');
      setPassword('admin123');
      setRole('admin');
    } else {
      setUsername('user');
      setPassword('user123');
      setRole('user');
    }
    setError(null);
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
        {/* Security Header */}
        <div style={{ textAlign: 'center', marginBottom: '2rem' }}>
          <img
            src="/logo.png"
            alt="Secure Vault Logo"
            style={{
              width: '74px',
              height: '74px',
              objectFit: 'contain',
              display: 'block',
              margin: '0 auto 1.25rem',
              filter: 'drop-shadow(0 4px 16px var(--accent-cyan-glow))',
            }}
          />
          <h2 style={{ fontSize: '1.6rem', marginBottom: '0.35rem' }}>
            {mfaRequired ? 'Tantangan MFA (TOTP)' : isRegister ? 'Registrasi Akun Baru' : 'Masuk ke Secure Vault'}
          </h2>
          <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
            {mfaRequired
              ? 'Masukkan 6 digit kode dari aplikasi authenticator Anda'
              : 'Otentikasi Zero-Trust terpusat OIDC & Enkripsi Klien 3 Lapis'}
          </p>
        </div>

        {error && (
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: '0.6rem',
            padding: '0.8rem 1rem',
            borderRadius: 'var(--radius-md)',
            background: 'var(--badge-rose-bg)',
            border: '1px solid var(--accent-rose)',
            color: 'var(--accent-rose)',
            fontSize: '0.825rem',
            marginBottom: '1.5rem',
          }}>
            <AlertTriangle size={18} style={{ flexShrink: 0 }} />
            <span>{error}</span>
          </div>
        )}

        {mfaRequired ? (
          /* MFA Verification Form */
          <form onSubmit={handleMfaSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
            <div className="input-group">
              <label className="input-label">
                <span>Kode Otentikasi (TOTP 6 Digit)</span>
                <span style={{ color: 'var(--accent-cyan)', fontWeight: 600 }}>Demo: 123456</span>
              </label>
              <div style={{ position: 'relative' }}>
                <Smartphone size={18} color="var(--text-muted)" style={{ position: 'absolute', left: '1rem', top: '50%', transform: 'translateY(-50%)' }} />
                <input
                  type="text"
                  maxLength={6}
                  value={totpCode}
                  onChange={(e) => setTotpCode(e.target.value)}
                  className="input-control mono"
                  style={{ paddingLeft: '2.8rem', fontSize: '1.25rem', letterSpacing: '0.3em', textAlign: 'center' }}
                  required
                  autoFocus
                />
              </div>
            </div>

            <button type="submit" className="btn btn-primary" style={{ width: '100%', padding: '0.8rem' }} disabled={loading}>
              {loading ? 'Memverifikasi...' : 'Verifikasi & Masuk'}
              <ArrowRight size={16} />
            </button>

            <button
              type="button"
              onClick={() => { setMfaRequired(false); setError(null); }}
              className="btn btn-secondary btn-sm"
              style={{ width: '100%' }}
            >
              Kembali ke Login
            </button>
          </form>
        ) : (
          /* Login / Register Form */
          <form onSubmit={handleLoginSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '1.15rem' }}>
            <div className="input-group">
              <label className="input-label">Username</label>
              <div style={{ position: 'relative' }}>
                <User size={18} color="var(--text-muted)" style={{ position: 'absolute', left: '1rem', top: '50%', transform: 'translateY(-50%)' }} />
                <input
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  className="input-control"
                  style={{ paddingLeft: '2.8rem' }}
                  placeholder="Masukkan username"
                  required
                />
              </div>
            </div>

            {isRegister && (
              <div className="input-group">
                <label className="input-label">Email Kedinasan (BSSN)</label>
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="input-control"
                  placeholder="nama@bssn.go.id"
                  required
                />
              </div>
            )}

            <div className="input-group">
              <label className="input-label">Kata Sandi (SSO Password)</label>
              <div style={{ position: 'relative' }}>
                <Lock size={18} color="var(--text-muted)" style={{ position: 'absolute', left: '1rem', top: '50%', transform: 'translateY(-50%)' }} />
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="input-control"
                  style={{ paddingLeft: '2.8rem' }}
                  placeholder="Masukkan password SSO"
                  required
                />
              </div>
            </div>

            {isRegister && (
              <div className="input-group">
                <label className="input-label">Peran Sistem (Role RBAC)</label>
                <select
                  value={role}
                  onChange={(e) => setRole(e.target.value as 'user' | 'admin')}
                  className="input-control"
                >
                  <option value="user">Pengguna / Evaluator Sandi (User)</option>
                  <option value="admin">Administrator Sistem (Admin)</option>
                </select>
              </div>
            )}

            <button type="submit" className="btn btn-primary" style={{ width: '100%', padding: '0.8rem', marginTop: '0.5rem' }} disabled={loading}>
              {loading ? 'Memproses...' : isRegister ? 'Daftar Akun Baru' : 'Masuk SSO & Lanjut MFA'}
              <ArrowRight size={16} />
            </button>

            {/* Switch Mode */}
            <div style={{ textAlign: 'center', marginTop: '0.5rem' }}>
              <button
                type="button"
                onClick={() => { setIsRegister(!isRegister); setError(null); }}
                style={{ background: 'none', border: 'none', color: 'var(--accent-cyan)', cursor: 'pointer', fontSize: '0.825rem', fontWeight: 600 }}
              >
                {isRegister ? 'Sudah memiliki akun? Masuk di sini' : 'Belum memiliki akun? Daftarkan akun baru'}
              </button>
            </div>

            {/* Quick Demo Credentials */}
            {!isRegister && (
              <div style={{
                marginTop: '1.25rem',
                paddingTop: '1.25rem',
                borderTop: '1px solid var(--border-subtle)',
              }}>
                <p style={{ fontSize: '0.725rem', color: 'var(--text-muted)', marginBottom: '0.5rem', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 700 }}>
                  Akun Demo Evaluasi PKL BSSN:
                </p>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem' }}>
                  <button
                    type="button"
                    onClick={() => setDemoAccount('user')}
                    className="btn btn-secondary btn-sm"
                    style={{ fontSize: '0.75rem', justifyContent: 'flex-start' }}
                  >
                    <CheckCircle2 size={13} color="var(--accent-cyan)" />
                    User / Sandiman
                  </button>
                  <button
                    type="button"
                    onClick={() => setDemoAccount('admin')}
                    className="btn btn-secondary btn-sm"
                    style={{ fontSize: '0.75rem', justifyContent: 'flex-start' }}
                  >
                    <Shield size={13} color="var(--accent-indigo)" />
                    Administrator
                  </button>
                </div>
              </div>
            )}
          </form>
        )}
      </div>
    </div>
  );
};
