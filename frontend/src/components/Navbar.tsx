import React from 'react';
import { Shield, Lock, Unlock, Key, FileText, UserCheck, LogOut, RefreshCw, Database } from 'lucide-react';
import { User } from '../types';
import { ThemeToggle } from './ThemeToggle';
import { ThemeMode } from '../utils/theme';

interface NavbarProps {
  user: User | null;
  isVaultUnlocked: boolean;
  activeTab: 'files' | 'audit' | 'admin';
  setActiveTab: (tab: 'files' | 'audit' | 'admin') => void;
  onOpenUnlockModal: () => void;
  onLockVault: () => void;
  onOpenChangePassModal: () => void;
  onLogout: () => void;
  currentTheme: ThemeMode;
  onThemeChange: (theme: ThemeMode) => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  user,
  isVaultUnlocked,
  activeTab,
  setActiveTab,
  onOpenUnlockModal,
  onLockVault,
  onOpenChangePassModal,
  onLogout,
  currentTheme,
  onThemeChange,
}) => {
  return (
    <header style={{
      borderBottom: '1px solid var(--border-subtle)',
      background: 'var(--header-bg)',
      backdropFilter: 'blur(16px)',
      position: 'sticky',
      top: 0,
      zIndex: 100,
      transition: 'background-color 0.25s ease',
    }}>
      <div className="container" style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        height: '72px',
        gap: '1rem',
      }}>
        {/* Brand */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.85rem' }}>
          <img
            src="/logo.png"
            alt="Secure Vault Logo"
            style={{
              width: '42px',
              height: '42px',
              objectFit: 'contain',
              flexShrink: 0,
              filter: 'drop-shadow(0 2px 8px var(--accent-cyan-glow))',
            }}
          />
          <div>
            <div style={{ display: 'flex', alignItems: 'center' }}>
              <span style={{ fontSize: '1.3rem', fontWeight: 800, letterSpacing: '-0.02em', color: 'var(--text-primary)' }}>
                SECURE<span style={{ color: 'var(--accent-cyan)' }}>VAULT</span>
              </span>
            </div>
            <p style={{ fontSize: '0.735rem', color: 'var(--text-muted)', letterSpacing: '0.01em', marginTop: '0.18rem' }}>
              Encrypted File Storage &bull; Zero-Knowledge Architecture
            </p>
          </div>
        </div>

        {/* Navigation Tabs */}
        {user && (
          <nav style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <button
              onClick={() => setActiveTab('files')}
              className={`btn btn-sm ${activeTab === 'files' ? 'btn-primary' : 'btn-secondary'}`}
              style={{ borderRadius: 'var(--radius-full)' }}
            >
              <Database size={15} />
              Brankas Berkas
            </button>
            <button
              onClick={() => setActiveTab('audit')}
              className={`btn btn-sm ${activeTab === 'audit' ? 'btn-primary' : 'btn-secondary'}`}
              style={{ borderRadius: 'var(--radius-full)' }}
            >
              <FileText size={15} />
              Audit Trail (Hash-Chain)
            </button>
            {user.role === 'admin' && (
              <button
                onClick={() => setActiveTab('admin')}
                className={`btn btn-sm ${activeTab === 'admin' ? 'btn-primary' : 'btn-secondary'}`}
                style={{ borderRadius: 'var(--radius-full)' }}
              >
                <UserCheck size={15} />
                Konsol Admin
              </button>
            )}
          </nav>
        )}

        {/* Controls: Theme Switcher & User Profile */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          {/* Theme Toggle (Light / Dark / System) */}
          <ThemeToggle currentTheme={currentTheme} onThemeChange={onThemeChange} />

          {user ? (
            <>
              {/* Vault Status Indicator */}
              {isVaultUnlocked ? (
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <span className="badge badge-emerald" style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                    <Unlock size={13} />
                    RAM Active
                  </span>
                  <button
                    onClick={onLockVault}
                    className="btn btn-sm btn-secondary"
                    title="Kunci Brankas & Bersihkan Kunci dari RAM"
                    style={{ color: 'var(--accent-amber)' }}
                  >
                    <Lock size={14} />
                    Kunci
                  </button>
                  <button
                    onClick={onOpenChangePassModal}
                    className="btn btn-sm btn-outline"
                    title="Ganti Passphrase (Re-wrap Master Key)"
                  >
                    <RefreshCw size={13} />
                    Re-Wrap
                  </button>
                </div>
              ) : (
                <button
                  onClick={onOpenUnlockModal}
                  className="btn btn-sm btn-primary"
                  style={{ animation: 'pulseGlow 3s infinite' }}
                >
                  <Key size={14} />
                  Buka Brankas
                </button>
              )}

              {/* User Profile Chip */}
              <div style={{
                display: 'flex',
                alignItems: 'center',
                gap: '0.5rem',
                padding: '0.3rem 0.75rem',
                borderRadius: 'var(--radius-full)',
                background: 'var(--surface-input)',
                border: '1px solid var(--border-subtle)',
              }}>
                <div style={{
                  width: '26px',
                  height: '26px',
                  borderRadius: '50%',
                  background: user.role === 'admin' ? 'var(--accent-indigo)' : 'var(--accent-cyan)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  fontSize: '0.75rem',
                  fontWeight: 700,
                  color: '#fff',
                }}>
                  {user.username.charAt(0).toUpperCase()}
                </div>
                <div style={{ display: 'flex', flexDirection: 'column' }}>
                  <span style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                    {user.username}
                  </span>
                  <span style={{ fontSize: '0.65rem', color: user.role === 'admin' ? 'var(--accent-indigo)' : 'var(--accent-cyan)', fontWeight: 700 }}>
                    {user.role.toUpperCase()}
                  </span>
                </div>
              </div>

              {/* Logout */}
              <button
                onClick={onLogout}
                className="btn btn-sm btn-danger"
                title="Logout Sesi"
              >
                <LogOut size={15} />
              </button>
            </>
          ) : null}
        </div>
      </div>
    </header>
  );
};
