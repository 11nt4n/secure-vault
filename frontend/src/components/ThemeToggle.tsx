import React from 'react';
import { Sun, Moon, Laptop } from 'lucide-react';
import { ThemeMode } from '../utils/theme';

interface ThemeToggleProps {
  currentTheme: ThemeMode;
  onThemeChange: (theme: ThemeMode) => void;
}

export const ThemeToggle: React.FC<ThemeToggleProps> = ({ currentTheme, onThemeChange }) => {
  return (
    <div
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        background: 'var(--surface-input)',
        border: '1px solid var(--border-subtle)',
        borderRadius: 'var(--radius-full)',
        padding: '3px',
        gap: '2px',
      }}
      title="Ubah Tema Tampilan (Terang / Gelap / Sistem)"
    >
      <button
        type="button"
        onClick={() => onThemeChange('light')}
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          width: '28px',
          height: '28px',
          borderRadius: '50%',
          border: 'none',
          cursor: 'pointer',
          background: currentTheme === 'light' ? 'var(--accent-cyan)' : 'transparent',
          color: currentTheme === 'light' ? '#060913' : 'var(--text-muted)',
          transition: 'all 0.2s ease',
        }}
        title="Tema Terang (Light)"
      >
        <Sun size={15} />
      </button>

      <button
        type="button"
        onClick={() => onThemeChange('dark')}
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          width: '28px',
          height: '28px',
          borderRadius: '50%',
          border: 'none',
          cursor: 'pointer',
          background: currentTheme === 'dark' ? 'var(--accent-cyan)' : 'transparent',
          color: currentTheme === 'dark' ? '#060913' : 'var(--text-muted)',
          transition: 'all 0.2s ease',
        }}
        title="Tema Gelap (Dark)"
      >
        <Moon size={14} />
      </button>

      <button
        type="button"
        onClick={() => onThemeChange('system')}
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          width: '28px',
          height: '28px',
          borderRadius: '50%',
          border: 'none',
          cursor: 'pointer',
          background: currentTheme === 'system' ? 'var(--accent-cyan)' : 'transparent',
          color: currentTheme === 'system' ? '#060913' : 'var(--text-muted)',
          transition: 'all 0.2s ease',
        }}
        title="Otomatis Sesuai Sistem (System)"
      >
        <Laptop size={14} />
      </button>
    </div>
  );
};
