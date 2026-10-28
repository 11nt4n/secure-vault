import React, { useState, useEffect } from 'react';
import { Shield, Users, HardDrive, Ban, CheckCircle2, AlertTriangle, RefreshCw, KeyRound, Lock } from 'lucide-react';
import { request } from '../utils/api';
import { AdminStats } from '../types';

interface ManagedUser {
  id: string;
  username: string;
  email: string;
  role: string;
  storage_quota_bytes: number;
  storage_used_bytes: number;
  is_active: boolean;
  created_at: string;
}

export const AdminConsole: React.FC = () => {
  const [users, setUsers] = useState<ManagedUser[]>([]);
  const [stats, setStats] = useState<AdminStats | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  useEffect(() => {
    fetchAdminData();
  }, []);

  const fetchAdminData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [uRes, sRes] = await Promise.all([
        request<{ users: ManagedUser[] }>('/admin/users'),
        request<{ stats: AdminStats }>('/admin/stats'),
      ]);
      setUsers(uRes.users);
      setStats(sRes.stats);
    } catch (err: any) {
      setError(err.message || 'Gagal memuat data konsol admin.');
    } finally {
      setLoading(false);
    }
  };

  const handleUpdateQuota = async (userId: string, currentGb: number) => {
    const input = window.prompt(`Masukkan kuota baru dalam GB (saat ini: ${currentGb} GB):`, currentGb.toString());
    if (!input || isNaN(Number(input))) return;

    const newBytes = Number(input) * 1024 * 1024 * 1024;
    try {
      await request(`/admin/users/${userId}/quota`, {
        method: 'PATCH',
        body: JSON.stringify({ storageQuotaBytes: newBytes }),
      });
      setSuccessMsg(`Kuota pengguna berhasil diperbarui menjadi ${input} GB.`);
      fetchAdminData();
    } catch (err: any) {
      setError(err.message || 'Gagal memperbarui kuota.');
    }
  };

  const handleRevokeSession = async (userId: string) => {
    if (!window.confirm('Cabut seluruh sesi aktif pengguna ini seketika? Pengguna akan dipaksa logout.')) {
      return;
    }

    try {
      await request(`/admin/users/${userId}/revoke`, { method: 'POST' });
      setSuccessMsg('Sesi aktif pengguna berhasil dicabut (Instant Revocation).');
      fetchAdminData();
    } catch (err: any) {
      setError(err.message || 'Gagal mencabut sesi.');
    }
  };

  return (
    <div className="container" style={{ padding: '2rem 1.5rem' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '2rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <div style={{
            width: '42px',
            height: '42px',
            borderRadius: '12px',
            background: 'linear-gradient(135deg, rgba(99, 102, 241, 0.3) 0%, rgba(56, 189, 248, 0.2) 100%)',
            border: '1px solid var(--border-card)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
          }}>
            <Shield size={24} color="var(--accent-indigo)" />
          </div>
          <div>
            <h2 style={{ fontSize: '1.5rem' }}>Konsol Pengawasan Administrator</h2>
            <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
              Tata Kelola Pengguna, Kuota Storage & Penegakan Kebijakan Zero-Trust (BSSN PKL)
            </p>
          </div>
        </div>

        <button onClick={fetchAdminData} className="btn btn-secondary btn-sm">
          <RefreshCw size={14} /> Refresh Data
        </button>
      </div>

      {/* Separation of Duties Notice */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        gap: '0.75rem',
        padding: '0.9rem 1.25rem',
        borderRadius: 'var(--radius-md)',
        background: 'var(--badge-cyan-bg)',
        border: '1px solid var(--border-card)',
        marginBottom: '2rem',
      }}>
        <Lock size={20} color="var(--accent-cyan)" style={{ flexShrink: 0 }} />
        <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
          <strong style={{ color: 'var(--text-primary)' }}>Prinsip Least Privilege & Separation of Duties:</strong> Administrator memiliki hak tata kelola akun dan pemantauan sistem, tetapi <em>dilarang dan tidak memiliki kemampuan teknis</em> untuk membaca, mengunduh, atau mendekripsi isi berkas pengguna mana pun.
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
          marginBottom: '1.5rem',
        }}>
          <AlertTriangle size={18} />
          <span>{error}</span>
        </div>
      )}

      {successMsg && (
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '0.5rem',
          padding: '0.75rem 1rem',
          borderRadius: 'var(--radius-md)',
          background: 'var(--badge-emerald-bg)',
          border: '1px solid var(--accent-emerald)',
          color: 'var(--accent-emerald)',
          fontSize: '0.825rem',
          marginBottom: '1.5rem',
        }}>
          <CheckCircle2 size={18} />
          <span>{successMsg}</span>
        </div>
      )}

      {/* Stats Cards */}
      {stats && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '1.25rem', marginBottom: '2rem' }}>
          <div className="glass-card" style={{ padding: '1.25rem' }}>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontWeight: 600 }}>TOTAL PENGGUNA</span>
            <div style={{ fontSize: '1.75rem', fontWeight: 800, marginTop: '0.35rem' }}>{stats.totalUsers}</div>
          </div>
          <div className="glass-card" style={{ padding: '1.25rem' }}>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontWeight: 600 }}>TOTAL BERKAS ENKRIPSI</span>
            <div style={{ fontSize: '1.75rem', fontWeight: 800, marginTop: '0.35rem' }}>{stats.totalFiles}</div>
          </div>
          <div className="glass-card" style={{ padding: '1.25rem' }}>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontWeight: 600 }}>CIPHERTEXT DI DISK</span>
            <div style={{ fontSize: '1.75rem', fontWeight: 800, marginTop: '0.35rem' }}>
              {(stats.totalCiphertextBytes / (1024 * 1024)).toFixed(1)} MB
            </div>
          </div>
          <div className="glass-card" style={{ padding: '1.25rem' }}>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontWeight: 600 }}>PANJANG RANTAI HASH</span>
            <div style={{ fontSize: '1.75rem', fontWeight: 800, marginTop: '0.35rem', color: 'var(--accent-emerald)' }}>
              {stats.auditChainLength} blok
            </div>
          </div>
        </div>
      )}

      {/* Users Table */}
      <div className="glass-card" style={{ overflow: 'hidden' }}>
        <div style={{ padding: '1.25rem', borderBottom: '1px solid var(--border-subtle)' }}>
          <h3 style={{ fontSize: '1.1rem' }}>Daftar Akun Pengguna</h3>
        </div>
        <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.85rem' }}>
          <thead>
            <tr style={{
              background: 'var(--table-header-bg)',
              borderBottom: '1px solid var(--border-subtle)',
              color: 'var(--text-secondary)',
              fontSize: '0.75rem',
              textTransform: 'uppercase',
            }}>
              <th style={{ padding: '0.9rem 1.25rem' }}>Username / Email</th>
              <th style={{ padding: '0.9rem 1rem' }}>Peran (Role)</th>
              <th style={{ padding: '0.9rem 1rem' }}>Alokasi Kuota</th>
              <th style={{ padding: '0.9rem 1rem' }}>Status Akun</th>
              <th style={{ padding: '0.9rem 1.25rem', textAlign: 'right' }}>Aksi Admin</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr>
                <td colSpan={5} style={{ padding: '3rem', textAlign: 'center', color: 'var(--text-muted)' }}>
                  Memuat daftar pengguna...
                </td>
              </tr>
            ) : (
              users.map((u) => {
                const quotaGb = (u.storage_quota_bytes / (1024 * 1024 * 1024)).toFixed(1);
                const usedMb = (u.storage_used_bytes / (1024 * 1024)).toFixed(1);
                return (
                  <tr key={u.id} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                    <td style={{ padding: '1rem 1.25rem' }}>
                      <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{u.username}</div>
                      <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{u.email}</div>
                    </td>
                    <td style={{ padding: '1rem' }}>
                      <span className={`badge ${u.role === 'admin' ? 'badge-rose' : 'badge-cyan'}`} style={{ fontSize: '0.7rem' }}>
                        {u.role.toUpperCase()}
                      </span>
                    </td>
                    <td style={{ padding: '1rem' }}>
                      <div style={{ fontSize: '0.85rem', fontWeight: 600 }}>{quotaGb} GB</div>
                      <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Terpakai: {usedMb} MB</div>
                    </td>
                    <td style={{ padding: '1rem' }}>
                      <span className={`badge ${u.is_active ? 'badge-emerald' : 'badge-rose'}`} style={{ fontSize: '0.7rem' }}>
                        {u.is_active ? 'AKTIF' : 'DINONAKTIFKAN'}
                      </span>
                    </td>
                    <td style={{ padding: '1rem 1.25rem', textAlign: 'right' }}>
                      <div style={{ display: 'inline-flex', gap: '0.5rem' }}>
                        <button
                          onClick={() => handleUpdateQuota(u.id, Number(quotaGb))}
                          className="btn btn-secondary btn-sm"
                          title="Ubah Kuota"
                        >
                          Atur Kuota
                        </button>
                        <button
                          onClick={() => handleRevokeSession(u.id)}
                          className="btn btn-danger btn-sm"
                          title="Cabut Sesi Aktif"
                        >
                          <Ban size={13} /> Cabut Sesi
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
