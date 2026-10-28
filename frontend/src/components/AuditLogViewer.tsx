import React, { useState, useEffect } from 'react';
import { FileText, ShieldCheck, ShieldAlert, RefreshCw, Filter, CheckCircle2, AlertTriangle, Link2 } from 'lucide-react';
import { AuditLogEntry } from '../types';
import { request } from '../utils/api';

export const AuditLogViewer: React.FC = () => {
  const [logs, setLogs] = useState<AuditLogEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const [verifying, setVerifying] = useState(false);
  const [filterAction, setFilterAction] = useState('ALL');
  const [filterStatus, setFilterStatus] = useState('ALL');
  const [integrityStatus, setIntegrityStatus] = useState<{
    verified: boolean;
    brokenIndex: number | null;
    message: string;
  } | null>(null);

  useEffect(() => {
    fetchLogs();
  }, []);

  const fetchLogs = async () => {
    setLoading(true);
    setIntegrityStatus(null);
    try {
      const res = await request<{ logs: AuditLogEntry[] }>('/audit');
      setLogs(res.logs);
    } catch (err: any) {
      console.error('Error fetching audit logs:', err);
    } finally {
      setLoading(false);
    }
  };

  /**
   * Verify SHA-256 Hash-Chain mathematically in the browser
   */
  const handleVerifyChain = async () => {
    setVerifying(true);
    try {
      const res = await request<{
        isValid: boolean;
        totalRecords: number;
        brokenSequence?: number;
        message: string;
      }>('/audit/verify');

      setIntegrityStatus({
        verified: res.isValid,
        brokenIndex: res.brokenSequence ?? null,
        message: res.message,
      });
    } catch (err: any) {
      setIntegrityStatus({
        verified: false,
        brokenIndex: null,
        message: 'Gagal memverifikasi rantai hash: ' + err.message,
      });
    } finally {
      setVerifying(false);
    }
  };

  const filteredLogs = logs.filter((l) => {
    const actionMatch = filterAction === 'ALL' || l.action_type === filterAction;
    const statusMatch = filterStatus === 'ALL' || l.status === filterStatus;
    return actionMatch && statusMatch;
  });

  return (
    <div className="container" style={{ padding: '2rem 1.5rem' }}>
      {/* Header */}
      <div style={{
        display: 'flex',
        flexWrap: 'wrap',
        alignItems: 'center',
        justifyContent: 'space-between',
        gap: '1rem',
        marginBottom: '2rem',
      }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
            <div style={{
              width: '40px',
              height: '40px',
              borderRadius: '12px',
              background: 'linear-gradient(135deg, rgba(99, 102, 241, 0.2) 0%, rgba(56, 189, 248, 0.2) 100%)',
              border: '1px solid var(--border-card)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}>
              <FileText size={22} color="var(--accent-cyan)" />
            </div>
            <div>
              <h2 style={{ fontSize: '1.5rem' }}>Jejak Audit Tahan Manipulasi (Tamper-Resistant Audit Trail)</h2>
              <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                Rantai kriptografi SHA-256 hash-chain &bull; Non-Repudiasi &bull; Row-Locking PostgreSQL (SELECT FOR UPDATE)
              </p>
            </div>
          </div>
        </div>

        {/* Actions */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <button onClick={fetchLogs} className="btn btn-secondary btn-sm" title="Refresh Log">
            <RefreshCw size={14} /> Refresh
          </button>
          <button
            onClick={handleVerifyChain}
            disabled={verifying || logs.length === 0}
            className="btn btn-primary btn-sm"
          >
            <ShieldCheck size={15} />
            {verifying ? 'Memvalidasi Rantai...' : 'Uji Integritas Rantai (Hash-Chain)'}
          </button>
        </div>
      </div>

      {/* Verification Result Banner */}
      {integrityStatus && (
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '0.75rem',
          padding: '1rem 1.25rem',
          borderRadius: 'var(--radius-md)',
          background: integrityStatus.verified ? 'var(--badge-emerald-bg)' : 'var(--badge-rose-bg)',
          border: `1px solid ${integrityStatus.verified ? 'var(--accent-emerald)' : 'var(--accent-rose)'}`,
          marginBottom: '1.5rem',
          animation: 'fadeIn 0.2s ease',
        }}>
          {integrityStatus.verified ? (
            <CheckCircle2 size={24} color="var(--accent-emerald)" style={{ flexShrink: 0 }} />
          ) : (
            <ShieldAlert size={24} color="var(--accent-rose)" style={{ flexShrink: 0 }} />
          )}
          <div>
            <h4 style={{ fontSize: '0.95rem', color: integrityStatus.verified ? 'var(--accent-emerald)' : 'var(--accent-rose)', marginBottom: '0.15rem' }}>
              {integrityStatus.verified ? 'Integritas Rantai Hash Terverifikasi Sempurna (100% Valid)' : 'Peringatan Integritas! Rantai Hash Terputus / Dimanipulasi'}
            </h4>
            <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
              {integrityStatus.message}
            </p>
          </div>
        </div>
      )}

      {/* Filter Toolbar */}
      <div style={{
        display: 'flex',
        flexWrap: 'wrap',
        alignItems: 'center',
        gap: '1rem',
        marginBottom: '1.5rem',
        background: 'var(--callout-bg)',
        padding: '0.75rem 1.25rem',
        borderRadius: 'var(--radius-md)',
        border: '1px solid var(--border-subtle)',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <Filter size={16} color="var(--text-muted)" />
          <span style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)' }}>Filter Aksi:</span>
          <select
            value={filterAction}
            onChange={(e) => setFilterAction(e.target.value)}
            className="input-control"
            style={{ width: 'auto', padding: '0.35rem 0.75rem', fontSize: '0.8rem' }}
          >
            <option value="ALL">Semua Aksi</option>
            <option value="AUTH_LOGIN">AUTH_LOGIN</option>
            <option value="AUTH_MFA_SUCCESS">AUTH_MFA_SUCCESS</option>
            <option value="VAULT_SETUP">VAULT_SETUP</option>
            <option value="FILE_INIT">FILE_INIT</option>
            <option value="FILE_CHUNK_UPLOAD">FILE_CHUNK_UPLOAD</option>
            <option value="FILE_UPLOAD_COMPLETE">FILE_UPLOAD_COMPLETE</option>
            <option value="FILE_DOWNLOAD">FILE_DOWNLOAD</option>
            <option value="FILE_DELETE">FILE_DELETE</option>
            <option value="VAULT_REWRAP_MK">VAULT_REWRAP_MK</option>
          </select>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <span style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)' }}>Status:</span>
          <select
            value={filterStatus}
            onChange={(e) => setFilterStatus(e.target.value)}
            className="input-control"
            style={{ width: 'auto', padding: '0.35rem 0.75rem', fontSize: '0.8rem' }}
          >
            <option value="ALL">Semua Status</option>
            <option value="SUCCESS">SUCCESS</option>
            <option value="FAILED">FAILED</option>
          </select>
        </div>
      </div>

      {/* Audit Log Table */}
      <div className="glass-card" style={{ overflow: 'hidden' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.825rem' }}>
          <thead>
            <tr style={{
              background: 'var(--table-header-bg)',
              borderBottom: '1px solid var(--border-subtle)',
              color: 'var(--text-secondary)',
              fontSize: '0.75rem',
              textTransform: 'uppercase',
              letterSpacing: '0.05em',
            }}>
              <th style={{ padding: '0.9rem 1rem', width: '60px' }}>Seq #</th>
              <th style={{ padding: '0.9rem 1rem' }}>Waktu (NTP)</th>
              <th style={{ padding: '0.9rem 1rem' }}>Tipe Aksi</th>
              <th style={{ padding: '0.9rem 1rem' }}>Pengguna / IP</th>
              <th style={{ padding: '0.9rem 1rem' }}>Status</th>
              <th style={{ padding: '0.9rem 1rem' }}>Rantai Kriptografi (Previous &rarr; Current Hash)</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr>
                <td colSpan={6} style={{ padding: '3rem', textAlign: 'center', color: 'var(--text-muted)' }}>
                  Memuat catatan audit berantai...
                </td>
              </tr>
            ) : filteredLogs.length === 0 ? (
              <tr>
                <td colSpan={6} style={{ padding: '3rem', textAlign: 'center', color: 'var(--text-muted)' }}>
                  Belum ada log audit yang sesuai dengan filter.
                </td>
              </tr>
            ) : (
              filteredLogs.map((log) => (
                <tr
                  key={log.id}
                  style={{
                    borderBottom: '1px solid var(--border-subtle)',
                    transition: 'background 0.15s ease',
                  }}
                  onMouseEnter={(e) => (e.currentTarget.style.background = 'var(--table-row-hover)')}
                  onMouseLeave={(e) => (e.currentTarget.style.background = 'transparent')}
                >
                  {/* Sequence */}
                  <td style={{ padding: '0.85rem 1rem' }}>
                    <span className="mono badge badge-cyan" style={{ fontSize: '0.7rem' }}>
                      #{log.sequence_number}
                    </span>
                  </td>

                  {/* Timestamp */}
                  <td style={{ padding: '0.85rem 1rem', color: 'var(--text-secondary)' }}>
                    {new Date(log.timestamp).toLocaleString('id-ID')}
                  </td>

                  {/* Action */}
                  <td style={{ padding: '0.85rem 1rem' }}>
                    <span className="mono" style={{ fontWeight: 600, color: 'var(--accent-cyan)' }}>
                      {log.action_type}
                    </span>
                  </td>

                  {/* User & IP */}
                  <td style={{ padding: '0.85rem 1rem' }}>
                    <div style={{ color: 'var(--text-primary)', fontWeight: 500 }}>{log.user_id}</div>
                    <div className="mono" style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                      {log.ip_address}
                    </div>
                  </td>

                  {/* Status */}
                  <td style={{ padding: '0.85rem 1rem' }}>
                    <span className={`badge ${log.status === 'SUCCESS' ? 'badge-emerald' : 'badge-rose'}`} style={{ fontSize: '0.65rem' }}>
                      {log.status}
                    </span>
                  </td>

                  {/* Hash Chain */}
                  <td style={{ padding: '0.85rem 1rem' }}>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.2rem' }}>
                      <div className="mono" style={{ fontSize: '0.68rem', color: 'var(--text-muted)' }}>
                        <span style={{ color: 'var(--text-secondary)' }}>Prev:</span> {log.previous_hash.substring(0, 16)}...
                      </div>
                      <div className="mono" style={{ fontSize: '0.68rem', color: 'var(--accent-emerald)' }}>
                        <span style={{ color: 'var(--text-secondary)' }}>Curr:</span> {log.current_hash.substring(0, 16)}...
                      </div>
                    </div>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
