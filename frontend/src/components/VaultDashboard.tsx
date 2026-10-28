import React, { useState, useEffect } from 'react';
import {
  FileText,
  Upload,
  Download,
  Trash2,
  Lock,
  Unlock,
  Key,
  Shield,
  Search,
  HardDrive,
  RefreshCw,
  FileCheck,
  AlertTriangle,
  Info,
  FileCode,
  FileSpreadsheet,
  FileArchive,
  Image,
  ArrowUpDown,
  ShieldCheck,
  CheckCircle2,
} from 'lucide-react';
import { EncryptedFile, User } from '../types';
import { request } from '../utils/api';
import {
  getLoadedMasterKey,
  unwrapDek,
  decryptText,
  decryptChunk,
  computeSha256,
} from '../utils/crypto';

interface VaultDashboardProps {
  user: User;
  isVaultUnlocked: boolean;
  onOpenUploadModal: () => void;
  onOpenUnlockModal: () => void;
  onSelectFileDetails: (file: EncryptedFile) => void;
}

export const VaultDashboard: React.FC<VaultDashboardProps> = ({
  user,
  isVaultUnlocked,
  onOpenUploadModal,
  onOpenUnlockModal,
  onSelectFileDetails,
}) => {
  const [files, setFiles] = useState<EncryptedFile[]>([]);
  const [decryptedFiles, setDecryptedFiles] = useState<EncryptedFile[]>([]);
  const [loading, setLoading] = useState(false);
  const [downloadingId, setDownloadingId] = useState<string | null>(null);
  const [downloadProgress, setDownloadProgress] = useState<number>(0);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedTag, setSelectedTag] = useState<string | null>(null);
  const [sortBy, setSortBy] = useState<'date' | 'name' | 'size'>('date');
  const [sortAsc, setSortAsc] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchFiles();
  }, [user]);

  useEffect(() => {
    if (isVaultUnlocked && files.length > 0) {
      decryptMetadataForFiles();
    } else {
      setDecryptedFiles(files);
    }
  }, [isVaultUnlocked, files]);

  const fetchFiles = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await request<{ files: EncryptedFile[] }>('/files');
      setFiles(res.files);
    } catch (err: any) {
      setError(err.message || 'Gagal memuat daftar berkas.');
    } finally {
      setLoading(false);
    }
  };

  /**
   * Decrypt filenames and tags in the browser using the un-wrapped DEK
   */
  const decryptMetadataForFiles = async () => {
    const masterKey = getLoadedMasterKey();
    if (!masterKey) return;

    const list: EncryptedFile[] = [];
    for (const f of files) {
      try {
        const dek = await unwrapDek(f.wrapped_dek, masterKey);
        
        let decName = f.encrypted_file_name;
        if (f.encrypted_file_name.includes(':')) {
          const [cipher, iv] = f.encrypted_file_name.split(':');
          decName = await decryptText(cipher, iv, dek);
        }

        let tags: string[] = [];
        if (f.encrypted_tags && f.encrypted_tags.includes(':')) {
          const [tagCipher, tagIv] = f.encrypted_tags.split(':');
          const rawTags = await decryptText(tagCipher, tagIv, dek);
          tags = rawTags.split(',').map((t) => t.trim()).filter(Boolean);
        }

        list.push({
          ...f,
          decryptedFileName: decName,
          tags,
        });
      } catch (err) {
        list.push({
          ...f,
          decryptedFileName: '[Gagal dekripsi nama berkas]',
          tags: [],
        });
      }
    }
    setDecryptedFiles(list);
  };

  /**
   * Helper to return icon and color badge for file extensions
   */
  const getFileIcon = (fileName: string) => {
    const ext = fileName.split('.').pop()?.toLowerCase();
    switch (ext) {
      case 'pdf':
        return <FileText size={18} color="var(--accent-rose)" />;
      case 'doc':
      case 'docx':
      case 'txt':
        return <FileText size={18} color="var(--accent-cyan)" />;
      case 'xls':
      case 'xlsx':
      case 'csv':
        return <FileSpreadsheet size={18} color="var(--accent-emerald)" />;
      case 'zip':
      case 'tar':
      case 'gz':
      case '7z':
        return <FileArchive size={18} color="var(--accent-indigo)" />;
      case 'png':
      case 'jpg':
      case 'jpeg':
      case 'svg':
        return <Image size={18} color="var(--accent-emerald)" />;
      case 'key':
      case 'pem':
      case 'crt':
        return <Key size={18} color="var(--accent-amber)" />;
      default:
        return <FileCode size={18} color="var(--accent-cyan)" />;
    }
  };

  /**
   * Download all chunks, decrypt each with AAD, verify integrity, reassemble and trigger browser download
   */
  const handleDownload = async (file: EncryptedFile) => {
    const masterKey = getLoadedMasterKey();
    if (!masterKey) {
      onOpenUnlockModal();
      return;
    }

    setDownloadingId(file.id);
    setDownloadProgress(0);
    setError(null);

    try {
      const dek = await unwrapDek(file.wrapped_dek, masterKey);
      const totalChunks = file.total_chunks;
      const chunksData: Uint8Array[] = [];

      for (let i = 0; i < totalChunks; i++) {
        // Fetch chunk metadata + ciphertext
        const meta = await request<{ ivBase64: string; aadString: string }>(`/files/${file.id}/chunk/${i}/meta`);
        const ciphertext = await request<Uint8Array>(`/files/${file.id}/chunk/${i}/data`);

        // Decrypt chunk with AAD verification
        const decryptedChunk = await decryptChunk(ciphertext, meta.ivBase64, dek, file.id, i);
        chunksData.push(decryptedChunk);

        setDownloadProgress(Math.round(((i + 1) / totalChunks) * 100));
      }

      // Combine chunks
      const totalLen = chunksData.reduce((acc, c) => acc + c.byteLength, 0);
      const fullBuffer = new Uint8Array(totalLen);
      let offset = 0;
      for (const c of chunksData) {
        fullBuffer.set(c, offset);
        offset += c.byteLength;
      }

      // Verify SHA-256 integrity hash
      const computedHash = await computeSha256(fullBuffer);
      if (computedHash !== file.plaintext_sha256) {
        throw new Error('Peringatan Keamanan Kritis! Hash SHA-256 berkas tidak cocok. Berkas kemungkinan rusak atau terkompromi.');
      }

      // Trigger download
      const fileName = file.decryptedFileName || 'downloaded-file';
      const blob = new Blob([fullBuffer]);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = fileName;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err: any) {
      setError(err.message || 'Gagal mengunduh atau mendekripsi berkas.');
    } finally {
      setDownloadingId(null);
      setDownloadProgress(0);
    }
  };

  const handleDelete = async (fileId: string) => {
    if (!window.confirm('Hapus berkas ini secara permanen dari penyimpanan fisik dan basis data?')) {
      return;
    }

    try {
      await request(`/files/${fileId}`, { method: 'DELETE' });
      fetchFiles();
    } catch (err: any) {
      setError(err.message || 'Gagal menghapus berkas.');
    }
  };

  const totalBytes = files.reduce((acc, f) => acc + f.file_size_bytes, 0);
  const quotaBytes = user.storageQuotaBytes || 5 * 1024 * 1024 * 1024;
  const quotaPercent = Math.min(100, Math.round((totalBytes / quotaBytes) * 100));

  // Extract all unique tags
  const allTags = Array.from(
    new Set(decryptedFiles.flatMap((f) => f.tags || []))
  );

  const filteredFiles = decryptedFiles.filter((f) => {
    const nameMatch = (f.decryptedFileName || f.encrypted_file_name)
      .toLowerCase()
      .includes(searchQuery.toLowerCase());
    const tagMatch = selectedTag ? f.tags?.includes(selectedTag) : true;
    return nameMatch && tagMatch;
  });

  filteredFiles.sort((a, b) => {
    if (sortBy === 'date') {
      const diff = new Date(b.created_at).getTime() - new Date(a.created_at).getTime();
      return sortAsc ? -diff : diff;
    }
    if (sortBy === 'name') {
      const nameA = (a.decryptedFileName || a.encrypted_file_name).toLowerCase();
      const nameB = (b.decryptedFileName || b.encrypted_file_name).toLowerCase();
      return sortAsc ? nameA.localeCompare(nameB) : nameB.localeCompare(nameA);
    }
    if (sortBy === 'size') {
      return sortAsc ? a.file_size_bytes - b.file_size_bytes : b.file_size_bytes - a.file_size_bytes;
    }
    return 0;
  });

  return (
    <div className="container" style={{ padding: '2rem 1.5rem' }}>
      {/* Top Banner & Security Summary */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '1.25rem', marginBottom: '2rem' }}>
        {/* Card 1: Total Files */}
        <div className="glass-card" style={{ padding: '1.5rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.75rem' }}>
            <span style={{ fontSize: '0.775rem', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Total Berkas Terenkripsi
            </span>
            <div style={{ width: '36px', height: '36px', borderRadius: '10px', background: 'var(--badge-cyan-bg)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <FileText size={18} color="var(--accent-cyan)" />
            </div>
          </div>
          <div style={{ fontSize: '2.1rem', fontWeight: 800, color: 'var(--text-primary)', letterSpacing: '-0.02em' }}>
            {files.length} <span style={{ fontSize: '0.9rem', color: 'var(--text-secondary)', fontWeight: 500 }}>berkas</span>
          </div>
          <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.35rem' }}>
            Enkripsi sisi-klien sebelum transmisi (Zero-Knowledge)
          </p>
        </div>

        {/* Card 2: Quota & Storage */}
        <div className="glass-card" style={{ padding: '1.5rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.75rem' }}>
            <span style={{ fontSize: '0.775rem', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Alokasi Brankas Lokal
            </span>
            <div style={{ width: '36px', height: '36px', borderRadius: '10px', background: 'var(--badge-emerald-bg)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <HardDrive size={18} color="var(--accent-emerald)" />
            </div>
          </div>
          <div style={{ fontSize: '1.5rem', fontWeight: 800, color: 'var(--text-primary)', marginBottom: '0.6rem' }}>
            {(totalBytes / (1024 * 1024)).toFixed(1)} MB{' '}
            <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)', fontWeight: 500 }}>
              / {(quotaBytes / (1024 * 1024 * 1024)).toFixed(1)} GB
            </span>
          </div>
          <div className="progress-container" style={{ height: '7px' }}>
            <div className="progress-bar" style={{ width: `${quotaPercent}%` }} />
          </div>
        </div>

        {/* Card 3: Security & Key State */}
        <div className="glass-card" style={{ padding: '1.5rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.75rem' }}>
            <span style={{ fontSize: '0.775rem', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Status Brankas di RAM
            </span>
            <div style={{ width: '36px', height: '36px', borderRadius: '10px', background: isVaultUnlocked ? 'var(--badge-emerald-bg)' : 'var(--badge-amber-bg)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <Shield size={18} color={isVaultUnlocked ? 'var(--accent-emerald)' : 'var(--accent-amber)'} />
            </div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.35rem' }}>
            {isVaultUnlocked ? (
              <span className="badge badge-emerald" style={{ fontSize: '0.85rem' }}>
                <Unlock size={14} /> Terbuka di RAM
              </span>
            ) : (
              <span className="badge badge-amber" style={{ fontSize: '0.85rem' }}>
                <Lock size={14} /> Terkunci
              </span>
            )}
          </div>
          <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            {isVaultUnlocked
              ? 'Master Key aktif di RAM non-extractable. Siap dekripsi.'
              : 'Passphrase diperlukan untuk menurunkan KEK via Argon2id WASM.'}
          </p>
        </div>
      </div>

      {/* Action Header & Search Bar */}
      <div style={{
        display: 'flex',
        flexWrap: 'wrap',
        alignItems: 'center',
        justifyContent: 'space-between',
        gap: '1rem',
        marginBottom: '1.5rem',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flex: 1, minWidth: '280px' }}>
          <div style={{ position: 'relative', width: '100%', maxWidth: '380px' }}>
            <Search size={16} color="var(--text-muted)" style={{ position: 'absolute', left: '1rem', top: '50%', transform: 'translateY(-50%)' }} />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="input-control"
              style={{ paddingLeft: '2.6rem', fontSize: '0.85rem' }}
              placeholder="Cari berkas berdasarkan nama..."
            />
          </div>

          {/* Sort Dropdown */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
            <button
              onClick={() => setSortAsc(!sortAsc)}
              className="btn btn-secondary btn-sm"
              title="Ganti Urutan (Ascending / Descending)"
            >
              <ArrowUpDown size={14} />
            </button>
            <select
              value={sortBy}
              onChange={(e) => setSortBy(e.target.value as any)}
              className="input-control"
              style={{ padding: '0.4rem 0.75rem', fontSize: '0.8rem', width: 'auto' }}
            >
              <option value="date">Urutkan: Tanggal</option>
              <option value="name">Urutkan: Nama</option>
              <option value="size">Urutkan: Ukuran</option>
            </select>
          </div>

          <button onClick={fetchFiles} className="btn btn-secondary btn-sm" title="Refresh Daftar Berkas">
            <RefreshCw size={14} />
          </button>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          {!isVaultUnlocked && (
            <button onClick={onOpenUnlockModal} className="btn btn-secondary">
              <Key size={16} />
              Buka Kunci Brankas
            </button>
          )}

          <button
            onClick={() => {
              if (!isVaultUnlocked) {
                onOpenUnlockModal();
              } else {
                onOpenUploadModal();
              }
            }}
            className="btn btn-primary"
          >
            <Upload size={16} />
            Unggah Berkas Baru
          </button>
        </div>
      </div>

      {/* Tag Filters */}
      {allTags.length > 0 && (
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap', marginBottom: '1.5rem' }}>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontWeight: 600 }}>Filter Tag:</span>
          <button
            onClick={() => setSelectedTag(null)}
            className={`badge ${selectedTag === null ? 'badge-cyan' : 'btn-secondary'}`}
            style={{ cursor: 'pointer' }}
          >
            Semua
          </button>
          {allTags.map((tag) => (
            <button
              key={tag}
              onClick={() => setSelectedTag(selectedTag === tag ? null : tag)}
              className={`badge ${selectedTag === tag ? 'badge-cyan' : 'btn-secondary'}`}
              style={{ cursor: 'pointer' }}
            >
              #{tag}
            </button>
          ))}
        </div>
      )}

      {error && (
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '0.5rem',
          padding: '0.85rem 1rem',
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

      {/* Files Table */}
      <div className="glass-card" style={{ overflow: 'hidden' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.875rem' }}>
          <thead>
            <tr style={{
              background: 'var(--table-header-bg)',
              borderBottom: '1px solid var(--border-subtle)',
              color: 'var(--text-secondary)',
              fontSize: '0.775rem',
              textTransform: 'uppercase',
              letterSpacing: '0.05em',
            }}>
              <th style={{ padding: '1rem 1.25rem' }}>Nama Berkas</th>
              <th style={{ padding: '1rem' }}>Ukuran</th>
              <th style={{ padding: '1rem' }}>Potongan (Chunks)</th>
              <th style={{ padding: '1rem' }}>Label / Tag</th>
              <th style={{ padding: '1rem' }}>Tanggal Unggah</th>
              <th style={{ padding: '1rem 1.25rem', textAlign: 'right' }}>Aksi</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr>
                <td colSpan={6} style={{ padding: '3rem', textAlign: 'center', color: 'var(--text-muted)' }}>
                  Memuat daftar berkas terenkripsi...
                </td>
              </tr>
            ) : filteredFiles.length === 0 ? (
              <tr>
                <td colSpan={6} style={{ padding: '4rem 1.5rem', textAlign: 'center' }}>
                  <div style={{
                    width: '64px',
                    height: '64px',
                    borderRadius: '50%',
                    background: 'var(--badge-cyan-bg)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    margin: '0 auto 1rem',
                  }}>
                    <FileCheck size={30} color="var(--accent-cyan)" />
                  </div>
                  <h4 style={{ fontSize: '1.15rem', marginBottom: '0.25rem', color: 'var(--text-primary)' }}>Brankas Masih Kosong</h4>
                  <p style={{ fontSize: '0.825rem', color: 'var(--text-muted)', marginBottom: '1.25rem' }}>
                    Belum ada berkas terenkripsi yang diunggah ke brankas pribadi Anda.
                  </p>
                  <button
                    onClick={() => {
                      if (!isVaultUnlocked) onOpenUnlockModal();
                      else onOpenUploadModal();
                    }}
                    className="btn btn-primary btn-sm"
                  >
                    <Upload size={14} />
                    Unggah Berkas Pertama
                  </button>
                </td>
              </tr>
            ) : (
              filteredFiles.map((file) => {
                const isDownloading = downloadingId === file.id;
                const displayName = isVaultUnlocked
                  ? file.decryptedFileName || file.encrypted_file_name
                  : '•••••••••••••••••••• (Terenkripsi)';

                return (
                  <tr
                    key={file.id}
                    style={{
                      borderBottom: '1px solid var(--border-subtle)',
                      transition: 'background-color 0.15s ease',
                    }}
                    onMouseEnter={(e) => (e.currentTarget.style.background = 'var(--table-row-hover)')}
                    onMouseLeave={(e) => (e.currentTarget.style.background = 'transparent')}
                  >
                    {/* Filename with dynamic file extension icon */}
                    <td style={{ padding: '1rem 1.25rem' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                        <div style={{
                          width: '36px',
                          height: '36px',
                          borderRadius: '8px',
                          background: 'var(--badge-cyan-bg)',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                          flexShrink: 0,
                        }}>
                          {getFileIcon(file.decryptedFileName || '')}
                        </div>
                        <div>
                          <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
                            {displayName}
                          </div>
                          <div className="mono" style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                            SHA-256: {file.plaintext_sha256.substring(0, 16)}...
                          </div>
                        </div>
                      </div>
                    </td>

                    {/* Size */}
                    <td style={{ padding: '1rem', color: 'var(--text-secondary)' }}>
                      {(file.file_size_bytes / (1024 * 1024)).toFixed(2)} MB
                    </td>

                    {/* Chunks */}
                    <td style={{ padding: '1rem' }}>
                      <span className="badge badge-cyan" style={{ fontSize: '0.7rem' }}>
                        {file.total_chunks} chunk ({file.total_chunks * 5} MB)
                      </span>
                    </td>

                    {/* Tags */}
                    <td style={{ padding: '1rem' }}>
                      {file.tags && file.tags.length > 0 ? (
                        <div style={{ display: 'flex', gap: '0.35rem', flexWrap: 'wrap' }}>
                          {file.tags.map((t, idx) => (
                            <span key={idx} className="badge badge-emerald" style={{ fontSize: '0.65rem' }}>
                              #{t}
                            </span>
                          ))}
                        </div>
                      ) : (
                        <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>-</span>
                      )}
                    </td>

                    {/* Date */}
                    <td style={{ padding: '1rem', color: 'var(--text-muted)', fontSize: '0.8rem' }}>
                      {new Date(file.created_at).toLocaleString('id-ID')}
                    </td>

                    {/* Actions */}
                    <td style={{ padding: '1rem 1.25rem', textAlign: 'right' }}>
                      <div style={{ display: 'inline-flex', alignItems: 'center', gap: '0.4rem' }}>
                        {/* Download & Decrypt */}
                        <button
                          onClick={() => handleDownload(file)}
                          disabled={isDownloading}
                          className="btn btn-sm btn-primary"
                          title="Unduh & Dekripsi Berkas (AES-256-GCM)"
                        >
                          {isDownloading ? (
                            <span>{downloadProgress}%</span>
                          ) : (
                            <>
                              <Download size={14} />
                              Unduh
                            </>
                          )}
                        </button>

                        {/* File Details */}
                        <button
                          onClick={() => onSelectFileDetails(file)}
                          className="btn btn-sm btn-secondary"
                          title="Lihat Spesifikasi Kriptografis Berkas"
                        >
                          <Info size={14} />
                        </button>

                        {/* Delete */}
                        <button
                          onClick={() => handleDelete(file.id)}
                          className="btn btn-sm btn-danger"
                          title="Hapus Berkas Aman"
                        >
                          <Trash2 size={14} />
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

      {/* Institutional Security Assurance Banner */}
      <div style={{
        marginTop: '2rem',
        padding: '1.25rem 1.5rem',
        borderRadius: 'var(--radius-lg)',
        background: 'var(--surface-card)',
        border: '1px solid var(--border-card)',
        display: 'flex',
        flexWrap: 'wrap',
        alignItems: 'center',
        justifyContent: 'space-between',
        gap: '1rem',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <ShieldCheck size={22} color="var(--accent-cyan)" />
          <div>
            <h5 style={{ fontSize: '0.875rem', color: 'var(--text-primary)', marginBottom: '0.1rem' }}>
              Jaminan Kepatuhan Keamanan Sistem Informasi
            </h5>
            <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              Sesuai dengan Kerangka Evaluasi ISO/IEC 15408-1:2022 (Common Criteria) &amp; ISO/IEC 18045:2026 di lingkungan BSSN.
            </p>
          </div>
        </div>
        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <span className="badge badge-cyan" style={{ fontSize: '0.65rem' }}>Envelope 3 Lapis</span>
          <span className="badge badge-emerald" style={{ fontSize: '0.65rem' }}>SHA-256 Hash Chain</span>
          <span className="badge badge-amber" style={{ fontSize: '0.65rem' }}>Zero-Knowledge</span>
        </div>
      </div>
    </div>
  );
};
