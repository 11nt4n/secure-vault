import React, { useState } from 'react';
import { Shield, Key, FileCode, CheckCircle2, X, Edit3, Lock } from 'lucide-react';
import { EncryptedFile } from '../types';
import { getLoadedMasterKey, unwrapDek, encryptText } from '../utils/crypto';
import { request } from '../utils/api';

interface FileDetailsModalProps {
  file: EncryptedFile | null;
  onClose: () => void;
  onUpdated: () => void;
}

export const FileDetailsModal: React.FC<FileDetailsModalProps> = ({
  file,
  onClose,
  onUpdated,
}) => {
  const [isEditing, setIsEditing] = useState(false);
  const [newFileName, setNewFileName] = useState(file?.decryptedFileName || '');
  const [newTags, setNewTags] = useState(file?.tags?.join(', ') || '');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!file) return null;

  const handleSaveMetadata = async () => {
    const masterKey = getLoadedMasterKey();
    if (!masterKey) {
      setError('Brankas terkunci! Buka brankas untuk mengubah metadata.');
      return;
    }

    setSaving(true);
    setError(null);

    try {
      // Unwrap DEK to re-encrypt new name and tags
      const dek = await unwrapDek(file.wrapped_dek, masterKey);
      const encName = await encryptText(newFileName, dek);
      const encTags = await encryptText(newTags, dek);

      await request(`/files/${file.id}/metadata`, {
        method: 'PATCH',
        body: JSON.stringify({
          encryptedFileName: `${encName.ciphertextB64}:${encName.ivB64}`,
          encryptedTags: `${encTags.ciphertextB64}:${encTags.ivB64}`,
        }),
      });

      setIsEditing(false);
      onUpdated();
    } catch (err: any) {
      setError(err.message || 'Gagal memperbarui metadata.');
    } finally {
      setSaving(false);
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
              <Shield size={20} color="var(--accent-cyan)" />
            </div>
            <div>
              <h3 style={{ fontSize: '1.2rem' }}>Spesifikasi Kriptografis Berkas</h3>
              <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                Arsitektur Envelope Encryption Sisi-Klien (ISO/IEC 15408)
              </p>
            </div>
          </div>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}>
            <X size={20} />
          </button>
        </div>

        {error && (
          <div style={{
            padding: '0.75rem 1rem',
            borderRadius: 'var(--radius-md)',
            background: 'var(--badge-rose-bg)',
            border: '1px solid var(--accent-rose)',
            color: 'var(--accent-rose)',
            fontSize: '0.8rem',
            marginBottom: '1rem',
          }}>
            {error}
          </div>
        )}

        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
          {/* Metadata Edit Form or Display */}
          {isEditing ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem', padding: '1rem', background: 'var(--callout-bg)', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-subtle)' }}>
              <div className="input-group">
                <label className="input-label">Nama Berkas Baru</label>
                <input
                  type="text"
                  value={newFileName}
                  onChange={(e) => setNewFileName(e.target.value)}
                  className="input-control"
                />
              </div>
              <div className="input-group">
                <label className="input-label">Tag Virtual Baru (Pisahkan koma)</label>
                <input
                  type="text"
                  value={newTags}
                  onChange={(e) => setNewTags(e.target.value)}
                  className="input-control"
                />
              </div>
              <div style={{ display: 'flex', gap: '0.5rem', justifyContent: 'flex-end' }}>
                <button onClick={() => setIsEditing(false)} className="btn btn-secondary btn-sm">Batal</button>
                <button onClick={handleSaveMetadata} disabled={saving} className="btn btn-primary btn-sm">
                  {saving ? 'Mengenkripsi & Menyimpan...' : 'Simpan Perubahan'}
                </button>
              </div>
            </div>
          ) : (
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
              <div>
                <h4 style={{ fontSize: '1.05rem', color: 'var(--text-primary)', marginBottom: '0.25rem' }}>
                  {file.decryptedFileName || 'Nama Berkas Terenkripsi'}
                </h4>
                <div style={{ display: 'flex', gap: '0.35rem', flexWrap: 'wrap' }}>
                  {file.tags && file.tags.map((t, i) => (
                    <span key={i} className="badge badge-emerald" style={{ fontSize: '0.65rem' }}>
                      #{t}
                    </span>
                  ))}
                </div>
              </div>
              <button onClick={() => setIsEditing(true)} className="btn btn-secondary btn-sm">
                <Edit3 size={13} /> Edit Nama & Tag
              </button>
            </div>
          )}

          {/* Technical Specs List */}
          <div style={{
            display: 'flex',
            flexDirection: 'column',
            gap: '0.85rem',
            padding: '1.25rem',
            borderRadius: 'var(--radius-md)',
            background: 'var(--callout-bg)',
            border: '1px solid var(--border-subtle)',
          }}>
            <div>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.2rem' }}>
                File ID (UUID v4)
              </span>
              <span className="mono" style={{ fontSize: '0.8rem', color: 'var(--accent-cyan)' }}>
                {file.id}
              </span>
            </div>

            <div>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.2rem' }}>
                Hash Integritas Asli (Plaintext SHA-256)
              </span>
              <span className="mono" style={{ fontSize: '0.75rem', color: 'var(--accent-emerald)', wordBreak: 'break-all' }}>
                {file.plaintext_sha256}
              </span>
            </div>

            <div>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.2rem' }}>
                Wrapped DEK (256-bit AES-KW dibungkus Master Key)
              </span>
              <div className="mono" style={{
                fontSize: '0.7rem',
                color: 'var(--text-secondary)',
                wordBreak: 'break-all',
                background: 'var(--box-code-bg)',
                padding: '0.5rem',
                borderRadius: '4px',
              }}>
                {file.wrapped_dek}
              </div>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', paddingTop: '0.5rem', borderTop: '1px solid var(--border-subtle)' }}>
              <div>
                <span style={{ fontSize: '0.725rem', color: 'var(--text-muted)' }}>Ukuran Berkas</span>
                <p style={{ fontSize: '0.85rem', fontWeight: 600 }}>
                  {(file.file_size_bytes / (1024 * 1024)).toFixed(2)} MB
                </p>
              </div>
              <div>
                <span style={{ fontSize: '0.725rem', color: 'var(--text-muted)' }}>Skema Chunking</span>
                <p style={{ fontSize: '0.85rem', fontWeight: 600 }}>
                  {file.total_chunks} chunk &times; 5 MB (AES-256-GCM)
                </p>
              </div>
            </div>

            <div>
              <span style={{ fontSize: '0.725rem', color: 'var(--text-muted)' }}>Formula Pengikatan AAD</span>
              <p className="mono" style={{ fontSize: '0.75rem', color: 'var(--accent-cyan)' }}>
                AAD = `${'{file_id}'}-${'{chunk_index}'}` (Anti-Swap Urutan)
              </p>
            </div>
          </div>

          <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '0.5rem' }}>
            <button onClick={onClose} className="btn btn-secondary">
              Tutup
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
