import React, { useState, useRef } from 'react';
import { UploadCloud, File, ShieldCheck, X, AlertTriangle, CheckCircle2, Lock } from 'lucide-react';
import {
  getLoadedMasterKey,
  generateFileDek,
  wrapDek,
  encryptText,
  encryptChunk,
  computeSha256,
} from '../utils/crypto';
import { request } from '../utils/api';

interface FileUploaderProps {
  isOpen: boolean;
  onClose: () => void;
  onUploadSuccess: () => void;
}

const CHUNK_SIZE = 5 * 1024 * 1024; // 5 MB per chunk
const MAX_FILE_SIZE = 500 * 1024 * 1024; // 500 MB limit

export const FileUploader: React.FC<FileUploaderProps> = ({
  isOpen,
  onClose,
  onUploadSuccess,
}) => {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [tagsInput, setTagsInput] = useState('Rahasia, BSSN, Sertifikasi');
  const [uploading, setUploading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [currentChunk, setCurrentChunk] = useState(0);
  const [totalChunks, setTotalChunks] = useState(0);
  const [statusMessage, setStatusMessage] = useState('');
  const [error, setError] = useState<string | null>(null);

  const fileInputRef = useRef<HTMLInputElement>(null);

  if (!isOpen) return null;

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      const file = e.target.files[0];
      if (file.size > MAX_FILE_SIZE) {
        setError(`Ukuran berkas (${(file.size / (1024 * 1024)).toFixed(1)} MB) melebihi batas MVP 500 MB.`);
        setSelectedFile(null);
        return;
      }
      setSelectedFile(file);
      setError(null);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      const file = e.dataTransfer.files[0];
      if (file.size > MAX_FILE_SIZE) {
        setError(`Ukuran berkas (${(file.size / (1024 * 1024)).toFixed(1)} MB) melebihi batas MVP 500 MB.`);
        setSelectedFile(null);
        return;
      }
      setSelectedFile(file);
      setError(null);
    }
  };

  const startUpload = async () => {
    const masterKey = getLoadedMasterKey();
    if (!masterKey) {
      setError('Brankas terkunci! Silakan buka brankas terlebih dahulu.');
      return;
    }
    if (!selectedFile) {
      setError('Pilih berkas yang akan dienkripsi.');
      return;
    }

    setUploading(true);
    setError(null);
    setProgress(0);

    try {
      setStatusMessage('1/5: Menghasilkan Data Encryption Key (DEK) 256-bit unik...');
      const dek = await generateFileDek();

      setStatusMessage('2/5: Membungkus DEK dengan Master Key (AES-KW)...');
      const wrappedDek = await wrapDek(dek, masterKey);

      setStatusMessage('3/5: Mengenkripsi nama berkas dan label virtual dengan DEK...');
      const encryptedNameObj = await encryptText(selectedFile.name, dek);
      const encryptedTagsObj = await encryptText(tagsInput, dek);

      setStatusMessage('4/5: Membaca berkas dan menghitung hash integritas SHA-256...');
      const fileBuffer = new Uint8Array(await selectedFile.arrayBuffer());
      const plaintextSha256 = await computeSha256(fileBuffer);

      const calculatedTotalChunks = Math.ceil(selectedFile.size / CHUNK_SIZE);
      setTotalChunks(calculatedTotalChunks);

      // Inisialisasi metadata file di backend
      const initRes = await request<{ fileId: string }>('/files/init', {
        method: 'POST',
        body: JSON.stringify({
          encryptedFileName: `${encryptedNameObj.ciphertextB64}:${encryptedNameObj.ivB64}`,
          encryptedTags: `${encryptedTagsObj.ciphertextB64}:${encryptedTagsObj.ivB64}`,
          fileSizeBytes: selectedFile.size,
          totalChunks: calculatedTotalChunks,
          wrappedDek: wrappedDek,
          plaintextSha256: plaintextSha256,
        }),
      });

      const fileId = initRes.fileId;

      // 5/5: Chunking & Client-Side AES-256-GCM + AAD Encryption
      for (let i = 0; i < calculatedTotalChunks; i++) {
        setCurrentChunk(i + 1);
        setStatusMessage(`5/5: Mengenkripsi & mengunggah chunk ${i + 1}/${calculatedTotalChunks} (AES-256-GCM + AAD)...`);

        const start = i * CHUNK_SIZE;
        const end = Math.min(start + CHUNK_SIZE, selectedFile.size);
        const chunkData = fileBuffer.slice(start, end);

        // Encrypt chunk with AAD = `${fileId}-${i}`
        const encryptedChunk = await encryptChunk(chunkData, dek, fileId, i);

        // Send ciphertext to backend via multipart or binary
        const formData = new FormData();
        formData.append('fileId', fileId);
        formData.append('chunkIndex', i.toString());
        formData.append('ivBase64', encryptedChunk.ivB64);
        formData.append('aadString', encryptedChunk.aad);
        formData.append('chunkBlob', new Blob([encryptedChunk.ciphertext]));

        await request(`/files/${fileId}/chunk/${i}`, {
          method: 'POST',
          body: formData,
        });

        const pct = Math.round(((i + 1) / calculatedTotalChunks) * 100);
        setProgress(pct);
      }

      setStatusMessage('Selesai! Mencatat transaksi ke audit trail...');
      await request(`/files/${fileId}/complete`, {
        method: 'POST',
      });

      setTimeout(() => {
        setUploading(false);
        onUploadSuccess();
        onClose();
      }, 500);
    } catch (err: any) {
      setError(err.message || 'Gagal mengenkripsi atau mengunggah berkas.');
      setUploading(false);
    }
  };

  return (
    <div className="modal-overlay">
      <div className="modal-content" style={{ padding: '2rem' }}>
        {/* Modal Header */}
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
              <UploadCloud size={20} color="var(--accent-cyan)" />
            </div>
            <div>
              <h3 style={{ fontSize: '1.2rem' }}>Unggah Berkas Terenkripsi</h3>
              <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                Chunking 5 MB &bull; AES-256-GCM + AAD &bull; Zero-Knowledge
              </p>
            </div>
          </div>
          {!uploading && (
            <button onClick={onClose} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}>
              <X size={20} />
            </button>
          )}
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

        {/* Dropzone */}
        {!uploading ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
            <div
              onDragOver={(e) => e.preventDefault()}
              onDrop={handleDrop}
              onClick={() => fileInputRef.current?.click()}
              style={{
                border: '2px dashed var(--border-card)',
                borderRadius: 'var(--radius-lg)',
                padding: '2.5rem 1.5rem',
                textAlign: 'center',
                cursor: 'pointer',
                background: 'rgba(56, 189, 248, 0.02)',
                transition: 'all 0.2s ease',
              }}
            >
              <input
                ref={fileInputRef}
                type="file"
                onChange={handleFileChange}
                style={{ display: 'none' }}
              />
              <div style={{
                width: '52px',
                height: '52px',
                borderRadius: '50%',
                background: 'rgba(56, 189, 248, 0.1)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                margin: '0 auto 1rem',
              }}>
                <Lock size={24} color="var(--accent-cyan)" />
              </div>
              <p style={{ fontWeight: 600, fontSize: '0.95rem', marginBottom: '0.35rem' }}>
                {selectedFile ? selectedFile.name : 'Tarik & letakkan berkas di sini atau klik untuk memilih'}
              </p>
              <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                {selectedFile
                  ? `${(selectedFile.size / (1024 * 1024)).toFixed(2)} MB — Siap dienkripsi`
                  : 'Batas ukuran berkas: 500 MB (MVP). Berkas dienkripsi di peramban sebelum dikirim.'}
              </p>
            </div>

            {/* Tags / Labels */}
            <div className="input-group">
              <label className="input-label">Label / Tag Virtual Terenkripsi (Pisahkan dengan koma)</label>
              <input
                type="text"
                value={tagsInput}
                onChange={(e) => setTagsInput(e.target.value)}
                className="input-control"
                placeholder="cth: Rahasia, Laporan Audit, Sandi"
              />
            </div>

            {/* Actions */}
            <div style={{ display: 'flex', gap: '0.75rem', marginTop: '0.5rem' }}>
              <button type="button" onClick={onClose} className="btn btn-secondary" style={{ flex: 1 }}>
                Batal
              </button>
              <button
                type="button"
                onClick={startUpload}
                disabled={!selectedFile}
                className="btn btn-primary"
                style={{ flex: 2 }}
              >
                <ShieldCheck size={16} />
                Enkripsi Sisi-Klien & Unggah
              </button>
            </div>
          </div>
        ) : (
          /* Progress View */
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem', padding: '1rem 0' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--accent-cyan)' }}>
                {statusMessage}
              </span>
              <span className="mono" style={{ fontSize: '0.9rem', fontWeight: 700 }}>
                {progress}%
              </span>
            </div>

            <div className="progress-container">
              <div className="progress-bar" style={{ width: `${progress}%` }} />
            </div>

            <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textAlign: 'center' }}>
              Setiap potongan 5 MB dienkripsi secara independen dengan kunci DEK acak dan tag AAD anti-penukaran.
            </p>
          </div>
        )}
      </div>
    </div>
  );
};
