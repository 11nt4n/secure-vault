export interface User {
  id: string;
  username: string;
  email: string;
  role: 'admin' | 'user';
  mfaEnabled: boolean;
  storageQuotaBytes: number;
  storageUsedBytes: number;
}

export interface VaultState {
  isUnlocked: boolean;
  isDeriving: boolean;
  error: string | null;
  masterKey: CryptoKey | null;
  kek: CryptoKey | null;
}

export interface EncryptedFile {
  id: string;
  owner_id: string;
  encrypted_file_name: string;
  decryptedFileName?: string;
  file_size_bytes: number;
  total_chunks: number;
  wrapped_dek: string;
  plaintext_sha256: string;
  encrypted_tags?: string;
  tags?: string[];
  created_at: string;
  upload_status?: 'uploading' | 'completed';
  completed_at?: string;
}

export interface AuditLogEntry {
  id: string;
  sequence_number: number;
  timestamp: string;
  user_id: string;
  action_type: string;
  file_id?: string;
  ip_address: string;
  user_agent?: string;
  status: 'SUCCESS' | 'FAILED';
  details?: string | null;
  hash_version?: number;
  previous_hash: string;
  current_hash: string;
  is_valid_chain?: boolean;
}

export interface AdminStats {
  totalUsers: number;
  totalFiles: number;
  totalCiphertextBytes: number;
  auditChainLength: number;
  chainIntegrity: boolean;
}
