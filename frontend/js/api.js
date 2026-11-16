// Secure Vault Centralized API Client. The PHP API remains on port 5000.
const BASE_URL = window.SECURE_VAULT_API_URL || 'http://127.0.0.1:5000/api';

export function getAuthToken() { return sessionStorage.getItem('sv_jwt'); }
export function setAuthToken(token) { sessionStorage.setItem('sv_jwt', token); }
export function clearAuthToken() { sessionStorage.removeItem('sv_jwt'); }

function isCredentialOrMfaEndpoint(endpoint) {
  const path = String(endpoint).split('?')[0].replace(/\/$/, '');
  return [
    '/auth/login',
    '/auth/activate',
    '/auth/onboarding/verify-email',
    '/auth/onboarding/set-password',
    '/auth/mfa/setup',
    '/auth/mfa/verify'
  ].includes(path);
}

async function readJsonSafely(response) {
  const contentType = response.headers.get('content-type') || '';
  if (!contentType.includes('application/json')) return null;
  try { return await response.json(); } catch { return null; }
}

export async function request(endpoint, options = {}) {
  const token = getAuthToken();
  const headers = new Headers(options.headers || {});
  if (token) headers.set('Authorization', `Bearer ${token}`);
  if (!(options.body instanceof FormData) && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }

  let response;
  try {
    response = await fetch(`${BASE_URL}${endpoint}`, { ...options, headers });
  } catch (error) {
    const detail = error?.message ? ` (${error.message})` : '';
    throw new Error(`Tidak dapat terhubung ke server Secure Vault. Pastikan backend PHP berjalan pada port 5000${detail}.`);
  }

  const renewedToken = response.headers.get('X-Secure-Vault-Token');
  if (renewedToken) setAuthToken(renewedToken);

  const contentType = response.headers.get('content-type') || '';
  if (!response.ok) {
    const payload = await readJsonSafely(response);
    const serverMessage = typeof payload?.error === 'string' && payload.error.trim()
      ? payload.error.trim()
      : `Permintaan gagal (${response.status} ${response.statusText || 'Server Error'}).`;

    if (response.status === 401) {
      // Login/MFA 401 is an authentication failure, not an expired account session.
      // Preserve the backend's actual message (e.g. wrong credentials or expired MFA challenge).
      if (isCredentialOrMfaEndpoint(endpoint)) {
        throw new Error(serverMessage);
      }

      // Other 401 responses belong to protected APIs and indicate that the account
      // session is absent, expired, revoked, or no longer authorized.
      clearAuthToken();
      window.dispatchEvent(new CustomEvent('auth:unauthorized', { detail: { message: serverMessage } }));
      throw new Error(serverMessage || 'Sesi login telah berakhir. Silakan masuk kembali.');
    }

    throw new Error(serverMessage);
  }

  if (contentType.includes('application/octet-stream')) {
    return new Uint8Array(await response.arrayBuffer());
  }
  if (response.status === 204) return null;
  if (contentType.includes('application/json')) return response.json();
  return null;
}
