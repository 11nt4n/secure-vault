// frontend/src/utils/api.ts
// Secure Vault Centralized API Client

const BASE_URL = '/api';

export function getAuthToken(): string | null {
  return sessionStorage.getItem('sv_jwt');
}

export function setAuthToken(token: string): void {
  sessionStorage.setItem('sv_jwt', token);
}

export function clearAuthToken(): void {
  sessionStorage.removeItem('sv_jwt');
}

export async function request<T>(
  endpoint: string,
  options: RequestInit = {}
): Promise<T> {
  const token = getAuthToken();
  const headers = new Headers(options.headers || {});

  if (token) {
    headers.set('Authorization', `Bearer ${token}`);
  }

  if (!(options.body instanceof FormData) && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }

  const res = await fetch(`${BASE_URL}${endpoint}`, {
    ...options,
    headers,
  });

  if (res.status === 401) {
    clearAuthToken();
    window.dispatchEvent(new Event('auth:unauthorized'));
    throw new Error('Sesi telah kedaluwarsa atau tidak diizinkan. Silakan login kembali.');
  }

  if (!res.ok) {
    let errMsg = `Request error: ${res.status} ${res.statusText}`;
    try {
      const data = await res.json();
      if (data.error) errMsg = data.error;
    } catch {
      // ignore JSON parse error
    }
    throw new Error(errMsg);
  }

  // Handle binary / octet-stream responses for downloading chunks
  const contentType = res.headers.get('content-type');
  if (contentType && contentType.includes('application/octet-stream')) {
    const arrayBuffer = await res.arrayBuffer();
    return new Uint8Array(arrayBuffer) as unknown as T;
  }

  return res.json() as Promise<T>;
}
