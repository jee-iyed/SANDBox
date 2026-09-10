import type { Health, Scan, ScanDetail, SecureAccess, SecureContent, WorkerMetrics } from './types';

const RAW_BASE = (import.meta.env.VITE_API_BASE_URL as string | undefined)?.trim();
// Port 8000 belongs to IOC-Hunter; SANDBox runs on 8001 by default.
export const API_BASE_URL = (RAW_BASE || 'http://localhost:8001').replace(/\/+$/, '');

export class ApiError extends Error {
  readonly status: number;
  readonly detail: unknown;

  constructor(message: string, status: number, detail: unknown) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.detail = detail;
  }
}

function extractDetail(detail: unknown): string | null {
  if (typeof detail === 'string' && detail.trim()) {
    return detail;
  }
  if (detail && typeof detail === 'object' && 'detail' in detail) {
    return extractDetail((detail as { detail: unknown }).detail);
  }
  if (Array.isArray(detail)) {
    const messages = detail
      .map((item) => (item && typeof item === 'object' && 'msg' in item ? String((item as { msg: unknown }).msg) : null))
      .filter((msg): msg is string => Boolean(msg));
    if (messages.length > 0) {
      return messages.join('; ');
    }
  }
  return null;
}

export function friendlyError(err: unknown): string {
  if (err instanceof ApiError) {
    if (err.status === 0) {
      return 'Unable to connect to SANDBox. Please verify that the backend is running on port 8001.';
    }
    if (err.status === 404) {
      return 'Scan not found on the server. It may have been removed.';
    }
    if (err.status === 413) {
      return err.message || 'The file is too large for the configured upload limit.';
    }
    if (err.message) {
      return err.message;
    }
    return `Request failed with an unexpected server error (HTTP ${err.status}).`;
  }
  return 'An unexpected error occurred. Please check your connection and try again.';
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${API_BASE_URL}${path}`, init);
  } catch {
    throw new ApiError('Unable to connect to SANDBox', 0, null);
  }

  if (!response.ok) {
    let detail: unknown = null;
    try {
      detail = await response.json();
    } catch {
      // non-JSON error body
    }
    const message =
      extractDetail(detail) ?? `Request failed with an unexpected server error (HTTP ${response.status}).`;
    throw new ApiError(message, response.status, detail);
  }

  if (response.status === 204) {
    return undefined as T;
  }
  return (await response.json()) as T;
}

export const api = {
  health: () => request<Health>('/api/health'),
  workerMetrics: () => request<WorkerMetrics>('/api/system/workers'),

  createScan: (file: File) => {
    const form = new FormData();
    form.append('file', file);
    return request<Scan>('/api/scans', { method: 'POST', body: form });
  },

  getScan: (scanId: string) => request<ScanDetail>(`/api/scans/${scanId}`),

  listScans: (limit = 50, offset = 0) =>
    request<Scan[]>(`/api/scans?limit=${limit}&offset=${offset}`),

  createSecureAccess: (file: File, sourceToken?: string) => {
    const form = new FormData();
    form.append('file', file);
    const headers: Record<string, string> = {};
    if (sourceToken) {
      headers['x-source-token'] = sourceToken;
    }
    return request<SecureAccess>('/api/secure-access', {
      method: 'POST',
      body: form,
      headers,
    });
  },

  getSecureAccess: (accessId: string) => request<SecureAccess>(`/api/secure-access/${accessId}`),

  getSecureContent: (accessId: string) =>
    request<SecureContent>(`/api/secure-access/${accessId}/content`),
};
