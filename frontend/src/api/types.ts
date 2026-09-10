// API contract types - mirror the backend OpenAPI schemas (see backend/app/api/schemas.py).
// These are the only source of truth for what the UI may rely on.

export type ScanStatus = 'queued' | 'processing' | 'completed' | 'failed';

export type Verdict = 'not_analyzed' | 'safe' | 'suspicious' | 'malicious' | 'sanitized';

export type Action = 'allow' | 'quarantine' | 'sanitize' | 'reject';

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export interface FileInfo {
  id: string;
  filename: string;
  sha256: string;
  size_bytes: number;
  mime_type: string | null;
  detected_type: string | null;
  quarantined: boolean;
}

export interface Scan {
  id: string;
  status: ScanStatus;
  verdict: Verdict;
  action: Action | null;
  risk_score: number | null;
  created_at: string;
  updated_at: string;
  completed_at: string | null;
  file: FileInfo | null;
}

export interface Finding {
  id: string;
  type: string;
  value: string | null;
  source: string;
  severity: Severity;
  confidence: number;
  evidence: Record<string, unknown> | null;
  location: Record<string, unknown> | null;
  tags: string[];
  analyzer_version: string;
  timestamp: string;
}

export interface AnalysisResult {
  id: string;
  analyzer: string;
  analyzer_version: string;
  status: string;
  duration_ms: number | null;
  payload: Record<string, unknown> | null;
  error: string | null;
  created_at: string;
}

export interface ScanDetail extends Scan {
  findings: Finding[];
  analysis_results: AnalysisResult[];
}

// Secure File Access (gateway) - mirrors backend schemas.py
export type SecureAccessStatus =
  | 'requested'
  | 'scanning'
  | 'authorized'
  | 'blocked'
  | 'quarantined'
  | 'failed'
  | 'expired';

export interface SecureAccess {
  id: string;
  scan_id: string;
  source_type: string;
  source_identifier: string | null;
  original_filename: string;
  status: SecureAccessStatus;
  policy_action: Action | null;
  verdict: Verdict | null;
  risk_score: number | null;
  preview_available: boolean;
  expires_at: string;
  created_at: string;
  updated_at: string;
}

export interface SecureContent {
  authorized: boolean;
  content_kind: string;
  message: string;
  deny_reason: string | null;
  filename: string | null;
  mime_type: string | null;
  size_bytes: number | null;
}

export interface Health {
  status: 'ok' | 'degraded';
  database: boolean;
  redis: boolean;
}

export interface WorkerMetrics {
  configured_workers: number;
  active_workers: number;
  idle_workers: number;
  processing_workers: number;
  completed_jobs: number;
  failed_jobs: number;
  queue_depth: number | null;
  pending_jobs: number | null;
  throughput_files_per_minute: number;
  target_files_per_minute: number;
  target_achieved: boolean;
  average_latency_ms: number | null;
  p95_latency_ms: number | null;
  window_minutes: number;
}
