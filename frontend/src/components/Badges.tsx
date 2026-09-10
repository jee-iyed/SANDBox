import type { ReactNode } from 'react';

import type { Action, ScanStatus, SecureAccessStatus, Severity, Verdict } from '../api/types';

type Tone = 'green' | 'amber' | 'red' | 'blue' | 'gray' | 'navy' | 'orange';

interface BadgeProps {
  children: ReactNode;
  tone: Tone;
  label: string;
}

export function Badge({ children, tone, label }: BadgeProps) {
  return (
    <span className={`badge badge-${tone}`} role="status" aria-label={label}>
      {children}
    </span>
  );
}

const SCAN_TONES: Record<ScanStatus, 'blue' | 'red' | 'gray'> = {
  queued: 'blue',
  processing: 'blue',
  completed: 'gray',
  failed: 'red',
};

export function ScanStatusBadge({ status }: { status: ScanStatus }) {
  return (
    <Badge tone={SCAN_TONES[status] ?? 'gray'} label={`Scan status: ${status}`}>
      {status.toUpperCase()}
    </Badge>
  );
}

const VERDICT_TONES: Record<Verdict, 'green' | 'amber' | 'red' | 'navy' | 'gray'> = {
  safe: 'green',
  suspicious: 'amber',
  malicious: 'red',
  sanitized: 'navy',
  not_analyzed: 'gray',
};

export function VerdictBadge({ verdict }: { verdict: Verdict }) {
  return (
    <Badge tone={VERDICT_TONES[verdict] ?? 'gray'} label={`Verdict: ${verdict}`}>
      {verdict.toUpperCase()}
    </Badge>
  );
}

const ACTION_TONES: Record<Action, 'green' | 'red' | 'navy'> = {
  allow: 'green',
  quarantine: 'red',
  reject: 'red',
  sanitize: 'navy',
};

export function ActionBadge({ action }: { action: Action | null }) {
  if (!action) {
    return <span className="badge badge-gray">-</span>;
  }
  return (
    <Badge tone={ACTION_TONES[action] ?? 'gray'} label={`Action: ${action}`}>
      {action.toUpperCase()}
    </Badge>
  );
}

const SEVERITY_TONES: Record<Severity, Tone> = {
  info: 'gray',
  low: 'blue',
  medium: 'amber',
  high: 'orange',
  critical: 'red',
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <Badge tone={SEVERITY_TONES[severity] ?? 'gray'} label={`Severity: ${severity}`}>
      {severity.toUpperCase()}
    </Badge>
  );
}

const SECURE_ACCESS_TONES: Record<SecureAccessStatus, 'green' | 'amber' | 'red' | 'blue' | 'gray'> = {
  requested: 'gray',
  scanning: 'blue',
  authorized: 'green',
  blocked: 'amber',
  quarantined: 'red',
  failed: 'red',
  expired: 'gray',
};

export function SecureAccessStatusBadge({ status }: { status: SecureAccessStatus }) {
  return (
    <Badge tone={SECURE_ACCESS_TONES[status] ?? 'gray'} label={`Secure access status: ${status}`}>
      {status.toUpperCase()}
    </Badge>
  );
}