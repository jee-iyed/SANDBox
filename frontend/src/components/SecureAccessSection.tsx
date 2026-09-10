import type { SecureAccess } from '../api/types';
import { formatDateTime } from '../utils/format';
import { ActionBadge, SecureAccessStatusBadge, VerdictBadge } from './Badges';
import { Spinner } from './Spinner';

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="file-info-row">
      <dt>{label}</dt>
      <dd title={value}>{value}</dd>
    </div>
  );
}

export function SecureAccessSection({
  access,
  loading = false,
  error = null,
}: {
  access: SecureAccess | null;
  loading?: boolean;
  error?: string | null;
}) {
  if (loading) {
    return (
      <section className="panel">
        <div className="panel-header">
          <h2 className="panel-title">Secure Access</h2>
        </div>
        <div className="panel-body">
          <Spinner label="Loading secure access request…" />
        </div>
      </section>
    );
  }

  if (!access) {
    return (
      <section className="panel">
        <div className="panel-header">
          <h2 className="panel-title">Secure Access</h2>
        </div>
        <div className="panel-body">
          <p className="page-note">
            {error ?? 'No secure access request is linked to this scan.'}
          </p>
        </div>
      </section>
    );
  }

  const authorized = access.status === 'authorized';
  const preview = authorized && access.preview_available ? 'Available' : 'Not available';

  return (
    <section className="panel" aria-label="Secure access">
      <div className="panel-header">
        <h2 className="panel-title">Secure Access</h2>
        <SecureAccessStatusBadge status={access.status} />
      </div>
      <div className="panel-body">
        <dl className="file-info-grid">
          <Row label="Access ID" value={access.id} />
          <Row label="Scan ID" value={access.scan_id} />
          <Row label="Source" value={access.source_identifier ?? access.source_type} />
          <Row label="Filename" value={access.original_filename} />
          <Row label="Security decision" value={access.status.toUpperCase()} />
          <Row label="Verdict" value={access.verdict?.toUpperCase() ?? '-'} />
          <Row label="Risk" value={access.risk_score !== null && access.risk_score !== undefined ? String(access.risk_score) : '-'} />
          <Row label="Policy" value={access.policy_action?.toUpperCase() ?? '-'} />
          <Row label="Preview" value={preview} />
          <Row label="Expiration" value={formatDateTime(access.expires_at)} />
        </dl>

        {authorized ? (
          <p className="page-note">
            The analysis completed and authorized this file. The secure content endpoint
            answers with a <strong>controlled placeholder</strong> until sandbox-side
            preview/rendering is implemented - the original file is never downloaded
            automatically.
          </p>
        ) : (
          <p className="page-note">
            Access is denied: the original file is not exposed to the client before the
            security decision, and unknown/error/timeout situations always deny access.
          </p>
        )}

        <div className="state-body">
          <VerdictBadge verdict={access.verdict ?? 'not_analyzed'} />
          <ActionBadge action={access.policy_action} />
        </div>
      </div>
    </section>
  );
}