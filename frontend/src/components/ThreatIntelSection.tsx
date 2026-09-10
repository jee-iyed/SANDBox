import type { AnalysisResult, Finding } from '../api/types';

const PROVIDER_LABELS: Record<string, string> = {
  virustotal: 'VirusTotal',
  abuseipdb: 'AbuseIPDB',
};

function toneFor(statusLabel: string, status: string): 'ok' | 'warn' | 'err' {
  if (status === 'error' || status === 'unavailable') return 'err';
  if (status === 'rate_limited') return 'warn';
  const label = statusLabel.toLowerCase();
  if (label === 'malicious') return 'err';
  if (label === 'suspicious' || label === 'watch') return 'warn';
  if (label === 'clean' || label === 'none') return 'ok';
  return 'warn';
}

function StatusBadge({ statusLabel, status }: { statusLabel: string; status: string }) {
  const tone = toneFor(statusLabel, status);
  const text = status ? status.toUpperCase() : statusLabel;
  return <span className={`analyzer-badge analyzer-${tone}`}>{text}</span>;
}

function Reputation({ evidence }: { evidence: Record<string, unknown> | null }) {
  const reputation = typeof evidence?.reputation === 'number' ? evidence.reputation : null;
  if (reputation === null) return <span className="table-muted">-</span>;
  return <span className="table-value">{reputation}%</span>;
}

export function ThreatIntelSection({
  results,
  findings,
}: {
  results: AnalysisResult[];
  findings: Finding[];
}) {
  const result = results.find((item) => item.analyzer === 'threat_intel');
  if (!result) {
    return null;
  }

  const payload = (result?.payload ?? {}) as Record<string, unknown>;
  const providersPayload =
    payload.providers && typeof payload.providers === 'object' ? (payload.providers as Record<string, unknown>) : {};
  const providerNames = Object.keys(providersPayload).sort();
  const tiFindings = findings.filter((item) => item.source === 'threat_intel');
  const lookups = typeof payload.lookups === 'number' ? payload.lookups : tiFindings.length;
  const status = typeof payload.status === 'string' ? payload.status : result.status;

  return (
    <section className="panel">
      <div className="panel-header">
        <h2 className="panel-title">Threat Intelligence</h2>
        <span className="count-badge">{providerNames.length > 0 ? lookups : '-'}</span>
      </div>
      <div className="panel-body">
        {providerNames.length === 0 && (
          <p className="page-note">Threat intelligence unavailable for this scan.</p>
        )}
        {providerNames.length > 0 && (
          <>
            <div className="qr-result">
              <div>
                <span className="result-label">Providers</span>
                <strong>{providerNames.map((name) => PROVIDER_LABELS[name] ?? name).join(' · ')}</strong>
              </div>
              <div>
                <span className="result-label">Lookups</span>
                <strong>{lookups}</strong>
              </div>
              <div>
                <span className="result-label">Duration</span>
                <strong>{result.duration_ms === null || result.duration_ms === undefined ? '-' : `${result.duration_ms} ms`}</strong>
              </div>
            </div>
            <div className="table-scroll">
              <table className="table">
                <thead>
                  <tr>
                    <th scope="col">Indicator</th>
                    <th scope="col">Provider</th>
                    <th scope="col">Reputation</th>
                    <th scope="col">Status</th>
                  </tr>
                </thead>
                <tbody>
                  {tiFindings.slice(0, 50).map((finding) => {
                    const evidence = finding.evidence ?? {};
                    const provider = PROVIDER_LABELS[String(evidence.provider ?? '')] ?? String(evidence.provider ?? '');
                    const statusLabel = String(evidence.status_label ?? 'unknown');
                    const statusText = String(evidence.status ?? '');
                    return (
                      <tr key={finding.id}>
                        <td>
                          <code className="finding-type">{finding.value}</code>
                          <span className="table-sub">{String(evidence.indicator_type ?? '')}</span>
                        </td>
                        <td>
                          <span className="table-value">{provider}</span>
                        </td>
                        <td>
                          <Reputation evidence={finding.evidence} />
                        </td>
                        <td>
                          <StatusBadge statusLabel={statusLabel} status={statusText} />
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
            {status === 'error' && (
              <p className="page-note">Some provider lookups could not be completed; deterministic verdict is unaffected.</p>
            )}
          </>
        )}
      </div>
    </section>
  );
}