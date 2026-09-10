import { useState } from 'react';

import type { AnalysisResult } from '../api/types';
import { titleCase } from '../utils/format';

const ANALYZER_LABELS: Record<string, string> = {
  fast_scan: 'Fast Scan',
  static_analysis: 'Static Analysis',
  structural_analysis: 'Structural Analysis',
  yara: 'YARA',
  sandbox: 'Sandbox',
};

function statusTone(status: string): 'ok' | 'warn' | 'err' {
  if (status === 'ok') return 'ok';
  if (status === 'skipped') return 'warn';
  return 'err';
}

function AnalyzerBadge({ status }: { status: string }) {
  const tone = statusTone(status);
  return <span className={`analyzer-badge analyzer-${tone}`}>{status.toUpperCase()}</span>;
}

function SandboxControls({ payload }: { payload: Record<string, unknown> }) {
  const [open, setOpen] = useState(false);

  const policy = payload?.policy;
  const rows: Array<[string, string]> = [];
  if (policy && typeof policy === 'object') {
    const mapping: Array<[string, string]> = [
      ['network_disabled', 'Network'],
      ['read_only_rootfs', 'Root filesystem'],
      ['non_root', 'User'],
      ['cap_drop', 'Capabilities'],
      ['no_new_privileges', 'No new privileges'],
    ];
    for (const [key, label] of mapping) {
      const value = (policy as Record<string, unknown>)[key];
      if (typeof value === 'boolean') {
        rows.push([label, value ? 'Enabled' + (key === 'network_disabled' ? ' (disabled)' : '') : 'Disabled']);
      } else if (typeof value === 'string') {
        rows.push([label, value]);
      }
    }
  }

  return (
    <div className="controls">
      <button type="button" className="btn btn-ghost btn-sm" aria-expanded={open} onClick={() => setOpen((v) => !v)}>
        {open ? 'Hide security controls' : 'View security controls'}
      </button>
      {open && (
        <dl className="controls-list">
          {rows.map(([label, value]) => (
            <div key={label} className="controls-row">
              <dt>{label}</dt>
              <dd>{titleCase(value)}</dd>
            </div>
          ))}
        </dl>
      )}
    </div>
  );
}

function AnalyzerDetails({ result }: { result: AnalysisResult }) {
  const payload = result.payload;
  const payloadEntries = payload ? Object.entries(payload) : [];
  const maxEntries = payloadEntries.slice(0, 8);
  const tooMany = payloadEntries.length > maxEntries.length;

  if (payloadEntries.length === 0) {
    return null;
  }

  return (
    <div className="analyzer-details">
      {result.analyzer === 'sandbox' && (
        <SandboxControls payload={payload as Record<string, unknown>} />
      )}
      <details>
        <summary>View payload</summary>
        <pre className="payload-json" aria-label={`${ANALYZER_LABELS[result.analyzer] ?? result.analyzer} analyzer payload`}>
          {JSON.stringify(Object.fromEntries(maxEntries), null, 2)}
          {tooMany ? '\n// … additional fields not shown\n' : ''}
        </pre>
      </details>
    </div>
  );
}

export function AnalysisResultsSection({ results }: { results: AnalysisResult[] }) {
  if (results.length === 0) {
    return (
      <section className="panel">
        <div className="panel-header">
          <h2 className="panel-title">Analysis Results</h2>
        </div>
        <div className="panel-body">
          <p className="table-empty">No analyzer results recorded.</p>
        </div>
      </section>
    );
  }

  return (
    <section className="panel">
      <div className="panel-header">
        <h2 className="panel-title">Analysis Results</h2>
        <span className="count-badge">{results.length}</span>
      </div>
      <div className="table-scroll">
        <table className="table">
          <thead>
            <tr>
              <th scope="col">Analyzer</th>
              <th scope="col">Result</th>
              <th scope="col" className="num">
                Duration
              </th>
              <th scope="col">Detail</th>
              <th scope="col">Payload</th>
            </tr>
          </thead>
          <tbody>
            {results.map((result) => {
              const decision =
                typeof result.payload?.decision === 'string' ? String(result.payload.decision) : null;
              const reason = typeof result.payload?.reason === 'string' ? String(result.payload.reason) : null;
              return (
                <tr key={result.id}>
                  <td>
                    <span className="finding-type">{ANALYZER_LABELS[result.analyzer] ?? titleCase(result.analyzer)}</span>
                    <span className="table-sub">v{result.analyzer_version}</span>
                  </td>
                  <td>
                    <AnalyzerBadge status={result.status} />
                  </td>
                  <td className="num">{result.duration_ms === null || result.duration_ms === undefined ? '-' : `${result.duration_ms} ms`}</td>
                  <td className="table-value">
                    {decision && <span className="analyzer-decision">{titleCase(decision)}</span>}
                    {reason && <span className="table-sub">{reason}</span>}
                    {result.error && <span className="table-error-text">{result.error}</span>}
                    {!decision && !reason && !result.error && <span className="table-muted">-</span>}
                  </td>
                  <td>
                    <AnalyzerDetails result={result} />
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </section>
  );
}