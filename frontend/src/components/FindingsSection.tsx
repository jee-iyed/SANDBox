import { useState } from 'react';

import type { Finding } from '../api/types';
import { SeverityBadge } from './Badges';
import { titleCase, truncate } from '../utils/format';

function Evidence({ finding }: { finding: Finding }) {
  const [open, setOpen] = useState(false);

  if (!finding.evidence && !finding.location) {
    return <span className="table-muted">None</span>;
  }

  const summary = [finding.evidence, finding.location]
    .filter(Boolean)
    .map((entry) => truncate(JSON.stringify(entry), 96))
    .join(' | ');

  return (
    <div className="evidence">
      <button
        type="button"
        className="btn btn-ghost btn-sm"
        aria-expanded={open}
        onClick={() => setOpen((value) => !value)}
      >
        {open ? 'Hide evidence' : 'View evidence'}
      </button>
      {open && (
        <pre className="evidence-json" aria-label="Finding evidence">
          {JSON.stringify({ evidence: finding.evidence, location: finding.location }, null, 2)}
        </pre>
      )}
      {!open && summary && <span className="evidence-preview">{summary}</span>}
    </div>
  );
}

export function FindingsSection({ findings }: { findings: Finding[] }) {
  if (findings.length === 0) {
    return (
      <section className="panel">
        <div className="panel-header">
          <h2 className="panel-title">Findings</h2>
        </div>
        <div className="panel-body">
          <p className="table-empty">No findings recorded by the analyzers.</p>
        </div>
      </section>
    );
  }

  return (
    <section className="panel">
      <div className="panel-header">
        <h2 className="panel-title">Findings</h2>
        <span className="count-badge">{findings.length}</span>
      </div>
      <div className="table-scroll">
        <table className="table">
          <thead>
            <tr>
              <th scope="col">Finding</th>
              <th scope="col">Severity</th>
              <th scope="col" className="num">
                Confidence
              </th>
              <th scope="col">Source</th>
              <th scope="col">Value</th>
              <th scope="col">Tags</th>
              <th scope="col">Evidence</th>
            </tr>
          </thead>
          <tbody>
            {findings.map((finding) => (
              <tr key={finding.id}>
                <td>
                  <span className="finding-type">{titleCase(finding.type)}</span>
                  <span className="table-sub">{finding.analyzer_version}</span>
                </td>
                <td>
                  <SeverityBadge severity={finding.severity} />
                </td>
                <td className="num">
                  {finding.confidence === undefined || finding.confidence === null
                    ? '-'
                    : finding.confidence.toFixed(2)}
                </td>
                <td>{titleCase(finding.source)}</td>
                <td className="table-value">{finding.value ? truncate(finding.value, 120) : '-'}</td>
                <td>
                  {finding.tags?.length ? (
                    <span className="tags">
                      {finding.tags.map((tag) => (
                        <span key={tag} className="tag">
                          {tag}
                        </span>
                      ))}
                    </span>
                  ) : (
                    <span className="table-muted">-</span>
                  )}
                </td>
                <td>
                  <Evidence finding={finding} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}