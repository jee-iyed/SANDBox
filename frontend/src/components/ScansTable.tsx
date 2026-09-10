import { Link } from 'react-router-dom';

import type { Scan } from '../api/types';
import { ActionBadge, ScanStatusBadge, VerdictBadge } from './Badges';
import { Spinner } from './Spinner';
import { Alert } from './Alert';
import { formatBytes, formatDateTime } from '../utils/format';

interface ScansTableProps {
  scans: Scan[];
  loading: boolean;
  error: string | null;
  emptyMessage?: string;
}

export function ScansTable({ scans, loading, error, emptyMessage = 'No scans yet.' }: ScansTableProps) {
  if (loading) {
    return (
      <div className="table-state">
        <Spinner label="Loading scans…" />
      </div>
    );
  }

  if (error) {
    return (
      <div className="table-state">
        <Alert variant="error">{error}</Alert>
      </div>
    );
  }

  if (scans.length === 0) {
    return <p className="table-empty">{emptyMessage}</p>;
  }

  return (
    <div className="table-scroll">
      <table className="table">
        <thead>
          <tr>
            <th scope="col">File</th>
            <th scope="col">Status</th>
            <th scope="col">Verdict</th>
            <th scope="col" className="num">
              Risk
            </th>
            <th scope="col">Action</th>
            <th scope="col">Created</th>
          </tr>
        </thead>
        <tbody>
          {scans.map((scan) => (
            <tr key={scan.id}>
              <td>
                <Link to={`/scans/${scan.id}`} className="table-link">
                  {scan.file?.filename ?? 'unnamed'}
                </Link>
                <span className="table-sub">{formatBytes(scan.file?.size_bytes)}</span>
              </td>
              <td>
                <ScanStatusBadge status={scan.status} />
              </td>
              <td>
                <VerdictBadge verdict={scan.verdict} />
              </td>
              <td className="num">{scan.risk_score === null ? '-' : scan.risk_score.toFixed(1)}</td>
              <td>
                <ActionBadge action={scan.action} />
              </td>
              <td className="table-muted">{formatDateTime(scan.created_at)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}