import { useCallback, useEffect, useState } from 'react';

import { api, friendlyError } from '../api/client';
import type { Scan } from '../api/types';
import { ScansTable } from '../components/ScansTable';

const HISTORY_LIMIT = 100;

export function ScanHistory() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const rows = await api.listScans(HISTORY_LIMIT);
      setScans(rows);
    } catch (err) {
      setError(friendlyError(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1 className="page-title">Scan History</h1>
          <p className="page-subtitle">
            {loading ? 'Loading…' : `${scans.length} most recent scans.`}
          </p>
        </div>
        <button type="button" className="btn btn-ghost" onClick={() => void load()} disabled={loading}>
          Refresh
        </button>
      </div>

      <section className="panel">
        <div className="panel-header">
          <h2 className="panel-title">Scans</h2>
          <span className="count-badge">{loading ? '…' : scans.length}</span>
        </div>
        <ScansTable
          scans={scans}
          loading={loading}
          error={error}
          emptyMessage="No scans submitted yet."
        />
      </section>
    </div>
  );
}