import { useEffect, useState } from 'react';

import { api, friendlyError } from '../api/client';
import type { Health } from '../api/types';
import { Spinner } from './Spinner';
import { Alert } from './Alert';

function StatusRow({ label, ok }: { label: string; ok: boolean }) {
  return (
    <div className="health-row">
      <span className="health-label">{label}</span>
      <span className={`health-dot ${ok ? 'health-dot-ok' : 'health-dot-down'}`} aria-hidden="true" />
      <span className="health-value">{ok ? 'Operational' : 'Offline'}</span>
    </div>
  );
}

export function SystemStatus() {
  const [health, setHealth] = useState<Health | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const check = async () => {
    setLoading(true);
    setError(null);
    try {
      setHealth(await api.health());
    } catch (err) {
      setHealth(null);
      setError(friendlyError(err));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void check();
  }, []);

  return (
    <section className="panel" aria-label="System status">
      <div className="panel-header">
        <h2 className="panel-title">System Status</h2>
        <button type="button" className="btn btn-ghost btn-sm" onClick={() => void check()}>
          Refresh
        </button>
      </div>

      {loading && (
        <div className="panel-body">
          <Spinner label="Checking system…" />
        </div>
      )}

      {!loading && error && (
        <div className="panel-body">
          <Alert variant="error">{error}</Alert>
        </div>
      )}

      {!loading && !error && health && (
        <div className="health-list">
          <StatusRow label="API" ok={health.status === 'ok'} />
          <StatusRow label="Database" ok={health.database} />
          <StatusRow label="Redis" ok={health.redis} />
        </div>
      )}
    </section>
  );
}