import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';

import { api, friendlyError } from '../api/client';
import type { Scan } from '../api/types';
import { SystemStatus } from '../components/SystemStatus';
import { ScansTable } from '../components/ScansTable';

export function Dashboard() {
  const [recent, setRecent] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      setLoading(true);
      setError(null);
      try {
        const scans = await api.listScans(8);
        if (!cancelled) {
          setRecent(scans);
        }
      } catch (err) {
        if (!cancelled) {
          setError(friendlyError(err));
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    };
    void load();
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1 className="page-title">Dashboard</h1>
          <p className="page-subtitle">
            SANDBox is a secure document gateway: files are analyzed by the backend before
            they reach the user&apos;s machine. This screen shows gateway health and recent
            processing activity.
          </p>
        </div>
        <div className="dashboard-cta">
          <Link to="/secure-access" className="btn btn-primary">
            Open a file securely
          </Link>
          <Link to="/scans/new" className="btn btn-ghost">
            Manual scan (testing)
          </Link>
        </div>
      </div>

      <SystemStatus />

      <section className="panel">
        <div className="panel-header">
          <h2 className="panel-title">Recent Scans</h2>
          <span className="count-badge">{loading ? '…' : recent.length}</span>
          <Link to="/scans" className="btn btn-ghost btn-sm">
            View all
          </Link>
        </div>
        <ScansTable
          scans={recent}
          loading={loading}
          error={error}
          emptyMessage="No scans yet. Submit your first document with New Scan."
        />
      </section>
    </div>
  );
}
