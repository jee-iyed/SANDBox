import { useEffect, useRef, useState } from 'react';
import { Link } from 'react-router-dom';

import { api, friendlyError } from '../api/client';
import type { SecureAccess, SecureContent } from '../api/types';
import { Alert } from '../components/Alert';
import { SecureAccessSection } from '../components/SecureAccessSection';
import { Spinner } from '../components/Spinner';

const POLL_INTERVAL_MS = 1500;
const MAX_POLLS = 160;

const TERMINAL = new Set<SecureAccess['status']>([
  'authorized',
  'blocked',
  'quarantined',
  'failed',
  'expired',
]);

const SOURCES = [
  { id: 'mail', label: 'Enterprise Mail Platform' },
  { id: 'dms', label: 'Document Management Platform' },
  { id: 'client', label: 'Client Platform (simulated)' },
];

export function SecureFileAccess() {
  const [file, setFile] = useState<File | null>(null);
  const [sourceId, setSourceId] = useState(SOURCES[0].id);
  const [access, setAccess] = useState<SecureAccess | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [preview, setPreview] = useState<SecureContent | null>(null);
  const [previewError, setPreviewError] = useState<string | null>(null);
  const [reloadNonce, setReloadNonce] = useState(0);
  const timer = useRef<number | undefined>(undefined);

  const reset = () => {
    if (timer.current !== undefined) {
      window.clearTimeout(timer.current);
      timer.current = undefined;
    }
    setAccess(null);
    setPreview(null);
    setPreviewError(null);
    setPending(false);
    setError(null);
  };

  useEffect(() => {
    return () => {
      if (timer.current !== undefined) {
        window.clearTimeout(timer.current);
      }
    };
  }, []);

  useEffect(() => {
    if (!access || TERMINAL.has(access.status)) {
      return;
    }
    let cancelled = false;
    let attempts = 0;

    const tick = async () => {
      let current: SecureAccess;
      try {
        current = await api.getSecureAccess(access.id);
      } catch (err) {
        if (!cancelled) {
          setError(friendlyError(err));
          setPending(false);
        }
        return;
      }
      if (cancelled) {
        return;
      }
      setAccess(current);
      setError(null);
      if (TERMINAL.has(current.status)) {
        setPending(false);
        return;
      }
      attempts += 1;
      if (attempts >= MAX_POLLS) {
        setPending(false);
        setError('The analysis is taking longer than expected. Reload to check status.');
        return;
      }
      timer.current = window.setTimeout(tick, POLL_INTERVAL_MS);
    };

    setPending(true);
    void tick();

    return () => {
      cancelled = true;
    };
  }, [access?.id, reloadNonce]);

  const startAccess = async () => {
    if (!file) {
      return;
    }
    reset();
    setSubmitting(true);
    setError(null);
    const source = SOURCES.find((s) => s.id === sourceId) ?? SOURCES[0];
    try {
      const created = await api.createSecureAccess(file, source.id);
      setAccess(created);
    } catch (err) {
      setError(friendlyError(err));
    } finally {
      setSubmitting(false);
    }
  };

  const openPreview = async () => {
    if (!access) {
      return;
    }
    setPreviewError(null);
    try {
      const content = await api.getSecureContent(access.id);
      setPreview(content);
    } catch (err) {
      setPreviewError(friendlyError(err));
    }
  };

  const status = access?.status;
  const decisionHeadline = (() => {
    switch (status) {
      case 'authorized':
        return { label: 'SAFE', tone: 'success' };
      case 'blocked':
        return { label: access?.verdict === 'malicious' ? 'MALICIOUS' : 'SUSPICIOUS', tone: 'warning' };
      case 'quarantined':
        return { label: 'QUARANTINED', tone: 'error' };
      case 'failed':
        return { label: 'FAILED', tone: 'error' };
      case 'expired':
        return { label: 'EXPIRED', tone: 'muted' };
      default:
        return { label: 'ANALYZING', tone: 'info' };
    }
  })();

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1 className="page-title">Secure File Access</h1>
          <p className="page-subtitle">
            SANDBox is a Secure Document Gateway: the file is analyzed by the backend before
            it ever reaches the user&apos;s machine. This screen simulates the client platform
            (e.g. an email or document platform) requesting that a file be opened securely.
          </p>
        </div>
      </div>

      <section className="panel">
        <div className="panel-header">
          <h2 className="panel-title">Open a file securely</h2>
          <span className="count-badge">Client Platform → SANDBox → Verdict</span>
        </div>
        <div className="panel-body">
          <div className="inline-form">
            <label className="field">
              <span className="field-label">Source (client platform)</span>
              <select
                className="input"
                value={sourceId}
                onChange={(e) => setSourceId(e.target.value)}
              >
                {SOURCES.map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.label}
                  </option>
                ))}
              </select>
            </label>

            <label className="field">
              <span className="field-label">File</span>
              <input
                className="input"
                type="file"
                onChange={(e) => setFile(e.target.files?.[0] ?? null)}
              />
            </label>

            <div className="form-actions">
              <button
                type="button"
                className="btn btn-primary"
                disabled={!file || submitting}
                onClick={() => void startAccess()}
              >
                {submitting ? 'Forwarding…' : 'Open Securely'}
              </button>
            </div>
          </div>

          {file && (
            <p className="page-note">
              Selected: <strong>{file.name}</strong> ({file.size} bytes). The client
              platform forwards this file to SANDBox; it is scanned before any secure
              access is granted.
            </p>
          )}

          {error && <Alert variant="error">{error}</Alert>}
        </div>
      </section>

      {access && (
        <>
          <section className={`panel panel-highlight`} aria-label="Secure file access status">
            <div className="result-summary">
              <div className="result-verdict">
                <span className="result-label">Decision</span>
                <strong className={`decision-text decision-${decisionHeadline.tone}`}>
                  {decisionHeadline.label}
                </strong>
              </div>
              <div className="result-risk">
                <span className="result-label">Risk</span>
                <strong className="decision-text">
                  {access.risk_score !== null && access.risk_score !== undefined
                    ? String(access.risk_score)
                    : 'Pending'}
                </strong>
              </div>
              <div className="result-action">
                <span className="result-label">Action</span>
                <strong className="decision-text">
                  {access.policy_action ? access.policy_action.toUpperCase() : 'PENDING'}
                </strong>
              </div>
            </div>

            {pending && (
              <div className="state-body">
                <Spinner label="SANDBox is scanning the file before granting access…" />
                <button
                  type="button"
                  className="btn btn-ghost btn-sm"
                  onClick={() => setReloadNonce((n) => n + 1)}
                >
                  Refresh status
                </button>
              </div>
            )}

            {status === 'authorized' && (
              <div className="state-body">
                <p className="page-note">
                  Security analysis completed. The file is authorized for secure access.
                  The original document is never downloaded automatically - use the secure
                  preview below.
                </p>
                <button type="button" className="btn btn-primary" onClick={() => void openPreview()}>
                  Open Secure Preview
                </button>
                <Link to={`/scans/${access.scan_id}?access=${access.id}`} className="btn btn-ghost">
                  View full analysis
                </Link>
              </div>
            )}

            {(status === 'blocked' || status === 'quarantined') && (
              <div className="state-body">
                <Alert variant={status === 'quarantined' ? 'error' : 'warning'} title="Access denied">
                  This file was not authorized by the security decision. It is not exposed
                  to you - no download of the original is offered.
                </Alert>
                <Link to={`/scans/${access.scan_id}?access=${access.id}`} className="btn btn-ghost">
                  View Analysis
                </Link>
              </div>
            )}

            {(status === 'failed' || status === 'expired') && (
              <div className="state-body">
                <Alert variant="error">
                  Access is denied: {status === 'failed' ? 'the analysis failed.' : 'the secure access request has expired.'}
                </Alert>
                <Link to={`/scans/${access.scan_id}?access=${access.id}`} className="btn btn-ghost">
                  View Analysis
                </Link>
              </div>
            )}
          </section>

          <SecureAccessSection access={access} />

          {preview && (
            <section className="panel">
              <div className="panel-header">
                <h2 className="panel-title">Secure Preview</h2>
                <span className="count-badge">{preview.content_kind}</span>
              </div>
              <div className="panel-body">
                <Alert variant="info">{preview.message}</Alert>
                {preview.deny_reason && <p className="page-note">{preview.deny_reason}</p>}
              </div>
            </section>
          )}
          {previewError && <Alert variant="error">{previewError}</Alert>}
        </>
      )}
    </div>
  );
}