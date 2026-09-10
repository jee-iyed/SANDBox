import { useEffect, useRef, useState } from 'react';
import { useParams, useSearchParams } from 'react-router-dom';

import { api, friendlyError } from '../api/client';
import type { ScanDetail as ScanDetailData, SecureAccess } from '../api/types';
import { ActionBadge, ScanStatusBadge, VerdictBadge } from '../components/Badges';
import { RiskMeter } from '../components/RiskMeter';
import { ScanPipeline } from '../components/ScanPipeline';
import { FindingsSection } from '../components/FindingsSection';
import { AnalysisResultsSection } from '../components/AnalysisResultsSection';
import { QrAnalysisSection } from '../components/QrAnalysisSection';
import { AiPlaceholder } from '../components/AiPlaceholder';
import { Alert } from '../components/Alert';
import { SecureAccessSection } from '../components/SecureAccessSection';
import { Spinner } from '../components/Spinner';
import { formatBytes, formatDateTime } from '../utils/format';

const POLL_INTERVAL_MS = 1500;
const MAX_POLLS = 120;

function isTerminal(status: string): boolean {
  return status === 'completed' || status === 'failed';
}

function FileInfoRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="file-info-row">
      <dt>{label}</dt>
      <dd title={value}>{value}</dd>
    </div>
  );
}

export function ScanDetail() {
  const { scanId = '' } = useParams();
  const [searchParams] = useSearchParams();
  const accessParam = searchParams.get('access');
  const [detail, setDetail] = useState<ScanDetailData | null>(null);
  const [secureAccess, setSecureAccess] = useState<SecureAccess | null>(null);
  const [accessLoading, setAccessLoading] = useState(false);
  const [accessError, setAccessError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [reloadNonce, setReloadNonce] = useState(0);
  const [copied, setCopied] = useState(false);
  const copyTimer = useRef<number | undefined>(undefined);

  useEffect(() => {
    if (!accessParam) {
      return;
    }
    let cancelled = false;
    setAccessLoading(true);
    setAccessError(null);
    api
      .getSecureAccess(accessParam)
      .then((item) => {
        if (!cancelled) {
          setSecureAccess(item);
        }
      })
      .catch((err) => {
        if (!cancelled) {
          setAccessError(friendlyError(err));
        }
      })
      .finally(() => {
        if (!cancelled) {
          setAccessLoading(false);
        }
      });
    return () => {
      cancelled = true;
    };
  }, [accessParam]);

  useEffect(() => {
    let cancelled = false;
    let timer: number | undefined;
    let attempts = 0;

    const tick = async () => {
      let data: ScanDetailData;
      try {
        data = await api.getScan(scanId);
      } catch (err) {
        if (!cancelled) {
          setError(friendlyError(err));
          setLoading(false);
        }
        return;
      }
      if (cancelled) {
        return;
      }
      setDetail(data);
      setError(null);
      setLoading(false);
      if (isTerminal(data.status)) {
        return;
      }
      attempts += 1;
      if (attempts >= MAX_POLLS) {
        setError('The scan is taking longer than expected. You can reload this page or check Scan History.');
        return;
      }
      timer = window.setTimeout(tick, POLL_INTERVAL_MS);
    };

    setDetail(null);
    setLoading(true);
    setError(null);
    void tick();

    return () => {
      cancelled = true;
      if (timer !== undefined) {
        window.clearTimeout(timer);
      }
    };
  }, [scanId, reloadNonce]);

  useEffect(() => {
    return () => {
      if (copyTimer.current !== undefined) {
        window.clearTimeout(copyTimer.current);
      }
    };
  }, []);

  const copySha256 = async () => {
    if (!detail?.file?.sha256) {
      return;
    }
    try {
      await navigator.clipboard.writeText(detail.file.sha256);
      setCopied(true);
      if (copyTimer.current !== undefined) {
        window.clearTimeout(copyTimer.current);
      }
      copyTimer.current = window.setTimeout(() => setCopied(false), 1500);
    } catch {
      // clipboard unavailable - feedback simply does not appear
    }
  };

  if (loading && !detail) {
    return (
      <div className="page">
        <div className="state-body">
          <Spinner label="Loading results…" />
        </div>
      </div>
    );
  }

  if (error && !detail) {
    return (
      <div className="page">
        <div className="state-body">
          <Alert variant="error">{error}</Alert>
          <button type="button" className="btn btn-ghost" onClick={() => setReloadNonce((n) => n + 1)}>
            Retry
          </button>
        </div>
      </div>
    );
  }

  if (!detail) {
    return (
      <div className="page">
        <div className="state-body">
          <Spinner label="Loading…" />
        </div>
      </div>
    );
  }

  const filename = detail.file?.filename ?? 'unnamed';
  const failed = detail.status === 'failed';
  const processing = !isTerminal(detail.status);

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1 className="page-title">
            {processing ? 'Scan in Progress' : failed ? 'Scan Failed' : 'Scan Result'}
          </h1>
          <p className="page-subtitle">{filename}</p>
        </div>
        <ScanStatusBadge status={detail.status} />
      </div>

      <div className="page-stats">
        <div className="meta-chip">
          <span className="meta-label">Scan ID</span>
          <span className="meta-value">{detail.id}</span>
        </div>
        <div className="meta-chip">
          <span className="meta-label">Created</span>
          <span className="meta-value">{formatDateTime(detail.created_at)}</span>
        </div>
        {detail.completed_at && (
          <div className="meta-chip">
            <span className="meta-label">Completed</span>
            <span className="meta-value">{formatDateTime(detail.completed_at)}</span>
          </div>
        )}
      </div>

      {processing && (
        <section className="panel">
          <div className="panel-body state-body">
            <ScanPipeline status={detail.status} />
            <p className="page-note">
              Waiting for analysis… the page refreshes automatically and stops once the scan is complete.
            </p>
            {error && <Alert variant="warning">{error}</Alert>}
            <button type="button" className="btn btn-ghost btn-sm" onClick={() => setReloadNonce((n) => n + 1)}>
              Refresh now
            </button>
          </div>
        </section>
      )}

      {failed && (
        <section className="panel">
          <div className="panel-body">
            <Alert variant="error" title="Analysis failed">
              The backend could not complete the scan of this file. No verdict was produced.
            </Alert>
            {error && <Alert variant="warning">{error}</Alert>}
            <div className="state-body">
              <button type="button" className="btn btn-ghost" onClick={() => setReloadNonce((n) => n + 1)}>
                Reload
              </button>
            </div>
          </div>
        </section>
      )}

      {!processing && !failed && <ResultBlock detail={detail} copied={copied} onCopy={copySha256} />}

      {accessParam && (
        <SecureAccessSection
          access={secureAccess}
          loading={accessLoading}
          error={accessError}
        />
      )}
    </div>
  );
}

function ResultBlock({
  detail,
  copied,
  onCopy,
}: {
  detail: ScanDetailData;
  copied: boolean;
  onCopy: () => void;
}) {
  const file = detail.file;

  return (
    <>
      <section className="panel panel-highlight" aria-label="Scan summary">
        <div className="result-summary">
          <div className="result-verdict">
            <span className="result-label">Verdict</span>
            <VerdictBadge verdict={detail.verdict} />
          </div>
          <div className="result-risk">
            <RiskMeter risk={detail.risk_score} verdict={detail.verdict} />
          </div>
          <div className="result-action">
            <span className="result-label">Action</span>
            <ActionBadge action={detail.action} />
          </div>
        </div>
      </section>

      <section className="panel">
        <div className="panel-header">
          <h2 className="panel-title">File Information</h2>
        </div>
        <div className="panel-body">
          <dl className="file-info-grid">
            <FileInfoRow label="Filename" value={file?.filename ?? '-'} />
            <FileInfoRow label="Size" value={formatBytes(file?.size_bytes)} />
            <FileInfoRow label="MIME type" value={file?.mime_type ?? '-'} />
            <FileInfoRow label="Detected type" value={file?.detected_type ?? '-'} />
            <FileInfoRow label="SHA-256" value={file?.sha256 ?? '-'} />
            <FileInfoRow label="File ID" value={file?.id ?? '-'} />
            <FileInfoRow label="Quarantined" value={file?.quarantined ? 'Yes' : 'No'} />
          </dl>
          {file?.sha256 && (
            <button type="button" className="btn btn-ghost btn-sm" onClick={onCopy}>
              {copied ? 'Copied' : 'Copy SHA-256'}
            </button>
          )}
        </div>
      </section>

      <FindingsSection findings={detail.findings} />
      <QrAnalysisSection results={detail.analysis_results} />
      <AnalysisResultsSection results={detail.analysis_results} />
      <AiPlaceholder />
    </>
  );
}
