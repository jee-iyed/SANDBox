import type { AnalysisResult } from '../api/types';

export function QrAnalysisSection({ results }: { results: AnalysisResult[] }) {
  const result = results.find((item) => item.analyzer === 'qr_analysis');
  if (!result) return null;
  const hasThreatIntel = results.some((item) => item.analyzer === 'threat_intel');
  const payload = result.payload ?? {};
  const status = typeof payload.status === 'string' ? payload.status : result.status;
  const count = typeof payload.count === 'number' ? payload.count : 0;
  const urls = Array.isArray(payload.urls) ? payload.urls.filter((item): item is string => typeof item === 'string') : [];
  const reason = typeof payload.reason === 'string' ? payload.reason : null;
  return (
    <section className="panel">
      <div className="panel-header"><h2 className="panel-title">QR Analysis</h2></div>
      <div className="panel-body qr-result">
        <div><span className="result-label">Status</span><strong>{status.replaceAll('_', ' ')}</strong></div>
        <div><span className="result-label">QR codes</span><strong>{count}</strong></div>
        {urls.length > 0 && <div className="qr-urls"><span className="result-label">Decoded URLs</span>{urls.map((url) => <code key={url}>{url}</code>)}<p className="page-note">{hasThreatIntel ? 'URL extracted — see Threat Intelligence section.' : 'URL extracted — reputation analysis not configured.'}</p></div>}
        {urls.length === 0 && status === 'detected' && <p className="page-note">QR payload decoded; no URL was extracted.</p>}
        {reason && status !== 'detected' && <p className="page-note">{reason.replaceAll('_', ' ')}</p>}
      </div>
    </section>
  );
}
