import type { Verdict } from '../api/types';

interface RiskMeterProps {
  risk: number | null;
  verdict: Verdict;
}

// The deterministic risk engine produces an UNBOUNDED score (values such as
// 0.0, 34.0 or 132.0 are real outputs). This visual meter is therefore only a
// relative indicator on a 0-200 display scale - it must never be read as a
// probability or a percentage.
export function RiskMeter({ risk, verdict }: RiskMeterProps) {
  if (risk === null || Number.isNaN(risk)) {
    return (
      <div className="risk">
        <span className="risk-value-label">Risk Score</span>
        <span className="risk-value risk-value-unavailable">Risk score unavailable</span>
      </div>
    );
  }

  const displayScale = 200;
  const width = Math.max(0, Math.min(100, (risk / displayScale) * 100));
  const tone = verdict === 'safe' ? 'green' : verdict === 'suspicious' ? 'amber' : verdict === 'malicious' ? 'red' : 'navy';

  return (
    <div className="risk">
      <span className="risk-value-label">Risk Score</span>
      <span className="risk-value">{risk.toFixed(1)}</span>
      <div className="risk-meter" aria-hidden="true">
        <div className={`risk-meter-fill risk-meter-${tone}`} style={{ width: `${width}%` }} />
      </div>
      <span className="risk-caption">Relative indicator. Score is unbounded, not a probability.</span>
    </div>
  );
}