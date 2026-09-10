import type { ScanStatus } from '../api/types';

interface ScanPipelineProps {
  status: ScanStatus;
}

interface Step {
  label: string;
  state: 'done' | 'active' | 'pending';
}

// The API only exposes the overall scan lifecycle (queued -> processing ->
// completed). Individual analyzer stages are NOT exposed as a pipeline, so we
// never claim that M1/M2/M3/... have progressed on their own.
export function ScanPipeline({ status }: ScanPipelineProps) {
  const queued = status === 'queued' || status === 'processing' || status === 'completed';
  const processing = status === 'processing' || status === 'completed';

  const steps: Step[] = [
    { label: 'Upload', state: 'done' },
    { label: 'Queued', state: queued ? 'done' : status === 'failed' ? 'pending' : 'pending' },
    {
      label: 'Analysis',
      state: status === 'processing' ? 'active' : processing ? 'done' : status === 'failed' ? 'pending' : 'pending',
    },
    { label: 'Verdict', state: status === 'completed' ? 'done' : 'pending' },
  ];

  return (
    <ol className="pipeline" aria-label="Scan progress">
      {steps.map((step, index) => (
        <li key={step.label} className={`pipeline-step pipeline-${step.state}`}>
          <span className="pipeline-indicator" aria-hidden="true">
            {step.state === 'done' ? '✓' : step.state === 'active' ? '●' : '○'}
          </span>
          <span>{step.label}</span>
          {index < steps.length - 1 && <span className="pipeline-connector" aria-hidden="true" />}
        </li>
      ))}
    </ol>
  );
}