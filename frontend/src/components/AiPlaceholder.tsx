// Reserved section for the AI interpretation layer.
// Intentionally shows ONLY the not-configured state: the backend AI layer is
// readiness-only (AI_ENABLED=false by default, see backend/app/ai/) and the
// supervisor has not finalized the LLM role. Nothing is invented here.

export function AiPlaceholder() {
  return (
    <section className="panel panel-muted" aria-label="AI security analysis">
      <div className="panel-header">
        <h2 className="panel-title">AI Security Analysis</h2>
        <span className="badge badge-gray">Not configured</span>
      </div>
      <div className="panel-body">
        <p className="ai-text">
          AI-assisted analysis will be available once the AI engine is configured.
        </p>
        <p className="ai-note">
          Reserved for the deterministic analysis review layer. The AI engine does not
          influence verdict, action or risk score.
        </p>
      </div>
    </section>
  );
}