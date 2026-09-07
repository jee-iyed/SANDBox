from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=BASE_DIR / ".env", env_file_encoding="utf-8", extra="ignore"
    )

    app_name: str = "Document Security Scanner"
    environment: str = "dev"
    version: str = "0.1.0"

    database_url: str = "postgresql+psycopg://sandbox:sandbox@localhost:5432/sandbox"
    redis_url: str = "redis://localhost:6379/0"

    # Security limits (hardening baseline, see SECURITY.md)
    max_upload_mb: int = 50
    max_archive_depth: int = 5
    max_archive_entries: int = 1000
    max_archive_ratio: float = 200.0
    max_archive_uncompressed_mb: int = 100
    scan_timeout_s: int = 300

    storage_dir: Path = BASE_DIR / "storage"

    # Sandbox (M3) - infra hardened, see analyzers/sandbox
    sandbox_enabled: bool = True
    sandbox_image: str = "docscan/sandbox-runner:latest"
    sandbox_timeout_s: int = 60
    sandbox_mem_limit: str = "256m"
    sandbox_nano_cpus: int = 500000000
    sandbox_pids_limit: int = 64
    # how long an individual traced process may run before being killed
    sandbox_exec_timeout_s: int = 30

    # Static analysis (M4) - bounded byte inspection, never executes the sample
    static_max_scan_bytes: int = 2_000_000
    yara_enabled: bool = True
    yara_timeout_s: int = 5
    yara_max_matches: int = 100

    # Dynamic analysis (M5) - eligibility + bounded monitoring (reuses M3 sandbox)
    dynamic_enabled: bool = True
    dynamic_max_file_mb: int = 10
    dynamic_max_events: int = 2000
    dynamic_max_output_mb: int = 1

    # MVP background worker (simple DB-poll, see DECISIONS.md)
    # Four bounded workers allow independent, eligible sandbox jobs to make
    # progress concurrently.  This does not change SandboxPolicy limits.
    worker_poll_interval_s: float = 0.1
    worker_max_threads: int = 4

    # PROVISIONAL risk-thresholds - NOT confirmed by client (§8, see DECISIONS.md)
    risk_safe_max: float = 0.0
    risk_suspect_max: float = 40.0
    risk_malicious_min: float = 75.0

    # Analyzer/ruleset versions. Bump on any change; recorded on every finding (§2.2).
    ANALYZER_VERSIONS: dict = {
        "ingestion": "0.1.0",
        "fast_scan": "0.1.0",
        "sandbox": "0.4.0",
        "static": "0.1.0",
        "yara": "0.1.0",
    }

    @property
    def uploads_dir(self) -> Path:
        return self.storage_dir / "uploads"

    @property
    def quarantine_dir(self) -> Path:
        return self.storage_dir / "quarantine"

    @property
    def sanitized_dir(self) -> Path:
        return self.storage_dir / "sanitized"

    @property
    def reports_dir(self) -> Path:
        return self.storage_dir / "reports"


settings = Settings()
for _d in (
    settings.uploads_dir,
    settings.quarantine_dir,
    settings.sanitized_dir,
    settings.reports_dir,
):
    _d.mkdir(parents=True, exist_ok=True)
