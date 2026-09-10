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

    # Redis-backed scan queue (see DECISIONS.md D-14). Connection is configured
    # via REDIS_URL, or - when REDIS_HOST/PORT/DB are set - built from those.
    redis_url: str = "redis://localhost:6379/0"
    redis_host: str = ""
    redis_port: int = 0
    redis_db: int = 0
    redis_username: str | None = None
    redis_password: str | None = None
    # Job dispatch stream + consumer group. Jobs are {scan_id: "..."} only;
    # files and persistent state stay in PostgreSQL/storage.
    redis_queue_name: str = "sandbox:scans"
    redis_consumer_group: str = "sandbox:workers"
    # Approximate stream cap: records are trimmed after ack; this bounds memory.
    redis_stream_maxlen: int = 100000
    # Minimum idle time before a pending (in-flight) job from a crashed worker
    # is reclaimed and redelivered. Must exceed the max pipeline duration:
    # scan_timeout_s + Docker sandbox lifecycle.
    redis_visibility_timeout_s: int = 600
    # Blocking read timeout per consumer (ms) before it reclaims stale jobs.
    redis_block_timeout_ms: int = 5000
    # Backoff before retrying after a QUEUE_ERROR / WORKER_ERROR.
    redis_backoff_s: float = 2.0

    # Security limits (hardening baseline, see SECURITY.md)
    max_upload_mb: int = 50
    max_archive_depth: int = 5
    max_archive_entries: int = 1000
    max_archive_ratio: float = 200.0
    max_archive_uncompressed_mb: int = 100
    scan_timeout_s: int = 300

    storage_dir: Path = BASE_DIR / "storage"

    # Secure File Access gateway (see DECISIONS.md D-16). TTL bounds how long a
    # request may be delivered/browsed after its access is granted. The
    # deliverable copy lives under sandbox_storage/ (never web-exposed).
    secure_access_ttl_minutes: int = 15

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

    # QR visual analysis is deliberately bounded. It is evidence collection
    # only; QR payloads never determine a verdict on their own.
    qr_enabled: bool = True
    qr_max_pages: int = 5
    qr_render_dpi: int = 144
    qr_max_pixels: int = 4_000_000
    qr_max_codes: int = 20
    qr_timeout_s: float = 10.0

# Bounded Redis scan consumers (see DECISIONS.md D-14). The queue replaced
    # the old DB-poll dispatch; worker_max_threads bounds concurrency.
    worker_max_threads: int = 4

    # Threat Intelligence enrichment (evidence only - see DECISIONS.md D-17).
    # DISABLED by default: the M1-M5 pipeline stays fully operational without
    # any external credentials. When enabled it runs AFTER the deterministic
    # verdict/action/risk are persisted; TI evidence never re-enters _decide().
    # API keys come from the environment exclusively (never committed, never
    # logged, never exposed to the frontend).
    ti_enabled: bool = False
    ti_cache_ttl_seconds: int = 3600
    ti_max_indicators_per_scan: int = 20
    ti_max_retry_wait_s: float = 10.0
    ti_local_cache_max_entries: int = 4096

    # AbuseIPDB (reputation CHECK only - never REPORT). Free key: 1000 checks/day.
    abuseipdb_enabled: bool = False
    abuseipdb_api_key: str = ""
    abuseipdb_base_url: str = "https://api.abuseipdb.com/api/v2"
    abuseipdb_timeout_seconds: float = 3.0
    abuseipdb_max_age_days: int = 90
    abuseipdb_min_spacing_s: float = 1.0
    abuseipdb_max_requests_per_day: int = 1000

    # VirusTotal API v3 (reputation lookups only - no file/URL submission).
    # Public free-license conservative limits: 4 requests/minute, 500/day.
    # The free public API is NOT suitable for commercial production; a future
    # licensed key only requires changing these limits (see DECISIONS.md D-17).
    virustotal_enabled: bool = False
    virustotal_api_key: str = ""
    virustotal_base_url: str = "https://www.virustotal.com/api/v3"
    virustotal_timeout_seconds: float = 4.0
    virustotal_max_requests_per_minute: int = 4
    virustotal_max_requests_per_day: int = 500
    # Minimum spacing between two provider calls (shared by every worker).
    # 0 means "auto": ceil(60 / virustotal_max_requests_per_minute).
    virustotal_min_spacing_s: float = 0.0
    virustotal_lookup_ip: bool = True
    virustotal_lookup_url: bool = True
    virustotal_lookup_domain: bool = True
    virustotal_lookup_sha256: bool = True

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
        "threat_intel": "0.1.0",
    }

    @property
    def uploads_dir(self) -> Path:
        return self.storage_dir / "uploads"

    @property
    def secure_storage_root(self) -> Path:
        """Secure File Access temporary storage (pending/authorized/quarantine)."""
        return self.storage_dir / "sandbox_storage"

    @property
    def quarantine_dir(self) -> Path:
        return self.storage_dir / "quarantine"

    @property
    def sanitized_dir(self) -> Path:
        return self.storage_dir / "sanitized"

    @property
    def reports_dir(self) -> Path:
        return self.storage_dir / "reports"

    @property
    def redis_connection_url(self) -> str:
        """Effective Redis URL.

        Prefer granular REDIS_HOST/REDIS_PORT/REDIS_DB/REDIS_USERNAME/
        REDIS_PASSWORD when set; otherwise fall back to REDIS_URL.
        """
        if self.redis_host or self.redis_port or self.redis_db:
            host = self.redis_host or "localhost"
            port = self.redis_port or 6379
            db = self.redis_db or 0
            user = self.redis_username or ""
            password = self.redis_password or ""
            auth = f"{user}:{password}@" if (user or password) else ""
            return f"redis://{auth}{host}:{port}/{db}"
        return self.redis_url


settings = Settings()
for _d in (
    settings.uploads_dir,
    settings.quarantine_dir,
    settings.sanitized_dir,
    settings.reports_dir,
):
    _d.mkdir(parents=True, exist_ok=True)
