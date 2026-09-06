from pathlib import Path

from app.core.config import settings


def safe_join(root: Path, *parts: str) -> Path:
    """Join path parts under root and guarantee the result stays inside it."""
    root_resolved = root.resolve()
    candidate = root.joinpath(*parts).resolve()
    try:
        candidate.relative_to(root_resolved)
    except ValueError as exc:
        raise ValueError(f"Unsafe path outside {root_resolved}: {candidate}") from exc
    return candidate


def quarantined_upload_path(sha256: str) -> Path:
    return safe_join(settings.quarantine_dir, f"{sha256}.bin")
