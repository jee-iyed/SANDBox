"""Safe temporary storage for secure-file-access deliverables.

Layout (under settings.storage_dir / "sandbox_storage"):
    pending/      - file received but not yet authorized (REQUESTED/SCANNING)
    processing/   - reserved for future pipeline-side processing
    authorized/   - file moved here ONLY after an authorized verdict
    quarantine/   - file moved here when BLOCKED/QUARANTINED (isolated)

Security properties:
* Files are named by a generated UUID (the access id), NEVER by the user
  filename. The original filename is metadata on the SecureFileAccess row.
* Every path is built with safe_join() so a stored reference can never escape
  the root (path traversal protection).
* The directory is NEVER exposed by the web server or any static mount.
* Transitions are best-effort; the actual gate is the state machine + content
  service. A non-authorized file is never served.
"""

from __future__ import annotations

import logging
import shutil
import uuid
from pathlib import Path

from app.core.config import settings
from app.core.security import safe_join

logger = logging.getLogger(__name__)

PENDING = "pending"
PROCESSING = "processing"
AUTHORIZED = "authorized"
QUARANTINE = "quarantine"

_STATUS_TO_DIR = {
    "requested": PENDING,
    "scanning": PENDING,
    "processing": PROCESSING,
    "authorized": AUTHORIZED,
    "blocked": QUARANTINE,
    "quarantined": QUARANTINE,
    # failed / expired → file is removed (no directory)
}


class SecureAccessStorage:
    def __init__(self, root: Path | None = None) -> None:
        self.root = root or settings.secure_storage_root
        for sub in (PENDING, PROCESSING, AUTHORIZED, QUARANTINE):
            (self.root / sub).mkdir(parents=True, exist_ok=True)

    def _rel(self, subdir: str, access_id: uuid.UUID) -> str:
        return f"{subdir}/{access_id}.bin"

    def _abs(self, ref: str):
        """Resolve a stored reference safely under the storage root."""
        return safe_join(self.root, *ref.split("/"))

    def write_pending(self, access_id: uuid.UUID, data: bytes) -> str:
        """Atomically store a received file in pending/. Returns the reference."""
        rel = self._rel(PENDING, access_id)
        dest = self._abs(rel)
        tmp = dest.with_suffix(".tmp")
        tmp.write_bytes(data)
        tmp.replace(dest)
        return rel

    def apply_transition(self, access_id: uuid.UUID, ref: str, status: str) -> str:
        """Move the deliverable copy according to the resolved state.

        Returns the new storage reference (or the previous one when the state
        maps to the same directory). Moves are best-effort and never raise:
        the authoritative gate is the state machine, not directory placement.
        """
        target = _STATUS_TO_DIR.get(status)
        if target is None:
            self.remove(access_id, ref)
            return ref
        target_rel = self._rel(target, access_id)
        if ref == target_rel:
            return ref
        src = self._abs(ref)
        dst = self._abs(target_rel)
        try:
            if src.exists():
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(str(src), str(dst))
                logger.info(
                    "SA_STORAGE moved access=%s %s -> %s", access_id, ref, target_rel
                )
        except OSError:  # best-effort move; gate remains the state machine
            logger.warning("SA_STORAGE move failed access=%s %s", access_id, ref)
        return target_rel

    def remove(self, access_id: uuid.UUID, ref: str) -> None:
        try:
            path = self._abs(ref)
            path.unlink(missing_ok=True)
        except OSError:
            logger.warning("SA_STORAGE remove failed access=%s %s", access_id, ref)


secure_storage = SecureAccessStorage()