"""Client platform integration abstraction.

Two integration modes are supported at the API level:

* MODE 1 - "upload": the client platform sends the actual file bytes
  (multipart/form-data). Used by this prototype and by platforms that can
  forward the file.
* MODE 2 - "external_reference": the client platform sends a secure reference
  / token instead of the bytes. The actual external retrieval (authenticated,
  platform-specific) is NOT implemented here and must never be a blind HTTP
  fetch of an arbitrary URL. An interface is provided for the future
  integration.

Authentication note: this is a PROTOTYPE integration endpoint. In production it
MUST sit behind an authenticated gateway (client platform credential /
integration token). It must NEVER be treated as a public, unauthenticated
endpoint in production.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass

UPLOAD_SOURCE = "upload"
EXTERNAL_REFERENCE_SOURCE = "external_reference"

SUPPORTED_SOURCE_TYPES = {UPLOAD_SOURCE, EXTERNAL_REFERENCE_SOURCE}


@dataclass(frozen=True)
class ClientSource:
    source_type: str
    source_identifier: str | None = None


class ExternalReferenceResolver(ABC):
    """Contract for future, platform-integrated file retrieval.

    MUST be authenticated and bound to a specific client platform. The default
    implementation is intentionally unavailable (``NotImplementedError``) - the
    prototype never downloads files from the internet.
    """

    @abstractmethod
    def retrieve(self, source_token: str, source_identifier: str | None) -> bytes:
        raise NotImplementedError("external reference retrieval is not configured")


def sanitize_filename(raw: str | None, default: str = "unnamed") -> str:
    """Reduce an untrusted client-supplied filename to a safe metadata string.

    The filename is NEVER used to build storage paths - it is only preserved as
    display metadata. This function strips path components, drive letters,
    control characters and trims the length to 512 chars (model bound).
    """
    if not raw:
        return default
    name = raw.replace("\\", "/").split("/")[-1]
    name = re.sub(r"[\x00-\x1f\x7f]", "", name).strip(" .")
    if not name:
        return default
    return name[:512]


def parse_source(
    *,
    source_type: str,
    source_token: str | None = None,
    source_identifier: str | None = None,
) -> ClientSource:
    """Validate and normalize a client source description from the endpoint."""
    source_type = (source_type or "").strip()
    if source_type not in SUPPORTED_SOURCE_TYPES:
        raise ValueError(
            f"unsupported source_type '{source_type}' "
            f"(expected one of {sorted(SUPPORTED_SOURCE_TYPES)})"
        )
    if source_type == EXTERNAL_REFERENCE_SOURCE and not source_token:
        raise ValueError("source_token is required for external_reference")
    return ClientSource(
        source_type=source_type,
        source_identifier=source_identifier or None,
    )