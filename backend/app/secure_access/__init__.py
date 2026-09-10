"""Secure File Access (gateway) layer.

This package turns SANDBox from a manual upload/scan tool into a Secure File
Access Gateway: the client platform forwards a file (or a secure reference),
SANDBox scans it through the existing M1-M5 pipeline with the existing Redis
Streams queue, and the deliverable is only exposed through a fail-closed
secure-content service AFTER an authorized deterministic verdict.

The analysis pipeline, risk engine, Redis queue and worker are NOT duplicated
here: the SecureFileAccess record simply wraps a normal Scan and observes its
state (see DECISIONS.md D-16).
"""

from app.secure_access.client_sources import (
    ClientSource,
    ExternalReferenceResolver,
    parse_source,
)
from app.secure_access.content import SecureContentService, secure_content_service
from app.secure_access.service import (
    cleanup_expired,
    create_access,
    deny_reason,
    raise_if_oversized,
    refresh,
    resolve_status,
    sanitize_filename,
)
from app.secure_access.storage import secure_storage

__all__ = [
    "ClientSource",
    "ExternalReferenceResolver",
    "SecureContentService",
    "secure_content_service",
    "cleanup_expired",
    "create_access",
    "deny_reason",
    "parse_source",
    "raise_if_oversized",
    "refresh",
    "resolve_status",
    "sanitize_filename",
    "secure_storage",
]