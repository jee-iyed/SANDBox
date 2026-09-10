"""Secure content delivery: decide WHETHER (and WHAT) may be exposed.

Invariant: the ORIGINAL file is never served to the browser before the
deterministic verdict authorizes it, and even then this prototype does NOT emit
document bytes. Rendering/sanitization inside the sandbox is NOT implemented
yet, so the service answers with a controlled placeholder:

    "File analyzed successfully. Secure preview is not yet configured."

This keeps the contract honest: an authorized access means the ANALYSIS
authorized the file, NOT that the project falsely claims to render arbitrary
Office/PDF content safely in the browser.
"""

from __future__ import annotations

from app.db.models import SecureAccessStatus


class SecureContentService:
    def __init__(self, *, original_delivery_enabled: bool = False) -> None:
        # Future: when a sandbox-side renderer/sanitizer exists, set this flag
        # and return the sanitized artifact. Until then the placeholder applies.
        self._original_delivery_enabled = original_delivery_enabled

    def delivery_response(self, status: SecureAccessStatus) -> dict:
        """Build the secure-content response for an ALREADY-authorized access.

        Callers MUST gate on ``status == AUTHORIZED`` first (fail-closed):
        this method never re-validates and must never be reached otherwise.
        """
        return {
            "authorized": True,
            "content_kind": "placeholder" if not self._original_delivery_enabled else "sanitized",
            "message": (
                "File analyzed successfully. Secure preview is not yet configured."
            ),
            "mime_type": None,
            "size_bytes": None,
        }


secure_content_service = SecureContentService()