"""Magic-byte based file type detection (fast, first-pass).

Only a bounded prefix of the file is inspected so detection stays cheap. The
entropy you compute on that same bound is by definition a *sample* entropy (see
entropy.py) - never presented as a whole-file property.

Signature match ordering matters: longer/more specific prefixes win.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class MagicSignature:
    offset: int
    hex_prefix: str  # bytes as hex, already at `offset`
    display_type: str
    mime: str
    extensions: tuple[str, ...] = ()  # expected filename extensions


_SIGS: list[MagicSignature] = [
    # PDF
    MagicSignature(0, "25504446", "pdf", "application/pdf", (".pdf",)),
    # ZIP -> container; OOXML/ODF probed separately (see probe_container)
    MagicSignature(0, "504b0304", "zip", "application/zip", ()),
    MagicSignature(0, "504b0506", "zip", "application/zip", ()),
    MagicSignature(0, "504b0708", "zip", "application/zip", ()),
    # OLE2 / CFB (legacy doc/xls/ppt)
    MagicSignature(
        0, "d0cf11e0a1b11ae1", "ole2", "application/x-ole-storage", (".doc", ".xls", ".ppt")
    ),
    MagicSignature(0, "377abcaf271c", "7z", "application/x-7z-compressed", (".7z",)),
    MagicSignature(0, "526172211a0700", "rar", "application/x-rar-compressed", (".rar",)),
    MagicSignature(0, "1f8b", "gzip", "application/gzip", (".gz", ".tgz")),
    MagicSignature(0, "425a68", "bzip2", "application/x-bzip2", (".bz2",)),
    MagicSignature(0, "fd377a585a00", "xz", "application/x-xz", (".xz",)),
    MagicSignature(0, "89504e470d0a1a0a", "png", "image/png", (".png",)),
    MagicSignature(0, "ffd8ff", "jpeg", "image/jpeg", (".jpg", ".jpeg")),
    MagicSignature(0, "47494638", "gif", "image/gif", (".gif",)),
    MagicSignature(0, "424d", "bmp", "image/bmp", (".bmp",)),
    MagicSignature(0, "52494646", "webp", "image/webp", (".webp",)),
    MagicSignature(0, "49492a00", "tiff", "image/tiff", (".tif", ".tiff")),
    MagicSignature(0, "4d4d002a", "tiff", "image/tiff", (".tif", ".tiff")),
    MagicSignature(0, "7f454c46", "elf", "application/x-elf", (".elf", "" )),
    MagicSignature(
        0, "4d5a", "pe", "application/vnd.microsoft.portable-executable", (".exe", ".dll")
    ),
    MagicSignature(0, "cafebabe", "mach-o", "application/x-mach-binary", (".bin",)),
    MagicSignature(0, "feedface", "mach-o", "application/x-mach-binary", (".bin",)),
    MagicSignature(0, "7b5c727466", "rtf", "application/rtf", (".rtf",)),
    MagicSignature(0, "7b", "json", "application/json", (".json",)),
]

# OOXML / ODF are ZIP containers distinguished by embedded marker entries.
_OOXML_MARKER = b"[Content_Types].xml"
_ODF_MARKER = b"mimetype"


def detect(data: bytes) -> tuple[str | None, str | None]:
    """Return (display_type, mime) from magic bytes, or (None, None) if unknown."""
    best: MagicSignature | None = None
    for sig in _SIGS:
        needed = sig.offset + len(sig.hex_prefix) // 2
        if len(data) < needed:
            continue
        probe = data[sig.offset : needed]
        if probe.hex().startswith(sig.hex_prefix):
            if best is None or sig.offset + len(sig.hex_prefix) > best.offset + len(
                best.hex_prefix
            ):
                best = sig
    if best is None:
        return None, None

    # Disambiguate ZIP containers into OOXML / ODF when their markers are visible
    # in the sample (cheap find on raw bytes, no ZIP extraction).
    if best.display_type == "zip":
        if _OOXML_MARKER in data:
            return "ooxml", "application/vnd.openxmlformats-officedocument"
        if _ODF_MARKER in data:
            return "odf", "application/vnd.oasis.opendocument"
    return best.display_type, best.mime


def expected_for(display_type: str) -> tuple[str, ...]:
    """Expected filename extensions for a detected type (used for mismatch logic)."""
    for sig in _SIGS:
        if sig.display_type == display_type:
            return sig.extensions
    return ()

def extension_of(filename: str) -> str:
    return "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""


# Extension -> acceptable detected types. OOXML/ODF are ZIP containers, so their
# extensions legitimately accept both the concrete type and "zip". This is the
# basis for the file_type_mismatch finding.
_EXT_ACCEPT: dict[str, tuple[str, ...]] = {
    ".pdf": ("pdf",),
    ".docx": ("ooxml", "zip"),
    ".xlsx": ("ooxml", "zip"),
    ".pptx": ("ooxml", "zip"),
    ".docm": ("ooxml", "zip"),
    ".odt": ("odf", "zip"),
    ".ods": ("odf", "zip"),
    ".odp": ("odf", "zip"),
    ".doc": ("ole2",),
    ".xls": ("ole2",),
    ".ppt": ("ole2",),
    ".zip": ("zip", "ooxml", "odf"),
    ".7z": ("7z",),
    ".rar": ("rar",),
    ".gz": ("gzip",),
    ".tgz": ("gzip",),
    ".bz2": ("bzip2",),
    ".xz": ("xz",),
    ".png": ("png",),
    ".jpg": ("jpeg",),
    ".jpeg": ("jpeg",),
    ".gif": ("gif",),
    ".bmp": ("bmp",),
    ".webp": ("webp",),
    ".tif": ("tiff",),
    ".tiff": ("tiff",),
    ".rtf": ("rtf",),
    ".json": ("json",),
}


def type_mismatch(extension: str, detected_type: str | None) -> bool:
    """True if the filename extension implies a type different from the detected one."""
    if detected_type is None:
        return False
    acceptable = _EXT_ACCEPT.get(extension)
    if acceptable is None:
        return False
    return detected_type not in acceptable

