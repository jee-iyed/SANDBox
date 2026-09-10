"""QR analyzer unit coverage that needs no native QR decoder."""
import tempfile
from pathlib import Path
from types import SimpleNamespace
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.analyzers.qr.analyzer import QRAnalyzer
from app.core.config import settings


def test_non_pdf_is_skipped_without_loading_decoders():
    with tempfile.TemporaryDirectory() as directory:
        original = settings.storage_dir
        try:
            settings.storage_dir = Path(directory)
            settings.uploads_dir.mkdir(parents=True, exist_ok=True)
            sha = "a" * 64
            (settings.uploads_dir / f"{sha}.bin").write_bytes(b"plain text")
            scan = SimpleNamespace(file=SimpleNamespace(sha256=sha))
            analyzer = QRAnalyzer()
            assert analyzer.analyze(None, scan) == []
            assert analyzer.get_payload()["status"] == "skipped"
            assert analyzer.get_payload()["reason"] == "not_a_pdf"
        finally:
            settings.storage_dir = original


if __name__ == "__main__":
    test_non_pdf_is_skipped_without_loading_decoders()
    print("QR ANALYZER TESTS PASSED")
