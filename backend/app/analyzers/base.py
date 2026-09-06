from sqlalchemy.orm import Session

from app.db.models import Scan
from app.findings.schema import FindingSpec


class BaseAnalyzer:
    name: str = ""
    version: str = "0.0.0"

    def analyze(self, db: Session, scan: Scan) -> list[FindingSpec]:
        raise NotImplementedError


class AnalyzerError(RuntimeError):
    pass
