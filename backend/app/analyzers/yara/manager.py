"""Deterministic approved YARA ruleset loading."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import yara


@dataclass(frozen=True)
class RuleSource:
    path: Path
    category: str


class RuleSetManager:
    def __init__(self, manifest_path: Path | None = None) -> None:
        root = Path(__file__).resolve().parents[3] / "rules" / "yara"
        self.manifest_path = manifest_path or root / "manifest.json"
        self.root = self.manifest_path.parent
        self.manifest = json.loads(self.manifest_path.read_text(encoding="utf-8"))

    @property
    def revision(self) -> str:
        return str(self.manifest["revision"])

    @property
    def ruleset_version(self) -> str:
        return self.revision[:8]

    @property
    def analyzer_version(self) -> str:
        return f"yara:{yara.__version__}|ruleset:{self.ruleset_version}"

    def sources(self) -> list[RuleSource]:
        selected = self.manifest.get("selected_rules", [])
        if len(selected) > 32:
            raise ValueError("ruleset exceeds approved file limit")
        result = []
        root = self.root.resolve()
        for entry in selected:
            path = (self.root / entry["path"]).resolve()
            if root not in path.parents or path.suffix.lower() not in {".yar", ".yara"}:
                raise ValueError(f"invalid ruleset path: {entry['path']}")
            if not path.is_file():
                raise FileNotFoundError(path)
            result.append(RuleSource(path=path, category=str(entry["category"])))
        return result

    def compile(self) -> tuple[list[tuple[RuleSource, yara.Rules]], list[str]]:
        compiled = []
        errors = []
        for source in self.sources():
            try:
                compiled.append((source, yara.compile(filepath=str(source.path))))
            except yara.Error as exc:
                errors.append(f"{source.path.name}: {str(exc)[:300]}")
        return compiled, errors
