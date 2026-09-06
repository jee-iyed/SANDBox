"""Bounded normalized FileAnalysis payload used by M4 static analyzers."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class FileAnalysis:
    metadata: dict = field(default_factory=dict)
    hashes: dict = field(default_factory=dict)
    structure: dict = field(default_factory=dict)
    objects: list = field(default_factory=list)
    indicators: list = field(default_factory=list)
    features: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "metadata": self.metadata,
            "hashes": self.hashes,
            "structure": self.structure,
            "objects": self.objects[:100],
            "indicators": self.indicators[:100],
            "features": self.features,
        }
