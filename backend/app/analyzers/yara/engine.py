"""Safe YARA engine wrapper with bounded results and explicit failures."""

from __future__ import annotations

from dataclasses import dataclass

import yara

from app.analyzers.yara.manager import RuleSetManager, RuleSource


@dataclass(frozen=True)
class YaraMatch:
    rule: str
    namespace: str
    tags: list[str]
    meta: dict
    category: str
    strings: list[dict]


class YaraEngine:
    def __init__(self, manager: RuleSetManager | None = None, timeout_s: int = 5, max_matches: int = 100) -> None:
        self.manager = manager or RuleSetManager()
        self.timeout_s = timeout_s
        self.max_matches = max_matches
        self.compiled, self.compile_errors = self.manager.compile()

    @property
    def analyzer_version(self) -> str:
        return self.manager.analyzer_version

    def scan(self, data: bytes) -> tuple[list[YaraMatch], list[str]]:
        matches: list[YaraMatch] = []
        errors = list(self.compile_errors)
        for source, rules in self.compiled:
            if len(matches) >= self.max_matches:
                break
            try:
                raw_matches = rules.match(data=data, timeout=self.timeout_s)
                for match in raw_matches:
                    strings = []
                    for string_match in getattr(match, "strings", [])[:20]:
                        identifier = getattr(string_match, "identifier", None)
                        for instance in getattr(string_match, "instances", [])[:10]:
                            strings.append({
                                "identifier": identifier,
                                "offset": int(instance.offset),
                                "length": len(instance.matched_data),
                                "data": bytes(instance.matched_data[:64]).hex(),
                            })
                    matches.append(YaraMatch(
                        rule=match.rule,
                        namespace=match.namespace,
                        tags=list(match.tags)[:20],
                        meta=dict(match.meta),
                        category=source.category,
                        strings=strings[:20],
                    ))
                    if len(matches) >= self.max_matches:
                        break
            except yara.Error as exc:
                errors.append(f"{source.path.name}: {str(exc)[:300]}")
        return matches, errors
