"""Core data types: severities, rules and findings."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> "Severity":
        try:
            return cls[value.strip().upper()]
        except KeyError as exc:
            raise ValueError(f"Unknown severity '{value}'. Use info, low, medium, high or critical.") from exc

    def __str__(self) -> str:
        return self.name.lower()


@dataclass(frozen=True)
class Rule:
    id: str            # e.g. PG-GHA-001
    title: str
    severity: Severity
    target: str        # github_actions | jenkins | dockerfile | terraform | any
    description: str   # why it matters
    fix: str           # how to fix it
    references: tuple[str, ...] = ()


@dataclass
class Finding:
    rule: Rule
    path: str
    line: int
    message: str
    snippet: str = ""
    extra: dict = field(default_factory=dict)

    @property
    def severity(self) -> Severity:
        return self.rule.severity

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule.id,
            "title": self.rule.title,
            "severity": str(self.rule.severity),
            "path": self.path,
            "line": self.line,
            "message": self.message,
            "snippet": self.snippet,
            "fix": self.rule.fix,
        }


@dataclass
class SourceFile:
    """A file to scan, with its detected type and text."""
    path: str          # path relative to the scan root, with forward slashes
    kind: str          # github_actions | jenkins | dockerfile | terraform | other
    text: str

    @property
    def lines(self) -> list[str]:
        return self.text.splitlines()

    def line_of(self, needle: str, start_line: int = 1) -> int:
        """1-based line number of the first line at or after start_line containing needle (1 if not found)."""
        for i, line in enumerate(self.lines[start_line - 1:], start=start_line):
            if needle in line:
                return i
        return max(start_line, 1)

    def line_text(self, line: int) -> str:
        lines = self.lines
        return lines[line - 1].strip() if 0 < line <= len(lines) else ""
