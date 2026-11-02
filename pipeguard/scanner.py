"""Run every applicable rule over the discovered files."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from . import rules  # noqa: F401  (importing registers all rules)
from .discovery import discover
from .models import Finding, Severity, SourceFile
from .registry import run_checks

SUPPRESS_RE = re.compile(r"pipeguard:\s*ignore(?:[\s:=]+([A-Z0-9,\s-]+))?", re.I)


@dataclass
class ScanResult:
    files: list[SourceFile]
    findings: list[Finding]
    suppressed: list[Finding] = field(default_factory=list)

    def count(self, severity: Severity) -> int:
        return sum(1 for f in self.findings if f.severity == severity)


def _suppressed_ids(line: str) -> set[str] | None:
    """None = no suppression; empty set = suppress every rule; else the listed rule ids."""
    m = SUPPRESS_RE.search(line)
    if not m:
        return None
    if not m.group(1):
        return set()
    return {x.strip().upper() for x in re.split(r"[,\s]+", m.group(1)) if x.strip()}


def is_suppressed(f: Finding, source: SourceFile) -> bool:
    lines = source.lines
    for ln in (f.line, f.line - 1):
        if 0 < ln <= len(lines):
            ids = _suppressed_ids(lines[ln - 1])
            if ids is not None and (not ids or f.rule.id in ids):
                return True
    return False


def scan(root: str | Path, exclude: list[str] | None = None, disabled: set[str] | None = None,
         secrets_everywhere: bool = True) -> ScanResult:
    files = discover(root, exclude=exclude, include_other=secrets_everywhere)
    disabled = {d.upper() for d in (disabled or set())}
    findings, suppressed = [], []
    for source in files:
        for f in run_checks(source):
            if f.rule.id in disabled:
                continue
            (suppressed if is_suppressed(f, source) else findings).append(f)
    findings.sort(key=lambda f: (-f.severity, f.path, f.line, f.rule.id))
    return ScanResult(files, findings, suppressed)
