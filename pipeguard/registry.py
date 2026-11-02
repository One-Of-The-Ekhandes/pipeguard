"""Rule registry. Each check is a function that takes a SourceFile and yields Findings."""
from __future__ import annotations

from typing import Callable, Iterable, Iterator

from .models import Finding, Rule, Severity, SourceFile

Check = Callable[[SourceFile], Iterable[Finding]]

RULES: dict[str, Rule] = {}
CHECKS: list[tuple[Rule, Check]] = []


def rule(id: str, title: str, severity: Severity, target: str, description: str, fix: str,
         references: tuple[str, ...] = ()) -> Callable[[Check], Check]:
    """Register a check function under a rule definition."""
    def decorator(fn: Check) -> Check:
        if id in RULES:
            raise ValueError(f"Duplicate rule id {id}")
        r = Rule(id, title, severity, target, description, fix, references)
        RULES[id] = r
        CHECKS.append((r, fn))
        fn.rule = r  # type: ignore[attr-defined]
        return fn
    return decorator


def run_checks(source: SourceFile) -> Iterator[Finding]:
    for r, check in CHECKS:
        if r.target in (source.kind, "any"):
            yield from check(source)


def finding(fn: Check, source: SourceFile, line: int, message: str) -> Finding:
    """Helper used inside checks: build a Finding for the rule attached to fn."""
    return Finding(fn.rule, source.path, line, message, source.line_text(line))  # type: ignore[attr-defined]
