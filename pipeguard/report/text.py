"""Human-readable terminal report."""
from __future__ import annotations

from ..models import Severity
from ..scoring import grade, score

COLOURS = {Severity.CRITICAL: "\033[1;31m", Severity.HIGH: "\033[31m", Severity.MEDIUM: "\033[33m",
           Severity.LOW: "\033[36m", Severity.INFO: "\033[37m"}
RESET, BOLD, DIM = "\033[0m", "\033[1m", "\033[2m"


def render(result, colour: bool = True) -> str:
    c = (lambda code, s: f"{code}{s}{RESET}") if colour else (lambda code, s: s)
    out = []
    for f in result.findings:
        sev = c(COLOURS[f.severity], f"{str(f.severity).upper():<8}")
        out.append(f"{sev} {c(BOLD, f.rule.id)}  {f.path}:{f.line}")
        out.append(f"         {f.message}")
        if f.snippet:
            out.append(c(DIM, f"         > {f.snippet[:120]}"))
        out.append(f"         fix: {f.rule.fix}")
        out.append("")
    s = score(result.findings)
    counts = ", ".join(f"{result.count(sv)} {sv}" for sv in sorted(Severity, reverse=True) if result.count(sv))
    out.append(c(BOLD, f"PipeGuard: {len(result.files)} files scanned, {len(result.findings)} findings"
                       + (f" ({counts})" if counts else "")
                       + (f", {len(result.suppressed)} suppressed" if result.suppressed else "")))
    out.append(c(BOLD, f"Security score: {s}/100 (grade {grade(s)})"))
    return "\n".join(out)
