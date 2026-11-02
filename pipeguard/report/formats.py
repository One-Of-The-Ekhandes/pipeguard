"""Machine-readable and Markdown reports."""
from __future__ import annotations

import hashlib
import json

from .. import __version__
from ..models import Severity
from ..registry import RULES
from ..scoring import grade, score

REPO_URL = "https://github.com/One-Of-The-Ekhandes/pipeguard"
SARIF_LEVEL = {Severity.CRITICAL: "error", Severity.HIGH: "error", Severity.MEDIUM: "warning",
               Severity.LOW: "note", Severity.INFO: "note"}
# GitHub code scanning reads properties.security-severity (CVSS-like 0-10) to rank alerts.
SECURITY_SEVERITY = {Severity.CRITICAL: "9.5", Severity.HIGH: "8.0", Severity.MEDIUM: "5.5",
                     Severity.LOW: "3.0", Severity.INFO: "0.0"}


def _summary(result) -> dict:
    s = score(result.findings)
    return {"files_scanned": len(result.files), "findings": len(result.findings),
            "suppressed": len(result.suppressed), "score": s, "grade": grade(s),
            "by_severity": {str(sv): result.count(sv) for sv in sorted(Severity, reverse=True)}}


def to_json(result) -> str:
    return json.dumps({"tool": "pipeguard", "version": __version__, "summary": _summary(result),
                       "findings": [f.to_dict() for f in result.findings]}, indent=2)


def to_sarif(result) -> str:
    rules = sorted(RULES.values(), key=lambda r: r.id)
    index = {r.id: i for i, r in enumerate(rules)}
    sarif_rules = [{
        "id": r.id,
        "name": r.title.title().replace(" ", ""),
        "shortDescription": {"text": r.title},
        "fullDescription": {"text": r.description},
        "help": {"text": f"{r.description}\n\nFix: {r.fix}",
                 "markdown": f"{r.description}\n\n**Fix:** {r.fix}"
                             + "".join(f"\n\n- {ref}" for ref in r.references)},
        "helpUri": f"{REPO_URL}/blob/main/docs/rules.md#{r.id.lower()}",
        "defaultConfiguration": {"level": SARIF_LEVEL[r.severity]},
        "properties": {"security-severity": SECURITY_SEVERITY[r.severity],
                       "tags": ["security", "ci-cd", r.target]},
    } for r in rules]
    results = []
    for f in result.findings:
        fp = hashlib.sha256(f"{f.rule.id}|{f.path}|{f.snippet}".encode()).hexdigest()[:32]
        results.append({
            "ruleId": f.rule.id, "ruleIndex": index[f.rule.id], "level": SARIF_LEVEL[f.severity],
            "message": {"text": f"{f.message} Fix: {f.rule.fix}"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.path},
                                                "region": {"startLine": f.line}}}],
            "partialFingerprints": {"pipeguardFinding/v1": fp},
        })
    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "PipeGuard", "version": __version__,
                                      "informationUri": REPO_URL, "rules": sarif_rules}},
                  "results": results}],
    }, indent=2)


def to_markdown(result) -> str:
    s = _summary(result)
    icon = {"critical": "🟥", "high": "🟧", "medium": "🟨", "low": "🟦", "info": "⬜"}
    lines = [f"## PipeGuard: {s['score']}/100 (grade {s['grade']})", "",
             f"{s['files_scanned']} files scanned, {s['findings']} findings"
             + (f", {s['suppressed']} suppressed" if s["suppressed"] else "") + ".", ""]
    if result.findings:
        lines += ["| Severity | Rule | Location | Finding |", "|---|---|---|---|"]
        for f in result.findings:
            msg = f.message.replace("|", "\\|")
            lines.append(f"| {icon[str(f.severity)]} {f.severity} | `{f.rule.id}` {f.rule.title} | "
                         f"`{f.path}:{f.line}` | {msg} |")
    else:
        lines.append("No issues found.")
    return "\n".join(lines) + "\n"
