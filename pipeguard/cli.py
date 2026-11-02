"""Command line interface: pipeguard scan PATH | pipeguard rules"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from . import __version__
from . import config as cfg
from .models import Severity
from .registry import RULES
from .scanner import scan

FORMATS = ("text", "json", "sarif", "markdown")


def _render(result, fmt: str, colour: bool) -> str:
    from .report import formats, text
    if fmt == "text":
        return text.render(result, colour=colour)
    return {"json": formats.to_json, "sarif": formats.to_sarif, "markdown": formats.to_markdown}[fmt](result)


def _cmd_scan(args) -> int:
    conf = cfg.load(args.path)
    exclude = conf.exclude + args.exclude
    disabled = conf.disable | {d.upper() for d in args.disable}
    fail_on = Severity.parse(args.fail_on) if args.fail_on else conf.fail_on
    result = scan(args.path, exclude=exclude, disabled=disabled)

    colour = sys.stdout.isatty() and not args.no_color and "NO_COLOR" not in os.environ
    if args.output:
        Path(args.output).write_text(_render(result, args.format, False), encoding="utf-8")
        # Always show a short human summary on the console when writing a file.
        if args.format != "text":
            from .report import text
            print(text.render(result, colour=colour))
    else:
        print(_render(result, args.format, colour))

    # Optional GitHub Actions job summary.
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if args.github_summary and summary_path:
        from .report import formats
        with open(summary_path, "a", encoding="utf-8") as fh:
            fh.write(formats.to_markdown(result))

    return 1 if any(f.severity >= fail_on for f in result.findings) else 0


def _cmd_rules(args) -> int:
    for r in sorted(RULES.values(), key=lambda r: r.id):
        print(f"{r.id:<12} {str(r.severity):<9} {r.target:<15} {r.title}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="pipeguard", description="Security scanner for CI/CD pipelines and IaC.")
    ap.add_argument("--version", action="version", version=f"pipeguard {__version__}")
    sub = ap.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="scan a directory or file")
    s.add_argument("path", nargs="?", default=".")
    s.add_argument("-f", "--format", choices=FORMATS, default="text")
    s.add_argument("-o", "--output", help="write the report to a file")
    s.add_argument("--fail-on", help="exit 1 if any finding is at or above this severity (default: high)")
    s.add_argument("--exclude", action="append", default=[], help="glob of paths to skip (repeatable)")
    s.add_argument("--disable", action="append", default=[], help="rule id to disable (repeatable)")
    s.add_argument("--github-summary", action="store_true", help="append a Markdown report to $GITHUB_STEP_SUMMARY")
    s.add_argument("--no-color", action="store_true")
    s.set_defaults(func=_cmd_scan)

    r = sub.add_parser("rules", help="list all rules")
    r.set_defaults(func=_cmd_rules)
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except ValueError as exc:
        print(f"pipeguard: error: {exc}", file=sys.stderr)
        return 2
