"""Command line interface: pipeguard scan PATH | pipeguard rules"""
from __future__ import annotations

import argparse
import os
import sys

from . import __version__
from .models import Severity
from .registry import RULES
from .scanner import scan


def _cmd_scan(args) -> int:
    from .report import text
    result = scan(args.path, exclude=args.exclude, disabled=set(args.disable))
    colour = sys.stdout.isatty() and not args.no_color and "NO_COLOR" not in os.environ
    print(text.render(result, colour=colour))
    fail_on = Severity.parse(args.fail_on)
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
    s.add_argument("--fail-on", default="high", help="exit 1 if any finding is at or above this severity")
    s.add_argument("--exclude", action="append", default=[], help="glob of paths to skip (repeatable)")
    s.add_argument("--disable", action="append", default=[], help="rule id to disable (repeatable)")
    s.add_argument("--no-color", action="store_true")
    s.set_defaults(func=_cmd_scan)

    r = sub.add_parser("rules", help="list all rules")
    r.set_defaults(func=_cmd_rules)
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)
