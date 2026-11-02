"""`pipeguard pin`: rewrite GitHub Actions `uses:` references to full commit SHAs.

    uses: actions/checkout@v4   ->   uses: actions/checkout@11bd719...683 # v4

Tags are resolved with the GitHub API (set GITHUB_TOKEN to raise the rate limit).
"""
from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from pathlib import Path
from typing import Callable

from .discovery import discover

USES_RE = re.compile(r"""^(?P<pre>\s*-?\s*uses:\s*['"]?)(?P<action>[\w.-]+/[\w.-]+(?:/[^@\s'"]*)?)@(?P<ref>[^\s'"#]+)(?P<post>['"]?)(?P<rest>.*)$""")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")

Resolver = Callable[[str, str], str]


def github_resolver(token: str | None = None) -> Resolver:
    token = token or os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    cache: dict[tuple[str, str], str] = {}

    def resolve(repo: str, ref: str) -> str:
        if (repo, ref) not in cache:
            req = urllib.request.Request(f"https://api.github.com/repos/{repo}/commits/{ref}",
                                         headers={"Accept": "application/vnd.github.sha", "User-Agent": "pipeguard"})
            if token:
                req.add_header("Authorization", f"Bearer {token}")
            try:
                with urllib.request.urlopen(req, timeout=20) as resp:
                    cache[(repo, ref)] = resp.read().decode().strip()
            except urllib.error.HTTPError as exc:
                raise RuntimeError(f"could not resolve {repo}@{ref}: HTTP {exc.code}") from exc
        return cache[(repo, ref)]
    return resolve


def pin_text(text: str, resolve: Resolver) -> tuple[str, list[str]]:
    """Return the rewritten text and a list of human-readable changes."""
    out, changes = [], []
    for line in text.split("\n"):
        m = USES_RE.match(line)
        if not m or m.group("action").startswith(".") or SHA_RE.match(m.group("ref")):
            out.append(line)
            continue
        action, ref = m.group("action"), m.group("ref")
        repo = "/".join(action.split("/")[:2])
        sha = resolve(repo, ref)
        rest = m.group("rest")
        comment = rest if "#" in rest else f"{rest} # {ref}"
        out.append(f"{m.group('pre')}{action}@{sha}{m.group('post')}{comment}")
        changes.append(f"{action}@{ref} -> {sha[:12]}")
    return "\n".join(out), changes


def pin_repo(root: str | Path, resolve: Resolver, dry_run: bool = False) -> dict[str, list[str]]:
    from .config import load
    root = Path(root)
    report: dict[str, list[str]] = {}
    for src in discover(root, exclude=load(root).exclude):
        if src.kind != "github_actions":
            continue
        new_text, changes = pin_text(src.text, resolve)
        if changes:
            report[src.path] = changes
            if not dry_run:
                target = root / src.path if root.is_dir() else root
                target.write_text(new_text, encoding="utf-8", newline="\n")
    return report
