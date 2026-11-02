"""Find the files PipeGuard knows how to scan and classify them."""
from __future__ import annotations

import fnmatch
import os
from pathlib import Path, PurePosixPath

from .models import SourceFile

SKIP_DIRS = {".git", ".venv", "venv", "node_modules", ".terraform", "__pycache__", ".tox", "dist", "build"}
MAX_BYTES = 1_000_000


# Files named like "dockerfile.py" or "jenkinsfile.md" are code or docs, not pipeline definitions.
NOT_PIPELINE_EXT = {".py", ".pyc", ".md", ".txt", ".json", ".yml", ".yaml", ".sh", ".js", ".ts", ".go", ".java",
                    ".html", ".rst", ".toml", ".cfg", ".ini", ".lock", ".sarif"}


def classify(rel_path: str) -> str:
    p = PurePosixPath(rel_path)
    name = p.name.lower()
    if p.suffix.lower() in NOT_PIPELINE_EXT and not (len(p.parts) >= 3 and p.parts[-3:-1] == (".github", "workflows")):
        return "other"
    parts = [x.lower() for x in p.parts]
    if p.suffix.lower() in (".yml", ".yaml") and len(parts) >= 3 and parts[-3:-1] == [".github", "workflows"]:
        return "github_actions"
    if name == "jenkinsfile" or name.startswith("jenkinsfile.") or name.endswith(".jenkinsfile"):
        return "jenkins"
    if name == "dockerfile" or name.startswith("dockerfile.") or name.endswith(".dockerfile"):
        return "dockerfile"
    if p.suffix.lower() == ".tf":
        return "terraform"
    return "other"


def discover(root: str | Path, exclude: list[str] | None = None, include_other: bool = False) -> list[SourceFile]:
    """Walk root and return scannable files. 'other' text files are included only for secret scanning."""
    root = Path(root)
    exclude = exclude or []
    if root.is_file():
        files = [(root, root.name)]
    else:
        files = []
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
            for fn in sorted(filenames):
                full = Path(dirpath) / fn
                rel = full.relative_to(root).as_posix()
                files.append((full, rel))

    out: list[SourceFile] = []
    for full, rel in files:
        if any(fnmatch.fnmatch(rel, pat) for pat in exclude):
            continue
        kind = classify(rel)
        if kind == "other" and not include_other:
            continue
        try:
            if full.stat().st_size > MAX_BYTES:
                continue
            raw = full.read_bytes()
        except OSError:
            continue
        if b"\x00" in raw[:4096]:  # binary
            continue
        text = raw.decode("utf-8", errors="replace").replace("\r\n", "\n")
        out.append(SourceFile(rel, kind, text))
    return out
