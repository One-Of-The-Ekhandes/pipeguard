"""Optional .pipeguard.yml configuration at the root of the scanned repository.

Example:
    fail_on: high          # info | low | medium | high | critical
    exclude:
      - "tests/fixtures/**"
    disable:
      - PG-DKR-008
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .models import Severity

CONFIG_NAMES = (".pipeguard.yml", ".pipeguard.yaml")


@dataclass
class Config:
    fail_on: Severity = Severity.HIGH
    exclude: list[str] = field(default_factory=list)
    disable: set[str] = field(default_factory=set)


def load(root: str | Path) -> Config:
    root = Path(root)
    base = root if root.is_dir() else root.parent
    for name in CONFIG_NAMES:
        path = base / name
        if path.is_file():
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            if not isinstance(data, dict):
                raise ValueError(f"{path} must contain a mapping")
            return Config(
                fail_on=Severity.parse(str(data.get("fail_on", "high"))),
                exclude=[str(x) for x in data.get("exclude") or []],
                disable={str(x).upper() for x in data.get("disable") or []},
            )
    return Config()
