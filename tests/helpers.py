from pipeguard import rules  # noqa: F401  (register rules)
from pipeguard.models import SourceFile
from pipeguard.registry import run_checks


def ids(kind: str, text: str, path: str = "x") -> list[str]:
    """Rule ids found in a snippet, in order."""
    return [f.rule.id for f in run_checks(SourceFile(path, kind, text.lstrip("\n")))]


def findings(kind: str, text: str, path: str = "x"):
    return list(run_checks(SourceFile(path, kind, text.lstrip("\n"))))
