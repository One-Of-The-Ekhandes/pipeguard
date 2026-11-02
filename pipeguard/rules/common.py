"""Patterns and helpers shared by several rule packs."""
from __future__ import annotations

import re

from ..models import SourceFile

# curl/wget output piped straight into a shell: runs whatever the server returns.
PIPE_TO_SHELL = re.compile(r"\b(curl|wget)\b[^|\n]*\|\s*(sudo\s+)?(ba|z|da|k)?sh\b")

# Names that usually hold credentials.
SECRET_NAME = re.compile(r"(passw(or)?d|secret|token|api[_-]?key|private[_-]?key|access[_-]?key|credential)", re.I)


class LineCursor:
    """Finds line numbers for repeated snippets in order, so the 2nd identical 'uses:' gets the 2nd line."""

    def __init__(self, source: SourceFile):
        self.source = source
        self.next_start: dict[str, int] = {}

    def find(self, needle: str) -> int:
        start = self.next_start.get(needle, 1)
        line = self.source.line_of(needle, start)
        if needle not in self.source.line_text(line):  # not found after start: fall back to first match
            line = self.source.line_of(needle, 1)
        self.next_start[needle] = line + 1
        return line
