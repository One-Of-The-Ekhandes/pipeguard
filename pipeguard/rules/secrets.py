"""Leaked credential detectors that run on every scanned file."""
from __future__ import annotations

import re
from typing import Iterator

from ..models import Finding, Severity, SourceFile
from ..registry import finding, rule

ROTATE = "Remove it from the file, rotate the credential immediately (it is in Git history), and load it from a secrets manager."
PLACEHOLDER = re.compile(r"example|dummy|placeholder|your[_-]|xxxx|<[^>]+>|\*{3,}", re.I)


def _scan(fn, source: SourceFile, pattern: re.Pattern, message: str) -> Iterator[Finding]:
    for i, line in enumerate(source.lines, start=1):
        m = pattern.search(line)
        if m and not PLACEHOLDER.search(m.group(0)):
            yield finding(fn, source, i, message)


@rule("PG-SEC-001", "AWS access key ID committed", Severity.CRITICAL, "any",
      "AWS access keys in a repository are found by automated scanners within minutes and used to run up "
      "bills or steal data.", ROTATE,
      ("https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html",))
def aws_key(source: SourceFile) -> Iterator[Finding]:
    yield from _scan(aws_key, source, re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), "Looks like an AWS access key ID.")


@rule("PG-SEC-002", "Private key committed", Severity.CRITICAL, "any",
      "A private key in the repository lets anyone with read access impersonate the server, user or signing identity it belongs to.",
      ROTATE)
def private_key(source: SourceFile) -> Iterator[Finding]:
    yield from _scan(private_key, source,
                     re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY( BLOCK)?-----"),
                     "A private key block is committed.")


@rule("PG-SEC-003", "GitHub token committed", Severity.CRITICAL, "any",
      "A GitHub token gives access to repositories, packages and sometimes organisation settings with the owner's permissions.",
      ROTATE, ("https://docs.github.com/en/code-security/secret-scanning",))
def github_token(source: SourceFile) -> Iterator[Finding]:
    yield from _scan(github_token, source,
                     re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{60,})\b"),
                     "Looks like a GitHub token.")


@rule("PG-SEC-004", "Slack token or webhook committed", Severity.HIGH, "any",
      "Slack tokens and incoming webhooks let anyone post (or read) messages as your integration, which is "
      "useful for phishing your own staff.", ROTATE)
def slack_token(source: SourceFile) -> Iterator[Finding]:
    yield from _scan(slack_token, source,
                     re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}|https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"),
                     "Looks like a Slack token or webhook URL.")


@rule("PG-SEC-005", "Password embedded in a URL", Severity.HIGH, "any",
      "user:password@host URLs leak the password into logs, shell history, process lists and error messages.",
      "Use a credential helper or pass the password through a secret environment variable, never in the URL.")
def url_credentials(source: SourceFile) -> Iterator[Finding]:
    pattern = re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s:/@'\"]+:([^\s@'\"]+)@[^\s'\"]+", re.I)
    for i, line in enumerate(source.lines, start=1):
        for m in pattern.finditer(line):
            password = m.group(1)
            if password.startswith(("$", "%", "{")) or PLACEHOLDER.search(password) or password.lower() in ("password", "pass"):
                continue
            yield finding(url_credentials, source, i, "A URL contains a username and password.")
            break
