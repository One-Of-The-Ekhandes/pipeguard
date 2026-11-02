"""Dockerfile rules."""
from __future__ import annotations

import re
import shlex
from dataclasses import dataclass
from typing import Iterator

from ..models import Finding, Severity, SourceFile
from ..registry import finding, rule
from .common import PIPE_TO_SHELL, SECRET_NAME

DOCKER_DOCS = "https://docs.docker.com/build/building/best-practices/"


@dataclass
class Instruction:
    line: int
    cmd: str
    args: str


def parse(source: SourceFile) -> list[Instruction]:
    """Split a Dockerfile into instructions, joining backslash continuations and skipping comments."""
    out: list[Instruction] = []
    buf, start = "", 0
    for i, raw in enumerate(source.lines, start=1):
        line = raw.strip()
        if not buf and (not line or line.startswith("#")):
            continue
        if buf and line.startswith("#"):
            continue
        if not buf:
            start = i
        if line.endswith("\\"):
            buf += line[:-1] + " "
            continue
        buf += line
        parts = buf.split(None, 1)
        out.append(Instruction(start, parts[0].upper(), parts[1] if len(parts) > 1 else ""))
        buf = ""
    return out


def _stages(ins: list[Instruction]) -> list[list[Instruction]]:
    stages: list[list[Instruction]] = []
    for x in ins:
        if x.cmd == "FROM":
            stages.append([])
        if stages:
            stages[-1].append(x)
    return stages


@rule("PG-DKR-001", "Container runs as root", Severity.MEDIUM, "dockerfile",
      "Without a USER instruction the process runs as root. A container escape or a bug in the app "
      "then gives the attacker root on the container, and often more.",
      "Create an unprivileged user and switch to it in the final stage: RUN useradd -r app && USER app.",
      (DOCKER_DOCS,))
def runs_as_root(source: SourceFile) -> Iterator[Finding]:
    stages = _stages(parse(source))
    if not stages:
        return
    final = stages[-1]
    users = [x for x in final if x.cmd == "USER"]
    if not users:
        yield finding(runs_as_root, source, final[0].line, "The final stage has no USER instruction, so it runs as root.")
    elif users[-1].args.split(":")[0].strip() in ("root", "0"):
        yield finding(runs_as_root, source, users[-1].line, "The final USER is root.")


@rule("PG-DKR-002", "Base image not pinned", Severity.MEDIUM, "dockerfile",
      "A missing tag or :latest pulls whatever the image is today, so builds change silently and a "
      "compromised or broken upstream image goes straight into production.",
      "Pin a specific version, ideally with a digest: FROM python:3.12-slim@sha256:<digest>.",
      (DOCKER_DOCS,))
def unpinned_base(source: SourceFile) -> Iterator[Finding]:
    ins = parse(source)
    stage_names: set[str] = set()
    for x in ins:
        if x.cmd != "FROM":
            continue
        tokens = [t for t in x.args.split() if not t.startswith("--")]
        if not tokens:
            continue
        image = tokens[0]
        if len(tokens) >= 3 and tokens[1].lower() == "as":
            stage_names.add(tokens[2].lower())
        if image.lower() == "scratch" or image.lower() in stage_names or "@sha256:" in image or "$" in image:
            continue
        name_part = image.rsplit("/", 1)[-1]
        tag = name_part.split(":", 1)[1] if ":" in name_part else ""
        if tag in ("", "latest"):
            yield finding(unpinned_base, source, x.line,
                          f"Base image '{image}' uses {'the latest tag' if tag else 'no tag (latest)'}.")


@rule("PG-DKR-003", "Remote script piped to a shell during build", Severity.MEDIUM, "dockerfile",
      "curl ... | sh runs whatever the server returns at build time, with no integrity check, and bakes it into the image.",
      "Download the file, verify its checksum (sha256sum -c), then run it.")
def docker_pipe_to_shell(source: SourceFile) -> Iterator[Finding]:
    for x in parse(source):
        if x.cmd == "RUN" and PIPE_TO_SHELL.search(x.args):
            yield finding(docker_pipe_to_shell, source, x.line, "RUN pipes a downloaded script into a shell.")


@rule("PG-DKR-004", "Secret in ENV or ARG", Severity.HIGH, "dockerfile",
      "ENV values are stored in the image and ARG values appear in `docker history`, so anyone who can "
      "pull the image can read them.",
      "Use BuildKit secrets (RUN --mount=type=secret,id=token ...) at build time and inject runtime secrets "
      "from your orchestrator, not the image.",
      ("https://docs.docker.com/build/building/secrets/",))
def secret_in_env(source: SourceFile) -> Iterator[Finding]:
    for x in parse(source):
        if x.cmd not in ("ENV", "ARG"):
            continue
        try:
            tokens = shlex.split(x.args)
        except ValueError:
            tokens = x.args.split()
        # ENV key=value key2=value2 | ENV key value | ARG name[=default]
        pairs = [t.split("=", 1) for t in tokens] if "=" in x.args or x.cmd == "ARG" else [tokens[:1] + [" ".join(tokens[1:])]]
        for p in pairs:
            key, value = p[0], (p[1] if len(p) > 1 else "")
            if SECRET_NAME.search(key) and (x.cmd == "ARG" or value):
                yield finding(secret_in_env, source, x.line,
                              f"{x.cmd} '{key}' looks like a credential and will be visible in the image.")


@rule("PG-DKR-005", "ADD downloads from a URL", Severity.MEDIUM, "dockerfile",
      "ADD <url> fetches a remote file with no checksum, so a changed or compromised file is copied in silently.",
      "Use ADD --checksum=sha256:<hash> <url>, or RUN curl followed by sha256sum -c.",
      (DOCKER_DOCS,))
def add_url(source: SourceFile) -> Iterator[Finding]:
    for x in parse(source):
        if x.cmd == "ADD" and re.search(r"https?://", x.args) and "--checksum" not in x.args:
            yield finding(add_url, source, x.line, "ADD fetches a remote URL without --checksum.")


@rule("PG-DKR-006", "World-writable permissions", Severity.MEDIUM, "dockerfile",
      "chmod 777 lets any user or process in the container modify the files, including the app's own code.",
      "Give the minimum permissions needed, e.g. chmod 755 for directories and 644 for files, owned by the app user.")
def chmod_777(source: SourceFile) -> Iterator[Finding]:
    for x in parse(source):
        if x.cmd == "RUN" and re.search(r"\bchmod\s+(-R\s+)?0?777\b", x.args):
            yield finding(chmod_777, source, x.line, "RUN sets world-writable (777) permissions.")


@rule("PG-DKR-007", "SSH port exposed", Severity.MEDIUM, "dockerfile",
      "Running SSH inside a container adds an extra service, credentials and attack surface; containers "
      "should be accessed with docker exec or kubectl exec.",
      "Remove the SSH server and EXPOSE 22; debug with docker exec / kubectl exec instead.")
def ssh_exposed(source: SourceFile) -> Iterator[Finding]:
    for x in parse(source):
        if x.cmd == "EXPOSE" and re.search(r"(^|\s)22(/tcp)?(\s|$)", x.args):
            yield finding(ssh_exposed, source, x.line, "Port 22 (SSH) is exposed.")


@rule("PG-DKR-008", "No HEALTHCHECK", Severity.LOW, "dockerfile",
      "Without a health check the runtime cannot tell a hung container from a healthy one, so failures "
      "stay hidden until users notice.",
      "Add HEALTHCHECK CMD <command that fails when the app is unhealthy>, or define a probe in your orchestrator.",
      (DOCKER_DOCS,))
def no_healthcheck(source: SourceFile) -> Iterator[Finding]:
    stages = _stages(parse(source))
    if stages and not any(x.cmd == "HEALTHCHECK" for x in stages[-1]):
        yield finding(no_healthcheck, source, stages[-1][0].line, "The final stage defines no HEALTHCHECK.")
