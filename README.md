# PipeGuard

[![CI](https://github.com/One-Of-The-Ekhandes/pipeguard/actions/workflows/ci.yml/badge.svg)](https://github.com/One-Of-The-Ekhandes/pipeguard/actions/workflows/ci.yml)

**A security scanner for CI/CD pipelines and infrastructure code.** One command checks your **Jenkinsfiles, GitHub Actions workflows, Dockerfiles and Terraform** for the misconfigurations attackers use to get into build systems, and tells you exactly how to fix each one.

```text
$ pipeguard scan examples/vulnerable

CRITICAL PG-GHA-002  .github/workflows/pr.yml:10
         Workflow triggered by pull_request_target checks out the pull request head.
         > ref: ${{ github.event.pull_request.head.sha }}
         fix: Use the pull_request trigger for building PR code. If you need pull_request_target, never check out
              or execute the PR's head; split the work into an unprivileged workflow plus a workflow_run step.

CRITICAL PG-JNK-003  Jenkinsfile:4
         'NEXUS_PASSWORD' is assigned a literal secret value.
         > NEXUS_PASSWORD = 'Nexus#2024!'
         fix: Store it in the Jenkins credentials store and load it with credentials('id') or withCredentials.
...
PipeGuard: 4 files scanned, 33 findings (5 critical, 12 high, 12 medium, 4 low)
Security score: 0/100 (grade F)
```

The same project after following the fixes ([`examples/hardened`](examples/hardened)) scores **100/100 (grade A)**.

## Why

CI/CD systems hold the keys to everything: cloud credentials, signing keys and write access to production. Attackers know it. In March 2025 the popular `tj-actions/changed-files` action was compromised and its version tags were repointed to code that printed CI secrets into public build logs ([GHSA-mrrh-fwg8-r2c3](https://github.com/advisories/GHSA-mrrh-fwg8-r2c3)). Every repository that referenced it by tag ran the malicious version; repositories pinned to a commit SHA did not.

Good scanners exist for single formats, but pipelines mix several. Jenkinsfiles in particular are rarely checked at all. PipeGuard covers the four formats a typical DevOps team touches in one tool, with one report, one score and one place to configure it.

## What it checks

**42 rules** ([full list with explanations](docs/rules.md)):

| Area | Rules | Examples |
|---|---|---|
| **GitHub Actions** | 11 | actions not pinned to a commit SHA, `pull_request_target` "pwn requests", script injection from issue/PR titles, `write-all` token permissions, secrets echoed to logs, self-hosted runners on PRs |
| **Jenkinsfile** | 10 | credentials interpolated into `sh` by Groovy, command injection from build parameters and branch names, hardcoded secrets, privileged agents and Docker socket mounts, approval gates anyone can approve |
| **Dockerfile** | 8 | running as root, unpinned base images, `curl \| sh`, secrets in `ENV`/`ARG`, `ADD` from URLs without checksums, `chmod 777` |
| **Terraform (AWS)** | 8 | SSH/RDP open to `0.0.0.0/0`, public S3 buckets, `Action "*"` IAM policies, provider access keys, public databases, IMDSv1 |
| **Secrets (all files)** | 5 | AWS access keys, private keys, GitHub and Slack tokens, passwords in URLs |

Every rule explains **why it matters** and **how to fix it**, with references to GitHub, Jenkins, Docker and AWS guidance.

## Quick start

```bash
pip install "git+https://github.com/One-Of-The-Ekhandes/pipeguard.git"

pipeguard scan .                                  # coloured terminal report
pipeguard scan . -f sarif -o pipeguard.sarif      # for GitHub code scanning
pipeguard scan . -f markdown                      # for PR comments
pipeguard scan . -f json                          # for dashboards and scripts
pipeguard scan . --fail-on medium                 # exit 1 on medium or worse (default: high)
pipeguard rules                                   # list all rules
```

### Fix unpinned actions automatically

```bash
pipeguard pin .            # uses: actions/checkout@v4  ->  uses: actions/checkout@11d5960a...677262 # v4
pipeguard pin . --dry-run  # show what would change
```

`pin` resolves each tag to its commit through the GitHub API (set `GITHUB_TOKEN` to raise the rate limit) and keeps the version as a comment so Dependabot and humans can still read it.

## Use it in your pipeline

**GitHub Actions**, with findings in the repository's Security tab:

```yaml
permissions:
  contents: read
  security-events: write
steps:
  - uses: actions/checkout@<sha> # v4
    with:
      persist-credentials: false
  - uses: One-Of-The-Ekhandes/pipeguard@<sha> # v0.1.0
    with:
      fail-on: high
  - uses: github/codeql-action/upload-sarif@<sha> # v3
    if: always()
    with:
      sarif_file: pipeguard.sarif
```

The action also writes a Markdown summary to the job page.

**Jenkins**, as a shared library step ([`jenkins/vars/pipeguardScan.groovy`](jenkins/vars/pipeguardScan.groovy)):

```groovy
@Library('pipeguard@v0.1.0') _
pipeline {
    agent { label 'linux' }
    options { timeout(time: 15, unit: 'MINUTES') }
    stages {
        stage('Pipeline security scan') {
            steps { pipeguardScan(path: '.', failOn: 'high') }
        }
    }
}
```

The step validates its inputs, passes them to the shell through `withEnv` (never Groovy interpolation), and archives SARIF and Markdown reports.

**pre-commit**:

```yaml
repos:
  - repo: https://github.com/One-Of-The-Ekhandes/pipeguard
    rev: v0.1.0
    hooks:
      - id: pipeguard
```

**Docker**:

```bash
docker build -t pipeguard .
docker run --rm -v "$PWD:/src:ro" pipeguard scan /src
```

## Configuration

Optional `.pipeguard.yml` at the repository root:

```yaml
fail_on: high
exclude:
  - "tests/fixtures/**"
disable:
  - PG-DKR-008
```

Suppress a single finding with a comment on the same line or the line above, ideally with a reason:

```dockerfile
# pipeguard:ignore PG-DKR-002 -- base image is pinned by our internal mirror
FROM registry.internal/python
```

## Security score

Each finding subtracts points (critical 25, high 10, medium 4, low 1) from 100, giving a grade from A to F. It is a simple way to track a repository's pipeline hygiene over time and to set a bar in CI.

## How it works

```text
pipeguard/
  discovery.py        find and classify files (workflows, Jenkinsfiles, Dockerfiles, .tf, other text)
  registry.py         @rule decorator: each rule is a small function with its metadata
  rules/
    github_actions.py YAML-based checks
    jenkins.py        line-level Groovy analysis with credential and quoting context
    dockerfile.py     instruction parser that understands continuations and multi-stage builds
    terraform.py      block parser with brace matching for resources and nested blocks
    secrets.py        credential patterns, run on every file
  scanner.py          runs rules, applies inline suppressions and config
  report/             text, JSON, SARIF 2.1.0 and Markdown
  pin.py              tag-to-SHA rewriting via the GitHub API
```

The only dependency is PyYAML.

**Dogfooding:** CI scans this repository with its own GitHub Action on every push, uploads the SARIF to the Security tab, builds the Docker image, and checks that the hardened example passes and the vulnerable one fails. The test suite has 51 tests, with at least one positive and one negative case per rule family.

## Limitations

- Jenkinsfile and Terraform checks are pattern-based, not full parsers or data-flow analysis. They catch the common forms of each problem; unusual formatting or values built across several variables can be missed.
- Terraform rules cover the AWS provider only.
- Secret detection uses patterns for well-known formats and skips obvious placeholders. It complements, and does not replace, GitHub secret scanning or tools like gitleaks.

## Roadmap

GitLab CI and Azure Pipelines support, Kubernetes manifests, auto-fix for more rules, and a baseline file so existing findings can be accepted while new ones fail the build.

## Built with

Python 3.10+, PyYAML, pytest and GitHub Actions. I built PipeGuard with Claude Code as an AI pair programmer, reviewing and testing every change.

## Author

Rujuta Ekhande · [LinkedIn](https://www.linkedin.com/in/rujuta-ekhande-93b257349) · [GitHub](https://github.com/One-Of-The-Ekhandes)

MIT License
