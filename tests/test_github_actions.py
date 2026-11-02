from helpers import findings, ids

GOOD = """
name: ci
on: [push]
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with:
          persist-credentials: false
      - run: make test
"""


def test_clean_workflow_has_no_findings():
    assert ids("github_actions", GOOD) == []


def test_unpinned_actions_and_line_numbers():
    wf = """
on: push
permissions: {contents: read}
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-python@v5
      - uses: actions/setup-python@v5
      - uses: ./local-action
      - uses: docker://alpine@sha256:aaaa
  b:
    uses: org/repo/.github/workflows/x.yml@main
"""
    fs = [f for f in findings("github_actions", wf) if f.rule.id == "PG-GHA-001"]
    assert [f.line for f in fs] == [7, 8, 12]
    assert "main" in fs[2].message


def test_pwn_request_is_critical():
    wf = """
on: pull_request_target
permissions: {contents: read}
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
        with:
          ref: ${{ github.event.pull_request.head.sha }}
          persist-credentials: false
      - run: npm install && npm test
"""
    fs = findings("github_actions", wf)
    pwn = [f for f in fs if f.rule.id == "PG-GHA-002"]
    assert pwn and pwn[0].line == 9 and str(pwn[0].severity) == "critical"


def test_script_injection_in_run_and_github_script():
    wf = """
on: issues
permissions: {contents: read}
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - run: |
          echo "New issue"
          echo "${{ github.event.issue.title }}"
      - run: echo "${{ github.event.issue.number }}"
      - uses: actions/github-script@60a0d83039c74a4aee543508d2ffcb1c3799cdea
        with:
          script: console.log("${{ github.event.comment.body }}")
"""
    fs = [f for f in findings("github_actions", wf) if f.rule.id == "PG-GHA-003"]
    assert [f.line for f in fs] == [9, 13]  # issue.number is not attacker-controlled text


def test_permissions_rules():
    assert "PG-GHA-004" in ids("github_actions", "on: push\npermissions: write-all\njobs:\n  a:\n    runs-on: x\n")
    assert "PG-GHA-005" in ids("github_actions", "on: push\njobs:\n  a:\n    runs-on: x\n")
    per_job = "on: push\njobs:\n  a:\n    runs-on: x\n    permissions: {contents: read}\n"
    assert "PG-GHA-005" not in ids("github_actions", per_job)


def test_secret_echo_pipe_to_shell_unsecure_commands_inherit():
    wf = """
on: push
permissions: {contents: read}
env:
  ACTIONS_ALLOW_UNSECURE_COMMANDS: true
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo ${{ secrets.DEPLOY_TOKEN }}
      - run: curl -sSL https://get.example.com/install | bash
  b:
    uses: org/repo/.github/workflows/deploy.yml@11bd71901bbe5b1630ceea73d27597364c9af683
    secrets: inherit
"""
    found = ids("github_actions", wf)
    for rid in ("PG-GHA-006", "PG-GHA-007", "PG-GHA-009", "PG-GHA-011"):
        assert rid in found, rid


def test_self_hosted_runner_on_pull_request():
    wf = "on: pull_request\npermissions: {contents: read}\njobs:\n  a:\n    runs-on: [self-hosted, linux]\n"
    assert "PG-GHA-010" in ids("github_actions", wf)
    assert "PG-GHA-010" not in ids("github_actions", wf.replace("pull_request", "push"))


def test_checkout_persist_credentials():
    wf = "on: push\npermissions: {contents: read}\njobs:\n  a:\n    runs-on: x\n    steps:\n" \
         "      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n"
    assert ids("github_actions", wf) == ["PG-GHA-008"]


def test_invalid_yaml_is_ignored():
    assert ids("github_actions", "on: [push\njobs: :::") == []
