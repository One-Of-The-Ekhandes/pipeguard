from pipeguard.pin import pin_repo, pin_text
from pipeguard.scanner import scan

SHA = "11bd71901bbe5b1630ceea73d27597364c9af683"


def fake(repo, ref):
    assert repo in ("actions/checkout", "github/codeql-action")
    return SHA


def test_pin_text_rewrites_and_keeps_comments():
    text = ("steps:\n"
            "  - uses: actions/checkout@v4\n"
            "  - uses: 'github/codeql-action/upload-sarif@v3' # upload\n"
            f"  - uses: actions/checkout@{SHA} # v4.2.2\n"
            "  - uses: ./local\n")
    new, changes = pin_text(text, fake)
    lines = new.split("\n")
    assert lines[1] == f"  - uses: actions/checkout@{SHA} # v4"
    assert lines[2] == f"  - uses: 'github/codeql-action/upload-sarif@{SHA}' # upload"
    assert lines[3:] == text.split("\n")[3:]
    assert len(changes) == 2


def test_pin_repo_fixes_the_finding(tmp_path):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text("on: push\npermissions: {contents: read}\njobs:\n  a:\n    runs-on: x\n"
                               "    steps:\n      - uses: actions/checkout@v4\n        with: {persist-credentials: false}\n")
    assert [f.rule.id for f in scan(tmp_path).findings] == ["PG-GHA-001"]
    assert pin_repo(tmp_path, fake, dry_run=True) and "@v4" in (wf / "ci.yml").read_text()
    pin_repo(tmp_path, fake)
    assert scan(tmp_path).findings == []
