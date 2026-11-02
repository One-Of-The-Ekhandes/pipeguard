import json

from pipeguard.cli import main
from pipeguard.report import formats
from pipeguard.scanner import scan

DOCKERFILE = "FROM ubuntu\nRUN curl -fsSL https://x.sh/i | sh\n"


def _repo(tmp_path):
    (tmp_path / "Dockerfile").write_text(DOCKERFILE)
    return tmp_path


def test_json_report(tmp_path):
    data = json.loads(formats.to_json(scan(_repo(tmp_path))))
    assert data["summary"]["findings"] == 4
    assert data["summary"]["by_severity"]["medium"] == 3
    assert {f["rule_id"] for f in data["findings"]} >= {"PG-DKR-001", "PG-DKR-003"}


def test_sarif_report_structure(tmp_path):
    sarif = json.loads(formats.to_sarif(scan(_repo(tmp_path))))
    run = sarif["runs"][0]
    assert sarif["version"] == "2.1.0" and run["tool"]["driver"]["name"] == "PipeGuard"
    rule_ids = [r["id"] for r in run["tool"]["driver"]["rules"]]
    for res in run["results"]:
        assert rule_ids[res["ruleIndex"]] == res["ruleId"]
        assert res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "Dockerfile"
        assert res["partialFingerprints"]["pipeguardFinding/v1"]


def test_markdown_report(tmp_path):
    md = formats.to_markdown(scan(_repo(tmp_path)))
    assert md.startswith("## PipeGuard:") and "`PG-DKR-003`" in md


def test_inline_suppression(tmp_path):
    (tmp_path / "Dockerfile").write_text(
        "FROM ubuntu # pipeguard:ignore PG-DKR-002\n"
        "# pipeguard:ignore\n"
        "RUN curl -fsSL https://x.sh/i | sh\n")
    result = scan(tmp_path)
    assert {f.rule.id for f in result.suppressed} == {"PG-DKR-002", "PG-DKR-003"}
    assert "PG-DKR-002" not in {f.rule.id for f in result.findings}


def test_exit_codes_and_fail_on(tmp_path, capsys):
    repo = _repo(tmp_path)
    assert main(["scan", str(repo), "--no-color"]) == 0            # only medium/low findings; default fails on high
    assert main(["scan", str(repo), "--fail-on", "medium"]) == 1
    assert main(["scan", str(repo), "--fail-on", "nonsense"]) == 2


def test_config_file_and_output(tmp_path, capsys):
    repo = _repo(tmp_path)
    (repo / ".pipeguard.yml").write_text("fail_on: low\ndisable: [PG-DKR-008]\n")
    out = repo / "report.sarif"
    assert main(["scan", str(repo), "-f", "sarif", "-o", str(out)]) == 1
    ids = {r["ruleId"] for r in json.loads(out.read_text())["runs"][0]["results"]}
    assert "PG-DKR-008" not in ids and "PG-DKR-003" in ids
    assert "Security score" in capsys.readouterr().out


def test_github_step_summary(tmp_path, monkeypatch):
    repo = _repo(tmp_path)
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    main(["scan", str(repo), "--github-summary"])
    assert "PipeGuard:" in summary.read_text(encoding="utf-8")


def test_rules_command(capsys):
    assert main(["rules"]) == 0
    assert "PG-JNK-002" in capsys.readouterr().out
