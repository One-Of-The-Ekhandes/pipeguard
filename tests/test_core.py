from pipeguard.discovery import classify, discover
from pipeguard.models import Severity
from pipeguard.scoring import grade, score


def test_classify():
    assert classify(".github/workflows/ci.yml") == "github_actions"
    assert classify("Jenkinsfile") == "jenkins"
    assert classify("ci/build.jenkinsfile") == "jenkins"
    assert classify("docker/Dockerfile.prod") == "dockerfile"
    assert classify("infra/main.tf") == "terraform"
    assert classify("README.md") == "other"
    assert classify("workflows/ci.yml") == "other"


def test_discover_skips_git_and_binary(tmp_path):
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "Jenkinsfile").write_text("x")
    (tmp_path / "Dockerfile").write_text("FROM python:3.12\n")
    (tmp_path / "img.bin").write_bytes(b"\x00\x01")
    files = discover(tmp_path, include_other=True)
    assert [f.path for f in files] == ["Dockerfile"]


def test_severity_parse():
    assert Severity.parse("High") is Severity.HIGH


def test_score_and_grade():
    assert score([]) == 100 and grade(100) == "A"
    assert grade(59) == "D" and grade(10) == "F"


def test_code_files_named_like_pipelines_are_not_pipelines():
    assert classify("pipeguard/rules/dockerfile.py") == "other"
    assert classify("docs/jenkinsfile.md") == "other"
    assert classify("Jenkinsfile.example") == "jenkins"
    assert classify(".github/workflows/release.yaml") == "github_actions"
