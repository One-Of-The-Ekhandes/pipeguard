from helpers import findings, ids

GOOD = """
FROM python:3.12-slim@sha256:1111111111111111111111111111111111111111111111111111111111111111 AS build
RUN pip wheel -w /wheels requests
FROM python:3.12-slim
COPY --from=build /wheels /wheels
RUN useradd -r app
USER app
HEALTHCHECK CMD python -c "print('ok')"
"""


def test_clean_dockerfile():
    assert ids("dockerfile", GOOD) == []


def test_root_and_latest_and_no_healthcheck():
    df = "FROM ubuntu\nRUN apt-get update\n"
    assert ids("dockerfile", df) == ["PG-DKR-001", "PG-DKR-002", "PG-DKR-008"]
    assert "PG-DKR-001" in ids("dockerfile", "FROM node:20\nUSER root\nHEALTHCHECK CMD true\n")


def test_stage_reference_and_scratch_are_not_unpinned():
    df = "FROM golang:1.23 AS builder\nFROM builder\nFROM scratch\nUSER 1000\nHEALTHCHECK NONE\n"
    assert "PG-DKR-002" not in ids("dockerfile", df)


def test_pipe_to_shell_with_continuation_reports_first_line():
    df = "FROM alpine:3.20\nRUN apk add curl && \\\n    curl -fsSL https://x.sh/install | sh\nUSER app\nHEALTHCHECK CMD true\n"
    fs = [f for f in findings("dockerfile", df) if f.rule.id == "PG-DKR-003"]
    assert fs and fs[0].line == 2


def test_secrets_in_env_and_arg():
    df = ("FROM alpine:3.20\nARG NPM_TOKEN\nENV DB_PASSWORD=hunter2 APP_PORT=8080\nENV API_KEY abc\n"
          "ENV LOG_LEVEL=info\nUSER app\nHEALTHCHECK CMD true\n")
    fs = [f for f in findings("dockerfile", df) if f.rule.id == "PG-DKR-004"]
    assert [f.line for f in fs] == [2, 3, 4]


def test_add_url_chmod_ssh():
    df = ("FROM alpine:3.20\nADD https://example.com/tool.tgz /opt/\n"
          "ADD --checksum=sha256:abc https://example.com/ok.tgz /opt/\nRUN chmod -R 777 /app\n"
          "EXPOSE 8080 22\nUSER app\nHEALTHCHECK CMD true\n")
    assert ids("dockerfile", df) == ["PG-DKR-005", "PG-DKR-006", "PG-DKR-007"]
