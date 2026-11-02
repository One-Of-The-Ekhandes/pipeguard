FROM python:3.12-slim

WORKDIR /opt/pipeguard
COPY pyproject.toml README.md ./
COPY pipeguard ./pipeguard
RUN pip install --no-cache-dir . \
    && useradd --create-home --uid 10001 scanner

USER scanner
WORKDIR /src
# A one-shot CLI has no long-running process to health-check.
HEALTHCHECK NONE
ENTRYPOINT ["pipeguard"]
CMD ["scan", "/src"]
