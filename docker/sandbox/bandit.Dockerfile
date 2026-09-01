# Sandboxed bandit image for VulnForge's Docker scanning mode.
# Build: docker build -t vulnforge/bandit-sandbox:1.7.9 -f docker/sandbox/bandit.Dockerfile docker/sandbox
#
# The container runs as a non-root user and its ENTRYPOINT is bandit itself
# (matching the convention of the official semgrep image), so the analyzer
# invokes it as: docker run <hardening flags> vulnforge/bandit-sandbox:1.7.9 <bandit args>
FROM python:3.12-slim

RUN pip install --no-cache-dir bandit==1.7.9 \
    && useradd --create-home --uid 10001 scanner
USER scanner
WORKDIR /workspace

ENTRYPOINT ["bandit"]
