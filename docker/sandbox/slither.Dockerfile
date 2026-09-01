# Sandboxed slither image for VulnForge's Docker scanning mode.
# Build: docker build -t vulnforge/slither-sandbox:0.10.4 -f docker/sandbox/slither.Dockerfile docker/sandbox
#
# This is the most complex of the sandbox images: Foundry-based Solidity
# projects need `forge` on PATH before Slither can compile and analyze them,
# so this image bundles Foundry too (installed to a shared, world-readable
# location so the non-root `scanner` user can run it). This has NOT been
# built or run against a real Foundry project in this environment — treat it
# as a starting point and verify it (see docker/sandbox/README.md) before
# relying on it.
FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl git ca-certificates build-essential \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir slither-analyzer==0.10.4

ENV FOUNDRY_DIR=/usr/local/foundry
ENV PATH="${FOUNDRY_DIR}/bin:${PATH}"
RUN curl -L https://foundry.paradigm.xyz | bash \
    && foundryup \
    && chmod -R a+rX "${FOUNDRY_DIR}"

RUN useradd --create-home --uid 10001 scanner
USER scanner
WORKDIR /workspace

ENTRYPOINT ["slither"]
