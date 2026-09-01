# Sandboxed gosec image for VulnForge's Docker scanning mode.
# Build: docker build -t vulnforge/gosec-sandbox:2.20.0 -f docker/sandbox/gosec.Dockerfile docker/sandbox
#
# Multi-stage: gosec is built with the full Go toolchain, then only the
# resulting binary is copied into a minimal, non-root final image. The
# ENTRYPOINT is gosec itself (matching the official semgrep image's
# convention), so the analyzer invokes it as:
#   docker run <hardening flags> vulnforge/gosec-sandbox:2.20.0 <gosec args>
#
# Scanning a Go project also requires its module cache to resolve
# dependencies; the analyzer mounts the target read-only, so `go vet`-style
# analyses that only need the module's own source (as gosec does) work
# without further setup for vendored or already-cached modules.
FROM golang:1.24-alpine AS build
RUN go install github.com/securego/gosec/v2/cmd/gosec@v2.20.0

FROM alpine:3.20
RUN adduser -D -u 10001 scanner
COPY --from=build /go/bin/gosec /usr/local/bin/gosec
USER scanner
WORKDIR /workspace

ENTRYPOINT ["gosec"]
