# Sandboxed scanner images

These images let the analyzer run a scanner inside a locked-down Docker
container — read-only mount of the scanned repository, no capabilities, no
privilege escalation, resource-limited, and (by default) no network access —
instead of directly on the host. See `internal/scanner/sandbox.go` for the
exact `docker run` flags applied, and the "Sandboxed scanning" section of the
top-level `README.md` for how to turn this on.

**Not verified against a real Docker daemon.** These Dockerfiles and the code
that invokes them were written and unit-tested without access to a Docker
engine. Build and run them yourself before relying on this in a real scan —
see "Verifying a new/changed image" below.

## Convention

Each image's `ENTRYPOINT` is the scanner binary itself (the same convention
the official `returntocorp/semgrep` image uses), so the analyzer always
invokes an image the same way: `docker run <hardening flags> <image> <tool args>`.
Do **not** set a `CMD`/entrypoint that requires an extra leading argument
naming the tool — the analyzer never passes one.

## Building the first-party images

```sh
docker build -t vulnforge/bandit-sandbox:1.7.9 -f docker/sandbox/bandit.Dockerfile docker/sandbox
docker build -t vulnforge/gosec-sandbox:2.20.0 -f docker/sandbox/gosec.Dockerfile docker/sandbox
docker build -t vulnforge/slither-sandbox:0.10.4 -f docker/sandbox/slither.Dockerfile docker/sandbox
```

semgrep needs no build step — `config/config.yaml`'s default `sandbox.images.semgrep`
points at the official `returntocorp/semgrep` image directly.

`slither.Dockerfile` is the most complex of the three first-party images (it
also installs Foundry, via the network, at build time, for `forge`) and is
correspondingly the least likely to be exactly right on the first try —
verify it especially carefully against a real Foundry project before relying
on it for anything.

### Scanners that write output to a file instead of stdout

Slither writes its results to a `--json <path>` file rather than stdout, so
its sandboxed run needs a *second* mount beyond the read-only source: a
small, dedicated, freshly created directory is bind-mounted read-write at
`/output` for that one run, and the `--json` argument is remapped to point
inside it. See `RunScannerSandboxedWithOutput` in `internal/scanner/sandbox.go`
and how `internal/scanner/slither.go` uses it — reuse this path (instead of
the plain `RunScannerSandboxed`) for any future scanner that writes its
report to a file (e.g. `dependency-check`'s `--out`) rather than stdout.

Then set `sandbox.enabled: true` in `config/config.yaml` (or
`ANALYZER_SANDBOX_ENABLED=true`) to start using them.

## Adding coverage for another scanner

The other scanners the analyzer supports (eslint, phpstan, psalm, spotbugs,
cargo-audit, brakeman, dependency-check, clang-analyzer, slither) run
unsandboxed on the host today — there is no image configured for them yet.
To sandbox one:

1. Write `docker/sandbox/<tool>.Dockerfile` following the same convention:
   non-root user, `ENTRYPOINT ["<tool>"]`, nothing else pre-set as `CMD`.
2. Build and tag it.
3. Add one line under `sandbox.images` in `config/config.yaml`:
   `<tool>: "<your-tag>"`.

No Go code changes are needed — `internal/scanner/common.go`'s `runWithEnv`
already checks `sandbox.images` for every scanner it runs.

Two of these need network access to fetch an advisory database at scan time
(`cargo-audit`, `dependency-check`); they're already listed under
`sandbox.network_allow` in the default config so they get `--network bridge`
instead of `--network none` even when sandboxed.

## Verifying a new/changed image

```sh
docker run --rm -v "$(pwd):/workspace:ro" -w /workspace vulnforge/bandit-sandbox:1.7.9 -r -f json .
docker run --rm -v "$(pwd):/workspace:ro" -w /workspace vulnforge/gosec-sandbox:2.20.0 -fmt=json ./...
docker run --rm -v "$(pwd):/workspace:ro" -w /workspace -v /tmp/slither-out:/output:rw \
  vulnforge/slither-sandbox:0.10.4 . --json /output/result.json
```

Confirm the output matches what the same tool produces when run directly on
the host against the same project, then run a real analyzer scan with
`sandbox.enabled: true` and confirm `docker ps -a` shows no leftover
containers afterward.
