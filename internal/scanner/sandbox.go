package scanner

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

// SandboxConfig controls whether — and how — scanner subprocesses run inside
// an isolated Docker container instead of directly on the host against the
// (untrusted) repository being scanned.
type SandboxConfig struct {
	Enabled        bool
	NetworkDefault string // "none" or "bridge"; empty means "none"
	Memory         string // docker --memory, e.g. "1g"
	CPUs           string // docker --cpus, e.g. "2"
	PIDsLimit      int
	Images         map[string]string // scanner binary name -> docker image ref
	NetworkAllow   map[string]bool   // tools that get network even when NetworkDefault=="none" (e.g. cargo-audit, dependency-check)
}

// sandbox is configured once, from main(), before any scanner goroutines
// start; reads from the goroutines it spawns afterward are safe without a
// mutex because each `go` statement happens-after this write.
var sandbox SandboxConfig

func ConfigureSandbox(cfg SandboxConfig) { sandbox = cfg }

var (
	dockerCheckOnce     sync.Once
	dockerIsReady       bool
	dockerReadyOverride *bool
)

// SetDockerReadyOverrideForTests forces dockerReady()'s result so tests can
// deterministically simulate Docker being available or unavailable without
// needing a real Docker daemon in the test environment. Pass nil to restore
// the real check. Test-only: production code must never call this.
func SetDockerReadyOverrideForTests(v *bool) { dockerReadyOverride = v }

// dockerReady reports whether a usable Docker daemon is reachable. The
// result is cached for the process lifetime — shelling out to `docker info`
// before every single scanner invocation would add needless latency.
func dockerReady() bool {
	if dockerReadyOverride != nil {
		return *dockerReadyOverride
	}
	dockerCheckOnce.Do(func() {
		if _, err := exec.LookPath("docker"); err != nil {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		dockerIsReady = exec.CommandContext(ctx, "docker", "info").Run() == nil
	})
	return dockerIsReady
}

// SandboxAvailableFor reports whether tool has a configured Docker image and
// a reachable daemon to run it in, i.e. whether the tool can be treated as
// available without being installed on the host at all.
func SandboxAvailableFor(tool string) bool {
	return sandbox.Enabled && sandbox.Images[tool] != "" && dockerReady()
}

// remapArgs replaces any argument that is an exact match for the host target
// directory with the container-internal mount point. Some scanners (bandit,
// semgrep) pass the target path both as the working directory and as a
// literal scan-path argument, so the argument needs remapping too.
func remapArgs(dir string, args []string) []string {
	out := make([]string, len(args))
	for i, a := range args {
		if a == dir {
			out[i] = "/workspace"
		} else {
			out[i] = a
		}
	}
	return out
}

func networkPolicy(tool string) string {
	if sandbox.NetworkAllow[tool] {
		return "bridge"
	}
	if sandbox.NetworkDefault != "" {
		return sandbox.NetworkDefault
	}
	return "none"
}

// hardenedDockerArgs returns the `docker run` flags common to every
// sandboxed invocation: auto-removed, resource-limited, no capabilities, no
// privilege escalation, and a read-only root filesystem with a small tmpfs
// for scratch space.
func hardenedDockerArgs(containerName, network string) []string {
	memory := sandbox.Memory
	if memory == "" {
		memory = "1g"
	}
	cpus := sandbox.CPUs
	if cpus == "" {
		cpus = "2"
	}
	pids := sandbox.PIDsLimit
	if pids <= 0 {
		pids = 256
	}
	return []string{
		"run", "--rm", "--name", containerName,
		"--network", network,
		"--memory", memory,
		"--cpus", cpus,
		"--pids-limit", strconv.Itoa(pids),
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges:true",
		"--read-only",
		"--tmpfs", "/tmp:rw,size=256m",
	}
}

// RunScannerSandboxed runs `name args...` inside the Docker image configured
// for that tool, with dir mounted read-only at /workspace so the tool can
// read but never modify the scanned repository. ranSandboxed is false, with
// a nil error, when sandboxing isn't enabled, no image is configured for
// this tool, or Docker isn't reachable — the caller must fall back to its
// own local execution in that case.
func RunScannerSandboxed(ctx context.Context, timeout time.Duration, dir string, env []string, name string, args ...string) (commandResult, bool, error) {
	return runScannerSandboxed(ctx, timeout, dir, "", env, name, args...)
}

// RunScannerSandboxedWithOutput behaves like RunScannerSandboxed, but for a
// tool that writes its results to a file rather than stdout (e.g. Slither's
// `--json <path>`). The directory containing outputHostPath is additionally
// bind-mounted read-write at /output, and any argument that exactly matches
// outputHostPath is remapped alongside dir. Callers should point
// outputHostPath at a small, dedicated directory created just for this run —
// not a shared temp root — since everything in that directory is exposed to
// the container.
func RunScannerSandboxedWithOutput(ctx context.Context, timeout time.Duration, dir, outputHostPath string, env []string, name string, args ...string) (commandResult, bool, error) {
	return runScannerSandboxed(ctx, timeout, dir, outputHostPath, env, name, args...)
}

func runScannerSandboxed(ctx context.Context, timeout time.Duration, dir, outputHostPath string, env []string, name string, args ...string) (commandResult, bool, error) {
	image, ok := sandbox.Images[name]
	if !sandbox.Enabled || !ok || !dockerReady() {
		return commandResult{}, false, nil
	}
	containerName := fmt.Sprintf("vulnforge-%s-%d", name, time.Now().UnixNano())
	dockerArgs := hardenedDockerArgs(containerName, networkPolicy(name))
	dockerArgs = append(dockerArgs, "-v", dir+":/workspace:ro", "-w", "/workspace")
	remapped := remapArgs(dir, args)
	if outputHostPath != "" {
		containerOutputPath := "/output/" + filepath.Base(outputHostPath)
		dockerArgs = append(dockerArgs, "-v", filepath.Dir(outputHostPath)+":/output:rw")
		for i, a := range remapped {
			if a == outputHostPath {
				remapped[i] = containerOutputPath
			}
		}
	}
	for _, e := range env {
		dockerArgs = append(dockerArgs, "-e", e)
	}
	dockerArgs = append(dockerArgs, image)
	dockerArgs = append(dockerArgs, remapped...)
	res, err := runDocker(ctx, timeout, containerName, dockerArgs)
	return res, true, err
}

func runDocker(ctx context.Context, timeout time.Duration, containerName string, dockerArgs []string) (commandResult, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", dockerArgs...)
	b, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		// --rm handles a normal exit, but a client process killed on timeout
		// can otherwise orphan a running container.
		_ = exec.Command("docker", "kill", containerName).Run()
	}
	return interpretExecResult(ctx, b, err)
}
