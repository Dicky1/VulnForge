package agent

import (
	"context"
	"testing"

	"github.com/example/sast-dast-analyzer/internal/parser"
	"github.com/example/sast-dast-analyzer/internal/scanner"
)

// AutoInstallAndRun must never fall back to executing a README-derived
// install command on the host: when sandboxing isn't configured/available
// for the tool, it must refuse instead of running anything locally.
func TestAutoInstallAndRunRefusesWithoutSandbox(t *testing.T) {
	scanner.ConfigureSandbox(scanner.SandboxConfig{}) // sandboxing disabled
	a := &SetupAgent{AllowInstall: true}
	setups := map[string]*parser.ToolSetup{"semgrep": {Name: "semgrep", InstallCmds: []string{"pip install semgrep"}}}
	if err := a.AutoInstallAndRun(context.Background(), setups); err == nil {
		t.Fatal("expected AutoInstallAndRun to refuse when no sandbox is available, but it returned nil")
	}
}

func TestAutoInstallAndRunSkipsWhenSandboxed(t *testing.T) {
	scanner.ConfigureSandbox(scanner.SandboxConfig{Enabled: true, Images: map[string]string{"semgrep": "returntocorp/semgrep:1.78.0"}})
	defer scanner.ConfigureSandbox(scanner.SandboxConfig{})
	dockerReady := true
	scanner.SetDockerReadyOverrideForTests(&dockerReady) // this test environment has no real Docker daemon
	defer scanner.SetDockerReadyOverrideForTests(nil)
	a := &SetupAgent{AllowInstall: true}
	setups := map[string]*parser.ToolSetup{"semgrep": {Name: "semgrep", InstallCmds: []string{"pip install semgrep"}}}
	if err := a.AutoInstallAndRun(context.Background(), setups); err != nil {
		t.Fatalf("expected no error once the tool is covered by a sandboxed image, got %v", err)
	}
}

func TestAutoInstallAndRunStillRejectsUnsafeCommands(t *testing.T) {
	scanner.ConfigureSandbox(scanner.SandboxConfig{Enabled: true, Images: map[string]string{"semgrep": "returntocorp/semgrep:1.78.0"}})
	defer scanner.ConfigureSandbox(scanner.SandboxConfig{})
	a := &SetupAgent{AllowInstall: true}
	setups := map[string]*parser.ToolSetup{"semgrep": {Name: "semgrep", InstallCmds: []string{"pip install evil-package semgrep"}}}
	if err := a.AutoInstallAndRun(context.Background(), setups); err == nil {
		t.Fatal("expected the smuggled-package install line to still be rejected even with sandboxing available")
	}
}

func TestSafeInstallAcceptsExactKnownCommands(t *testing.T) {
	cases := []string{
		"pip install semgrep",
		"pip3 install semgrep==1.78.0",
		"pip install bandit",
		"pip install bandit[toml]==1.7.9",
		"go install github.com/securego/gosec/v2/cmd/gosec",
		"go install github.com/securego/gosec/v2/cmd/gosec@latest",
		"go install github.com/securego/gosec/v2/cmd/gosec@v2.20.0",
	}
	for _, line := range cases {
		if _, _, ok := safeInstall(line); !ok {
			t.Errorf("expected %q to be accepted", line)
		}
	}
}

// A malicious target repository's README is untrusted input. safeInstall must
// reject any line that tries to smuggle an extra, attacker-chosen package
// onto the same install invocation just because it also mentions a known tool.
func TestSafeInstallRejectsSmuggledPackages(t *testing.T) {
	cases := []string{
		"pip install evil-package semgrep",
		"pip install semgrep evil-package",
		"pip3 install --upgrade evil-package && curl evil.sh semgrep",
		"pip install semgrep; rm -rf /",
		"go install github.com/securego/gosec/v2/cmd/gosecmalicious@latest",
		"go install github.com/attacker/evil@latest github.com/securego/gosec/v2/cmd/gosec",
		"npm install semgrep",
		"pip install requests",
	}
	for _, line := range cases {
		if _, _, ok := safeInstall(line); ok {
			t.Errorf("expected %q to be rejected", line)
		}
	}
}
