package scanner

import (
	"context"
	"reflect"
	"testing"
	"time"
)

func TestRemapArgsReplacesExactHostPath(t *testing.T) {
	got := remapArgs("/host/target", []string{"-r", "-f", "json", "/host/target"})
	want := []string{"-r", "-f", "json", "/workspace"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestRemapArgsLeavesUnrelatedArgsAlone(t *testing.T) {
	got := remapArgs("/host/target", []string{"--config=p/security-audit", "--json"})
	want := []string{"--config=p/security-audit", "--json"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

// These fallback paths must never attempt to shell out to docker, so they
// stay deterministic in CI environments without Docker installed.

func TestRunScannerSandboxedFallsBackWhenDisabled(t *testing.T) {
	ConfigureSandbox(SandboxConfig{})
	defer ConfigureSandbox(SandboxConfig{})
	_, ranSandboxed, err := RunScannerSandboxed(context.Background(), time.Second, "/target", nil, "bandit", "-r", "/target")
	if ranSandboxed || err != nil {
		t.Fatalf("expected a clean fallback signal when sandboxing is disabled, got ranSandboxed=%v err=%v", ranSandboxed, err)
	}
}

func TestRunScannerSandboxedFallsBackWhenNoImageConfigured(t *testing.T) {
	ConfigureSandbox(SandboxConfig{Enabled: true, Images: map[string]string{"semgrep": "returntocorp/semgrep:1.78.0"}})
	defer ConfigureSandbox(SandboxConfig{})
	_, ranSandboxed, err := RunScannerSandboxed(context.Background(), time.Second, "/target", nil, "bandit", "-r", "/target")
	if ranSandboxed || err != nil {
		t.Fatalf("expected a clean fallback signal when no image is configured for the tool, got ranSandboxed=%v err=%v", ranSandboxed, err)
	}
}

func TestSandboxAvailableForRequiresEnabledAndImage(t *testing.T) {
	ConfigureSandbox(SandboxConfig{})
	if SandboxAvailableFor("semgrep") {
		t.Fatal("expected unavailable when sandboxing is disabled")
	}
	ConfigureSandbox(SandboxConfig{Enabled: true})
	defer ConfigureSandbox(SandboxConfig{})
	if SandboxAvailableFor("semgrep") {
		t.Fatal("expected unavailable when no image is configured, regardless of Docker presence")
	}
}

func TestRunScannerSandboxedWithOutputFallsBackWhenDisabled(t *testing.T) {
	ConfigureSandbox(SandboxConfig{})
	defer ConfigureSandbox(SandboxConfig{})
	_, ranSandboxed, err := RunScannerSandboxedWithOutput(context.Background(), time.Second, "/target", "/tmp/out/result.json", nil, "slither", ".", "--json", "/tmp/out/result.json")
	if ranSandboxed || err != nil {
		t.Fatalf("expected a clean fallback signal when sandboxing is disabled, got ranSandboxed=%v err=%v", ranSandboxed, err)
	}
}

func TestNetworkPolicyDefaultsToNoneAndHonorsAllowlist(t *testing.T) {
	ConfigureSandbox(SandboxConfig{NetworkAllow: map[string]bool{"cargo-audit": true}})
	defer ConfigureSandbox(SandboxConfig{})
	if got := networkPolicy("bandit"); got != "none" {
		t.Fatalf("expected default network policy \"none\", got %q", got)
	}
	if got := networkPolicy("cargo-audit"); got != "bridge" {
		t.Fatalf("expected the allowlisted tool to get network access, got %q", got)
	}
}
