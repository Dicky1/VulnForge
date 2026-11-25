package scanner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

func TestScannerHelperProcess(t *testing.T) {
	if os.Getenv("VULNFORGE_TEST_CHILD") != "1" {
		return
	}
	fmt.Fprintln(os.Stdout, `{"findings":[]}`)
	fmt.Fprintln(os.Stderr, "fixture diagnostic")
	os.Exit(3)
}

func TestScannerSeparatesJSONFromStderr(t *testing.T) {
	ConfigureSandbox(SandboxConfig{})
	r, err := runWithEnv(context.Background(), 0, t.TempDir(), []string{"VULNFORGE_TEST_CHILD=1"}, os.Args[0], "-test.run=^TestScannerHelperProcess$")
	if err != nil || r.exitCode != 3 {
		t.Fatalf("exit=%d err=%v", r.exitCode, err)
	}
	if !json.Valid(r.data) {
		t.Fatalf("stdout is not JSON: %q", r.data)
	}
	if !strings.Contains(string(r.stderr), "fixture diagnostic") || !strings.Contains(string(r.combined()), "fixture diagnostic") {
		t.Fatal("stderr diagnostic lost")
	}
}
func TestScannerCanceledContext(t *testing.T) {
	ConfigureSandbox(SandboxConfig{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r, err := run(ctx, time.Second, t.TempDir(), os.Args[0], "-test.run=^TestScannerHelperProcess$")
	if !errors.Is(err, context.Canceled) || r.exitCode != -1 {
		t.Fatalf("exit=%d err=%v", r.exitCode, err)
	}
}
func TestProcessIsolationRemainsFailClosed(t *testing.T) {
	ConfigureSandbox(SandboxConfig{Enabled: true, Images: map[string]string{"fixture": "fixture-image"}})
	defer ConfigureSandbox(SandboxConfig{})
	unavailable := false
	SetDockerReadyOverrideForTests(&unavailable)
	defer SetDockerReadyOverrideForTests(nil)
	_, err := run(context.Background(), time.Second, t.TempDir(), "fixture")
	if err == nil || !strings.Contains(err.Error(), "Docker unavailable") {
		t.Fatalf("expected fail-closed error, got %v", err)
	}
}

func TestLimitedOutputBoundsMemory(t *testing.T) {
	b := limitedOutput{limit: 4}
	if n, err := b.Write([]byte("12345678")); n != 8 || err != nil || b.String() != "1234" || !b.truncated {
		t.Fatalf("unexpected capture: %d %v %q", n, err, b.String())
	}
}

func TestLimitedOutputCannotBeBypassedByIOCopy(t *testing.T) {
	b := limitedOutput{limit: 4}
	n, err := io.Copy(&b, io.LimitReader(strings.NewReader("12345678"), 8))
	if n != 8 || err != nil || b.String() != "1234" || !b.truncated {
		t.Fatalf("unexpected copy: %d %v %q", n, err, b.String())
	}
}

func TestHostInstallBlockedInSandboxMode(t *testing.T) {
	ConfigureSandbox(SandboxConfig{Enabled: true})
	defer ConfigureSandbox(SandboxConfig{})
	err := installCommand(context.Background(), "nonexistent-test-binary")
	if err == nil || !strings.Contains(err.Error(), "host auto-install disabled") {
		t.Fatalf("unexpected: %v", err)
	}
}
