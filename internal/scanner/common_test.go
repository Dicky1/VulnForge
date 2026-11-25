package scanner

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestRunFailsClosedWhenSandboxImageMissing(t *testing.T) {
	ConfigureSandbox(SandboxConfig{Enabled:true, Images: map[string]string{}})
	defer ConfigureSandbox(SandboxConfig{})
	_, err := run(context.Background(), time.Second, t.TempDir(), "echo", "unsafe")
	if err == nil || !strings.Contains(err.Error(), "no image configured") {
		t.Fatalf("expected fail-closed sandbox error, got %v", err)
	}
}
