package integrations

import (
	"os/exec"
	"path/filepath"
	"testing"
)

func TestDetectGitRepoDistinguishesBareAndWorktree(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git unavailable")
	}
	for _, bare := range []bool{false, true} {
		d := filepath.Join(t.TempDir(), "repo")
		args := []string{"init", "-q"}
		if bare {
			args = append(args, "--bare")
		}
		args = append(args, d)
		if b, err := exec.Command("git", args...).CombinedOutput(); err != nil {
			t.Fatalf("init: %s: %v", b, err)
		}
		if got := DetectGitRepo(d); got == bare {
			t.Errorf("bare=%v; detected worktree=%v", bare, got)
		}
	}
}
func TestGitMetadataForWorktree(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git unavailable")
	}
	d := t.TempDir()
	for _, args := range [][]string{{"init", "-q", "-b", "fixture"}, {"-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "--allow-empty", "-qm", "fixture"}} {
		c := exec.Command("git", args...)
		c.Dir = d
		if b, err := c.CombinedOutput(); err != nil {
			t.Fatalf("git: %s: %v", b, err)
		}
	}
	if branch := GetCurrentBranch(d); branch != "fixture" {
		t.Fatalf("unexpected branch %q", branch)
	}
	if hash := GetCommitHash(d); len(hash) < 40 {
		t.Fatalf("invalid commit %q", hash)
	}
}
