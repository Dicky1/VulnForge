package integrations

import (
	"context"
	"os/exec"
	"strings"
	"time"
)

func DetectGitRepo(target string) bool {
	value, err := runGit(target, "rev-parse", "--is-inside-work-tree")
	return err == nil && value == "true"
}
func GetCurrentBranch(repo string) string { v, _ := runGit(repo, "branch", "--show-current"); return v }
func GetCommitHash(repo string) string    { v, _ := runGit(repo, "rev-parse", "HEAD"); return v }
func runGit(dir string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	args = append([]string{"-c", "core.fsmonitor=false"}, args...)
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = dir
	cmd.Env = append(cmd.Environ(), "GIT_TERMINAL_PROMPT=0", "GIT_OPTIONAL_LOCKS=0")
	b, e := cmd.Output()
	return strings.TrimSpace(string(b)), e
}
