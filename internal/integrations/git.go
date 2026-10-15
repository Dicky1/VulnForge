package integrations

import (
	"context"
	"os/exec"
	"strings"
)

func DetectGitRepo(target string) bool {
	_, err := runGit(target, "rev-parse", "--is-inside-work-tree")
	return err == nil
}
func GetCurrentBranch(repo string) string { v, _ := runGit(repo, "branch", "--show-current"); return v }
func GetCommitHash(repo string) string    { v, _ := runGit(repo, "rev-parse", "HEAD"); return v }
func runGit(dir string, args ...string) (string, error) {
	cmd := exec.CommandContext(context.Background(), "git", args...)
	cmd.Dir = dir
	b, e := cmd.Output()
	return strings.TrimSpace(string(b)), e
}
