package integrations

import (
	"context"
	"os/exec"
	"path/filepath"
	"strings"
)

func DetectGitRepo(target string) bool {
	_, err := runGit(target, "rev-parse", "--is-inside-work-tree")
	return err == nil
}
func GetCurrentBranch(repo string) string { v, _ := runGit(repo, "branch", "--show-current"); return v }
func GetCommitHash(repo string) string    { v, _ := runGit(repo, "rev-parse", "HEAD"); return v }
func GetGitRemote(repo string) string {
	v, _ := runGit(repo, "config", "--get", "remote.origin.url")
	return v
}
func GetDiffFiles(repo, base string) ([]string, error) {
	if base == "" {
		base = "HEAD~1"
	}
	v, err := runGit(repo, "diff", "--name-only", "--diff-filter=ACMR", base, "--")
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(v, "\n") {
		if line != "" {
			out = append(out, filepath.Join(repo, filepath.FromSlash(line)))
		}
	}
	return out, nil
}
func runGit(dir string, args ...string) (string, error) {
	cmd := exec.CommandContext(context.Background(), "git", args...)
	cmd.Dir = dir
	b, e := cmd.Output()
	return strings.TrimSpace(string(b)), e
}
