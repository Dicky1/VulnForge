package agent

import (
	"context"
	"fmt"
	"github.com/example/sast-dast-analyzer/internal/parser"
	"github.com/example/sast-dast-analyzer/internal/scanner"
	"log"
	"regexp"
	"strings"
	"time"
)

type SetupAgent struct {
	Timeout      time.Duration
	AllowInstall bool
	Logger       *log.Logger
}

func (a *SetupAgent) ParseREADME(path string) (map[string]*parser.ToolSetup, error) {
	return parser.ParseREADME(path)
}

// AutoInstallAndRun handles install hints parsed from the *target*
// repository's README — untrusted input. Every recognized line is first
// re-validated by safeInstall's strict allowlist. It never executes that
// command on the host: it only confirms the tool is covered by a sandboxed
// Docker image (those images already bake the tool in at build time, so
// there is nothing left to install at scan time). If sandboxing isn't
// configured or Docker isn't reachable, it refuses outright rather than
// falling back to running an untrusted-repo-derived command locally.
func (a *SetupAgent) AutoInstallAndRun(_ context.Context, setups map[string]*parser.ToolSetup) error {
	if !a.AllowInstall {
		return nil
	}
	for name, s := range setups {
		for _, line := range s.InstallCmds {
			if _, _, ok := safeInstall(line); !ok {
				return fmt.Errorf("unsafe install command rejected for %s", name)
			}
			if !scanner.SandboxAvailableFor(name) {
				return fmt.Errorf("refusing to run the %s install command from the target README on the host: sandboxing is unavailable for it (build/enable its Docker image under sandbox.images, or install %s yourself)", name, name)
			}
			if a.Logger != nil {
				a.Logger.Printf("%s is provided by its sandboxed image; skipping host install", name)
			}
		}
	}
	return nil
}

// allowedPipPackage matches only the exact package specs safeInstall is
// permitted to install; there is no wildcard here on purpose.
var allowedPipPackage = regexp.MustCompile(`(?i)^(?:semgrep|bandit(?:\[[\w,]+\])?)(?:==[\w.\-]+)?$`)

// gosecModuleRef matches only the gosec module path itself, optionally pinned
// to a version/tag, so a README cannot smuggle a different module in via @ref.
var gosecModuleRef = regexp.MustCompile(`^github\.com/securego/gosec/v2/cmd/gosec(?:@[\w.\-/]+)?$`)

// safeInstall re-validates the parsed README line independently of
// parser.ParseREADME's own regexes: a target repository's README is
// untrusted input, so this must reject anything but an exact, known-safe
// install command. In particular, it requires exactly the expected number of
// arguments — a line like "pip install evil-package semgrep" must NOT be
// allowed through just because it also mentions "semgrep".
func safeInstall(line string) (string, []string, bool) {
	f := strings.Fields(line)
	if len(f) == 3 && (f[0] == "pip" || f[0] == "pip3") && f[1] == "install" && allowedPipPackage.MatchString(f[2]) {
		return f[0], f[1:], true
	}
	if len(f) == 3 && f[0] == "go" && f[1] == "install" && gosecModuleRef.MatchString(f[2]) {
		return f[0], f[1:], true
	}
	return "", nil, false
}
