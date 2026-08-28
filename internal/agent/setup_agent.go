package agent

import (
	"context"
	"fmt"
	"github.com/example/sast-dast-analyzer/internal/parser"
	"log"
	"os/exec"
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
func (a *SetupAgent) AutoInstallAndRun(ctx context.Context, setups map[string]*parser.ToolSetup) error {
	if !a.AllowInstall {
		return nil
	}
	for name, s := range setups {
		for _, line := range s.InstallCmds {
			cmd, args, ok := safeInstall(line)
			if !ok {
				return fmt.Errorf("unsafe install command rejected for %s", name)
			}
			cctx, cancel := context.WithTimeout(ctx, a.Timeout)
			err := exec.CommandContext(cctx, cmd, args...).Run()
			cancel()
			if err != nil {
				return fmt.Errorf("install %s: %w", name, err)
			}
		}
	}
	return nil
}
func safeInstall(line string) (string, []string, bool) {
	f := strings.Fields(line)
	if len(f) < 3 {
		return "", nil, false
	}
	if (f[0] == "pip" || f[0] == "pip3") && f[1] == "install" {
		return f[0], f[1:], true
	}
	if f[0] == "go" && f[1] == "install" && strings.HasPrefix(f[2], "github.com/securego/gosec/") {
		return f[0], f[1:], true
	}
	return "", nil, false
}
