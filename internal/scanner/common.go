package scanner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"time"
)

type commandResult struct {
	data     []byte
	exitCode int
}

func run(ctx context.Context, timeout time.Duration, dir, name string, args ...string) (commandResult, error) {
	return runWithEnv(ctx, timeout, dir, nil, name, args...)
}

func runWithEnv(ctx context.Context, timeout time.Duration, dir string, env []string, name string, args ...string) (commandResult, error) {
	// Once sandbox mode is explicitly enabled, never silently execute a
	// scanner on the host. Some scanners parse or execute untrusted project
	// files and require a clear trust boundary.
	if sandbox.Enabled {
		if sandbox.Images[name] == "" {
			return commandResult{exitCode: -1}, fmt.Errorf("sandbox enabled but no image configured for %q", name)
		}
		res, ran, err := RunScannerSandboxed(ctx, timeout, dir, env, name, args...)
		if !ran {
			return commandResult{exitCode: -1}, fmt.Errorf("sandbox enabled but Docker is unavailable for %q", name)
		}
		return res, err
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	if len(env) > 0 {
		cmd.Env = append(os.Environ(), env...)
	}
	b, err := cmd.CombinedOutput()
	return interpretExecResult(ctx, b, err)
}

// interpretExecResult normalizes scanner output and errors.
func interpretExecResult(ctx context.Context, b []byte, err error) (commandResult, error) {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return commandResult{b, -1}, ctx.Err()
	}
	if err == nil {
		return commandResult{b, 0}, nil
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return commandResult{b, ee.ExitCode()}, nil
	}
	return commandResult{b, -1}, err
}
