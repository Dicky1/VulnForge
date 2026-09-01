package scanner

import (
	"context"
	"errors"
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
	// Prefer running the tool inside its sandboxed Docker image when one is
	// configured and Docker is reachable; fall through to local execution
	// otherwise (today's behavior, unchanged).
	if res, ranSandboxed, err := RunScannerSandboxed(ctx, timeout, dir, env, name, args...); ranSandboxed {
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

// interpretExecResult normalizes a finished command's output/error the way
// every exec-based scanner already expects: a deadline is surfaced as an
// error, a clean run or a non-zero exit both return the captured output with
// the matching exit code, and any other failure (e.g. binary not found) is
// returned as an error.
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
