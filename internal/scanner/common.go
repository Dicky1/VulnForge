package scanner

import (
	"context"
	"errors"
	"os/exec"
	"time"
)

type commandResult struct {
	data     []byte
	exitCode int
}

func run(ctx context.Context, timeout time.Duration, dir, name string, args ...string) (commandResult, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	b, err := cmd.CombinedOutput()
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
