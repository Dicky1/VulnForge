package scanner

import (
	"bytes"
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
	stderr   []byte
}

const defaultScannerTimeout = 10 * time.Minute

func (r commandResult) combined() []byte {
	if len(r.stderr) == 0 {
		return r.data
	}
	out := append([]byte(nil), r.data...)
	if len(out) > 0 && out[len(out)-1] != '\n' {
		out = append(out, '\n')
	}
	return append(out, r.stderr...)
}

func run(ctx context.Context, timeout time.Duration, dir, name string, args ...string) (commandResult, error) {
	return runWithEnv(ctx, timeout, dir, nil, name, args...)
}

func runWithEnv(ctx context.Context, timeout time.Duration, dir string, env []string, name string, args ...string) (commandResult, error) {
	if timeout <= 0 {
		timeout = defaultScannerTimeout
	}
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
	return execSplit(ctx, cmd)
}

// execSplit prevents diagnostics from corrupting machine-readable stdout.
func execSplit(ctx context.Context, cmd *exec.Cmd) (commandResult, error) {
	var stdout, stderr limitedOutput
	stdout.limit = 64 << 20
	stderr.limit = 4 << 20
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	cmd.WaitDelay = 5 * time.Second
	err := cmd.Run()
	if stdout.truncated || stderr.truncated {
		return commandResult{exitCode: -1}, fmt.Errorf("scanner output exceeded capture limit")
	}
	res, err := interpretExecResult(ctx, stdout.Bytes(), err)
	res.stderr = stderr.Bytes()
	return res, err
}

// interpretExecResult normalizes scanner output and errors.
func interpretExecResult(ctx context.Context, b []byte, err error) (commandResult, error) {
	if ctx.Err() != nil {
		return commandResult{data: b, exitCode: -1}, ctx.Err()
	}
	if err == nil {
		return commandResult{data: b, exitCode: 0}, nil
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return commandResult{data: b, exitCode: ee.ExitCode()}, nil
	}
	return commandResult{data: b, exitCode: -1}, err
}

// Consume excess bytes so subprocesses do not block on a full pipe, but
// never retain unlimited data or parse a silently truncated JSON document.
type limitedOutput struct {
	buf       bytes.Buffer
	limit     int
	truncated bool
}

func (b *limitedOutput) Write(p []byte) (int, error) {
	n := len(p)
	available := b.limit - b.buf.Len()
	if available < n {
		b.truncated = true
		if available < 0 {
			available = 0
		}
		p = p[:available]
	}
	_, err := b.buf.Write(p)
	return n, err
}

func (b *limitedOutput) Bytes() []byte  { return b.buf.Bytes() }
func (b *limitedOutput) String() string { return b.buf.String() }
