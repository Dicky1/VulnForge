package integrations

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// ErrExists is returned by WriteGeneratedFile when the destination already
// exists; generated CI files must never silently clobber a project's own
// pipeline definition or hook.
var ErrExists = errors.New("file already exists")

// WriteGeneratedFile creates path with body, refusing to overwrite an
// existing file. Only hooks are made executable; CI definitions are written
// owner-writable, world-readable data files.
func WriteGeneratedFile(path, body string, executable bool) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	mode := fs.FileMode(0o644)
	if executable {
		mode = 0o750
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("%s: %w (remove it first to regenerate)", path, ErrExists)
	}
	if err != nil {
		return err
	}
	if _, err = f.WriteString(body); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// WriteGeneratedFileWithin refuses existing symlink components below a trusted
// root. The caller must not scan a checkout that is being modified concurrently.
func WriteGeneratedFileWithin(root, path, body string, executable bool) error {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(absRoot, absPath)
	if err != nil || !filepath.IsLocal(rel) || rel == "." {
		return errors.New("integration path escapes target")
	}
	info, err := os.Lstat(absRoot)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("integration root is not a regular directory")
	}
	parent := filepath.Dir(absPath)
	for d := parent; d != absRoot; d = filepath.Dir(d) {
		info, err := os.Lstat(d)
		if err == nil && (!info.IsDir() || info.Mode()&os.ModeSymlink != 0) {
			return errors.New("integration parent is not a regular directory")
		}
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	return WriteGeneratedFile(absPath, body, executable)
}
