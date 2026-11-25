package reporter

import (
	"io"
	"os"
	"path/filepath"
)

func ensureDir(path string) error {
	dir := filepath.Dir(path)
	if dir == "." || dir == "" {
		return nil
	}
	return os.MkdirAll(dir, 0700)
}

// Write to a private temporary file in the selected output directory, then
// replace the destination. Existing file permissions and symlinks must not
// cause report contents to be written to another file or made world-readable.
func atomicReportPath(path string, render func(string) error) error {
	if err := ensureDir(path); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".vulnforge-report-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err = f.Close(); err != nil {
		return err
	}
	if err = render(tmp); err != nil {
		return err
	}
	if err = os.Chmod(tmp, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
func atomicReport(path string, render func(io.Writer) error) error {
	return atomicReportPath(path, func(tmp string) error {
		f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_TRUNC, 0600)
		if err != nil {
			return err
		}
		if err = render(f); err != nil {
			_ = f.Close()
			return err
		}
		return f.Close()
	})
}
func write(path string, b []byte) error {
	return atomicReport(path, func(w io.Writer) error { _, err := w.Write(b); return err })
}
