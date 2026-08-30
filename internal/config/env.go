package config

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// LoadEnvFile loads KEY=VALUE entries without replacing variables already set
// by the parent shell. A missing default .env file is intentionally harmless.
func LoadEnvFile(path string) error {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
		key, value, ok := strings.Cut(line, "=")
		key = strings.TrimSpace(key)
		if !ok || !validEnvKey(key) {
			return fmt.Errorf("%s:%d: invalid environment entry", path, lineNumber)
		}
		if _, exists := os.LookupEnv(key); exists {
			continue
		}
		value = strings.TrimSpace(value)
		if len(value) >= 2 && ((value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'')) {
			value = value[1 : len(value)-1]
		}
		if err := os.Setenv(key, value); err != nil {
			return fmt.Errorf("%s:%d: %w", path, lineNumber, err)
		}
	}
	return scanner.Err()
}

func EnvBool(key string, fallback bool) bool {
	raw, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(raw) == "" {
		return fallback
	}
	value, err := strconv.ParseBool(strings.TrimSpace(raw))
	if err != nil {
		return fallback
	}
	return value
}

// PrepareToolPath makes per-user tool installations discoverable without
// requiring every terminal to duplicate PATH setup. ANALYZER_TOOL_PATHS may
// contain additional paths separated with the platform list separator.
func PrepareToolPath() error {
	paths := filepath.SplitList(os.Getenv("ANALYZER_TOOL_PATHS"))
	if home, err := os.UserHomeDir(); err == nil {
		paths = append(paths, filepath.Join(home, ".foundry", "bin"))
	}
	current := filepath.SplitList(os.Getenv("PATH"))
	seen := make(map[string]bool, len(current))
	for _, path := range current {
		seen[strings.ToLower(filepath.Clean(path))] = true
	}
	for _, path := range paths {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		if info, err := os.Stat(path); err != nil || !info.IsDir() {
			continue
		}
		key := strings.ToLower(filepath.Clean(path))
		if !seen[key] {
			current = append(current, path)
			seen[key] = true
		}
	}
	return os.Setenv("PATH", strings.Join(current, string(os.PathListSeparator)))
}

func validEnvKey(key string) bool {
	if key == "" || !isEnvLetter(key[0]) {
		return false
	}
	for i := 1; i < len(key); i++ {
		if !isEnvLetter(key[i]) && (key[i] < '0' || key[i] > '9') {
			return false
		}
	}
	return true
}

func isEnvLetter(c byte) bool {
	return c == '_' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z'
}
