package parser

import (
	"bufio"
	"os"
	"regexp"
	"strings"
)

type ToolSetup struct {
	Name        string            `json:"name"`
	InstallCmds []string          `json:"install_commands"`
	RunCmds     []string          `json:"run_commands"`
	DockerCmds  []string          `json:"docker_commands"`
	EnvVars     map[string]string `json:"environment_variables"`
}

var (
	installPatterns = []struct {
		name string
		re   *regexp.Regexp
	}{
		{"semgrep", regexp.MustCompile(`(?i)^\s*(?:python\s+-m\s+)?pip3?\s+install\s+[^#]*(?:semgrep)[^#]*$`)},
		{"bandit", regexp.MustCompile(`(?i)^\s*(?:python\s+-m\s+)?pip3?\s+install\s+[^#]*(?:bandit)[^#]*$`)},
		{"gosec", regexp.MustCompile(`(?i)^\s*go\s+install\s+github\.com/securego/gosec/v2/cmd/gosec(?:@\S+)?\s*$`)},
	}
	envPattern    = regexp.MustCompile(`^\s*(?:export\s+|ENV\s+)([A-Za-z_][A-Za-z0-9_]*)=(?:"([^"]*)"|'([^']*)'|(\S+))\s*$`)
	dockerPattern = regexp.MustCompile(`(?i)^\s*docker\s+(?:build|compose\s+(?:build|up))\b`)
)

func ParseREADME(path string) (map[string]*ToolSetup, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	setups := map[string]*ToolSetup{}
	inCode := false
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 64*1024), 1024*1024)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if strings.HasPrefix(line, "```") {
			inCode = !inCode
			continue
		}
		if !inCode || line == "" {
			continue
		}
		if m := envPattern.FindStringSubmatch(line); m != nil {
			v := m[2] + m[3] + m[4]
			for _, name := range []string{"project"} {
				setup(setups, name).EnvVars[m[1]] = v
			}
		}
		for _, p := range installPatterns {
			if p.re.MatchString(line) {
				setup(setups, p.name).InstallCmds = append(setup(setups, p.name).InstallCmds, line)
			}
		}
		if dockerPattern.MatchString(line) {
			setup(setups, "docker").DockerCmds = append(setup(setups, "docker").DockerCmds, line)
		}
	}
	return setups, s.Err()
}

func setup(m map[string]*ToolSetup, name string) *ToolSetup {
	if m[name] == nil {
		m[name] = &ToolSetup{Name: name, EnvVars: map[string]string{}}
	}
	return m[name]
}
