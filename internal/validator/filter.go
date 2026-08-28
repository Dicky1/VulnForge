package validator

import (
	"github.com/example/sast-dast-analyzer/internal/models"
	"regexp"
	"strings"
)

func SkipKnownFalsePositives(in []models.Finding, patterns []string) []models.Finding {
	rs := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		if r, e := regexp.Compile("(?i)" + p); e == nil {
			rs = append(rs, r)
		}
	}
	out := in[:0]
	for _, f := range in {
		v := strings.Join([]string{f.Title, f.Description, f.CodeSnippet, f.FilePath}, " ")
		skip := false
		for _, r := range rs {
			if r.MatchString(v) {
				skip = true
				break
			}
		}
		if !skip {
			out = append(out, f)
		}
	}
	return out
}
