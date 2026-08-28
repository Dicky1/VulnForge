package validator

import (
	"fmt"
	"github.com/example/sast-dast-analyzer/internal/models"
	"strings"
)

func Deduplicate(in []models.Finding) []models.Finding {
	seen := map[string]int{}
	out := make([]models.Finding, 0, len(in))
	for _, f := range in {
		k := strings.ToLower(fmt.Sprintf("%s:%s", f.CWE, f.FilePath))
		if f.CWE == "" {
			k = strings.ToLower(fmt.Sprintf("%s:%s:%d", f.Title, f.FilePath, f.LineNumber))
		}
		if i, ok := seen[k]; ok {
			if f.CVSSBase > out[i].CVSSBase {
				out[i] = f
			}
			continue
		}
		seen[k] = len(out)
		out = append(out, f)
	}
	return out
}
