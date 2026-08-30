package reporter

import (
	"fmt"
	"github.com/example/sast-dast-analyzer/internal/models"
	"path/filepath"
	"strings"
)

func GenerateCompellingTitle(f models.Finding) string {
	where := filepath.ToSlash(f.FilePath)
	if where == "" {
		where = "an unverified application component"
	} else if f.LineNumber > 0 {
		where = fmt.Sprintf("%s:%d", where, f.LineNumber)
	}
	kind := titleKind(classify(f))
	impact := "may weaken application security controls"
	switch classify(f) {
	case "sql injection":
		impact = "may allow unauthorized database access"
	case "authentication bypass":
		impact = "may allow account access without valid credentials"
	case "authorization bypass":
		impact = "may expose resources across user roles"
	case "ssrf":
		impact = "may reach unintended internal services"
	case "reentrancy":
		impact = "may cause inconsistent asset accounting"
	case "rce":
		impact = "may allow unintended code execution"
	}
	return fmt.Sprintf("%s in %s %s", kind, where, impact)
}
func titleKind(v string) string {
	parts := strings.Fields(v)
	for i := range parts {
		parts[i] = strings.ToUpper(parts[i][:1]) + parts[i][1:]
	}
	return strings.Join(parts, " ")
}
