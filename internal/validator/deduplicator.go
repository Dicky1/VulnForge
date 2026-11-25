package validator

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/example/sast-dast-analyzer/internal/models"
)

// Prefer exact scanner identity to similarity. Different checks at one source
// location or different package advisories must not silently disappear.
func Deduplicate(in []models.Finding) []models.Finding {
	type key struct {
		Tool, ID, Path, Title, Description string
		Line                               int
	}
	seen := map[key]int{}
	out := make([]models.Finding, 0, len(in))
	for _, f := range in {
		k := key{f.SourceTool, f.ID, f.FilePath, f.Title, f.Description, f.LineNumber}
		if i, ok := seen[k]; ok {
			if f.CVSSBase > out[i].CVSSBase {
				out[i] = f
			}
			continue
		}
		seen[k] = len(out)
		out = append(out, f)
	}

	// SQLite and report joins require unique IDs even when a scanner reused
	// its identity for distinct evidence at the same source location.
	counts := map[string]int{}
	for _, f := range out {
		counts[f.ID]++
	}
	for i, f := range out {
		if f.ID == "" || counts[f.ID] > 1 {
			raw, _ := json.Marshal(key{f.SourceTool, f.ID, f.FilePath, f.Title, f.Description, f.LineNumber})
			sum := sha256.Sum256(raw)
			out[i].ID = "finding-" + hex.EncodeToString(sum[:])
		}
	}
	return out
}
