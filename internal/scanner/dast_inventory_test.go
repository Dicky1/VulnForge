package scanner

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestInventoryDASTPathsFiltersCapturedRequests(t *testing.T) {
	for _, tc := range []struct {
		format, content string
	}{
		{"openapi", "paths:\n  /keep:\n    get: {}\n  /template/{id}:\n    get: {}\n  /ignored:\n    post: {}\n"},
		{"har", `{"log":{"entries":[{"request":{"method":"GET","url":"https://app.test/keep?token=secret"}},{"request":{"method":"POST","url":"https://app.test/ignored"}},{"request":{"method":"GET","url":"https://elsewhere.test/ignored"}}]}}`},
		{"burp", `<items><item><url>https://app.test/keep?token=secret</url><method>GET</method><response>secret</response></item><item><url>https://app.test/ignored</url><method>POST</method></item></items>`},
		{"sitemap", `<urlset><url><loc>https://app.test/keep?token=secret</loc></url><url><loc>https://elsewhere.test/ignored</loc></url></urlset>`},
	} {
		t.Run(tc.format, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "inventory")
			if err := os.WriteFile(path, []byte(tc.content), 0600); err != nil {
				t.Fatal(err)
			}
			manifest, err := InventoryDASTPaths("https://app.test", path, tc.format)
			if err != nil {
				t.Fatal(err)
			}
			if manifest.Origin != "https://app.test/" || !slices.Equal(manifest.Paths, []string{"/keep"}) {
				t.Fatalf("unexpected inventory: %+v", manifest)
			}
		})
	}
}
