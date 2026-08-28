package scanner

import "testing"

func TestESLintParseOutput(t *testing.T) {
	raw := []byte(`[{"filePath":"app.js","messages":[{"ruleId":"security/detect-eval-with-expression","severity":2,"message":"eval injection","line":7}]}]`)
	got, err := NewESLintScanner().ParseOutput(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Language != "javascript" || got[0].LineNumber != 7 {
		t.Fatalf("unexpected: %#v", got)
	}
}
func TestCargoAuditParseOutput(t *testing.T) {
	raw := []byte(`{"vulnerabilities":{"list":[{"advisory":{"id":"RUSTSEC-1","title":"bad crate","description":"vulnerable","severity":"high"},"package":{"name":"crate","version":"1.0"}}]}}`)
	got, err := NewCargoAuditScanner().ParseOutput(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Language != "rust" {
		t.Fatalf("unexpected: %#v", got)
	}
}
func TestPackageLanguage(t *testing.T) {
	if got := packageLanguage("x/node_modules/pkg"); got != "javascript" {
		t.Fatalf("got %s", got)
	}
}
