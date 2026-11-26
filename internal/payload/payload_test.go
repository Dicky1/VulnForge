package payload

import (
	"strings"
	"testing"
)

func TestNewTokenIsUniqueAndHex(t *testing.T) {
	a, err := NewToken(8)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewToken(8)
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("expected two distinct tokens")
	}
	if len(a) != 16 { // 8 bytes -> 16 hex chars
		t.Fatalf("expected 16-char hex token, got %q", a)
	}
	for _, r := range a {
		if !strings.ContainsRune("0123456789abcdef", r) {
			t.Fatalf("token contains non-hex rune: %q", a)
		}
	}
}

func TestReflectedXSSUsesUniqueCanaryPerCall(t *testing.T) {
	e := Engine{}
	point := InjectionPoint{Kind: PointQuery, Name: "q"}
	first := e.ReflectedXSS(point, ContextHTMLBody)
	second := e.ReflectedXSS(point, ContextHTMLBody)
	if len(first) == 0 || len(second) == 0 {
		t.Fatal("expected at least one attempt")
	}
	if first[0].Canary == second[0].Canary {
		t.Fatal("expected a fresh canary on every call")
	}
	for _, a := range first {
		if a.Class != ClassXSSReflected {
			t.Errorf("expected ClassXSSReflected, got %v", a.Class)
		}
		if !strings.Contains(a.Value, a.Canary) {
			t.Errorf("payload value %q does not contain its own canary %q", a.Value, a.Canary)
		}
	}
}

func TestReflectsCanary(t *testing.T) {
	a := Attempt{Canary: "vfxssabc123"}
	if !ReflectsCanary("<html>hello vfxssabc123 world</html>", a) {
		t.Fatal("expected canary to be detected")
	}
	if ReflectsCanary("<html>no marker here</html>", a) {
		t.Fatal("did not expect a false positive")
	}
	if ReflectsCanary("anything", Attempt{}) {
		t.Fatal("an attempt with no canary must never match")
	}
}

func TestSQLiBooleanBasedProducesComplementaryPair(t *testing.T) {
	e := Engine{}
	point := InjectionPoint{Kind: PointQuery, Name: "id"}
	tru, fls := e.SQLiBooleanBased(point, "1")
	if tru.Class != ClassSQLiBoolean || fls.Class != ClassSQLiBoolean {
		t.Fatal("expected both attempts to be ClassSQLiBoolean")
	}
	if tru.Value == fls.Value {
		t.Fatal("true and false attempts must differ")
	}
	if !strings.HasPrefix(tru.Value, "1") || !strings.HasPrefix(fls.Value, "1") {
		t.Fatal("expected the base value to be preserved as a prefix")
	}
}

func TestPathTraversalOnlyTargetsBenignFiles(t *testing.T) {
	e := Engine{}
	for _, a := range e.PathTraversal(InjectionPoint{Kind: PointQuery, Name: "file"}) {
		if strings.Contains(a.Value, "rm ") || strings.Contains(a.Value, "DROP") {
			t.Fatalf("path traversal probe is not benign: %q", a.Value)
		}
	}
}

func TestSSRFOutOfBandRequiresHost(t *testing.T) {
	e := Engine{}
	if _, err := e.SSRFOutOfBand(InjectionPoint{Kind: PointQuery, Name: "url"}, ""); err == nil {
		t.Fatal("expected an error for an empty OOB host")
	}
	a, err := e.SSRFOutOfBand(InjectionPoint{Kind: PointQuery, Name: "url"}, "collab.example")
	if err != nil {
		t.Fatal(err)
	}
	if a.OOBToken == "" {
		t.Fatal("expected a non-empty OOB token")
	}
	if !strings.Contains(a.Value, a.OOBToken+".collab.example") {
		t.Fatalf("expected the token to be embedded as a subdomain, got %q", a.Value)
	}
}

func TestGenerateAllSkipsOOBClassesWithoutCallbackHost(t *testing.T) {
	e := Engine{} // no OOBCallbackHost
	attempts := e.GenerateAll(InjectionPoint{Kind: PointQuery, Name: "q"}, ContextUnknown)
	for _, a := range attempts {
		if a.Class == ClassSSRFOOB {
			t.Fatal("expected no SSRF-OOB attempt without a configured callback host")
		}
	}
}

func TestGenerateAllIncludesOOBClassWithCallbackHost(t *testing.T) {
	e := Engine{OOBCallbackHost: "collab.example"}
	attempts := e.GenerateAll(InjectionPoint{Kind: PointQuery, Name: "q"}, ContextUnknown)
	found := false
	for _, a := range attempts {
		if a.Class == ClassSSRFOOB {
			found = true
		}
	}
	if !found {
		t.Fatal("expected an SSRF-OOB attempt when a callback host is configured")
	}
}

func TestInjectionPointString(t *testing.T) {
	cases := []struct {
		point InjectionPoint
		want  string
	}{
		{InjectionPoint{Kind: PointQuery, Name: "search"}, "query:search"},
		{InjectionPoint{Kind: PointJSON, Name: "user.search"}, "json:user.search"},
		{InjectionPoint{Kind: PointHeader, Name: "X-Forwarded-For"}, "header:X-Forwarded-For"},
		{InjectionPoint{Kind: PointPath, PathSegment: 2}, "path[2]"},
	}
	for _, c := range cases {
		if got := c.point.String(); got != c.want {
			t.Errorf("String() = %q, want %q", got, c.want)
		}
	}
}

func TestMutate(t *testing.T) {
	if got := Mutate("url_encode", "<script>"); got != "%3Cscript%3E" {
		t.Errorf("url_encode: got %q", got)
	}
	if got := Mutate("upper_case", "abc"); got != "ABC" {
		t.Errorf("upper_case: got %q", got)
	}
	if got := Mutate("unknown_mutation", "unchanged"); got != "unchanged" {
		t.Errorf("unknown mutation should pass through unchanged, got %q", got)
	}
	for _, name := range MutationNames() {
		if Mutate(name, "x") == "" {
			t.Errorf("mutation %q produced an empty result for non-empty input", name)
		}
	}
}

func TestCommandInjectionOutOfBandNeverDestructive(t *testing.T) {
	e := Engine{}
	attempts, err := e.CommandInjectionOutOfBand(InjectionPoint{Kind: PointQuery, Name: "host"}, "collab.example")
	if err != nil {
		t.Fatal(err)
	}
	destructive := []string{"rm -rf", " dd ", "mkfs", "> /dev/sd"}
	for _, a := range attempts {
		for _, d := range destructive {
			if strings.Contains(a.Value, d) {
				t.Fatalf("command injection probe looks destructive: %q", a.Value)
			}
		}
	}
}
