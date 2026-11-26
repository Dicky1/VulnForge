package evidence

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newReq(t *testing.T, method, url string, headers map[string]string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return req
}

func TestCaptureRedactsSensitiveHeaders(t *testing.T) {
	req := newReq(t, http.MethodGet, "https://target.example/search?q=1", map[string]string{
		"Authorization": "Bearer super-secret-token",
		"Cookie":        "session=highly-sensitive-value",
		"Accept":        "text/html",
	})
	resp := &http.Response{StatusCode: 200, Header: http.Header{"Set-Cookie": {"session=rotated-secret"}}}

	b := Builder{}
	ev := b.Capture(req, nil, resp, []byte("ok"))

	if ev.Request == nil {
		t.Fatal("expected request evidence")
	}
	for _, h := range ev.Request.Headers {
		if strings.EqualFold(h.Name, "Authorization") && h.Value != Redacted {
			t.Fatalf("Authorization value not redacted: %q", h.Value)
		}
		if strings.EqualFold(h.Name, "Cookie") && h.Value != Redacted {
			t.Fatalf("Cookie value not redacted: %q", h.Value)
		}
		if strings.EqualFold(h.Name, "Accept") && h.Value != "text/html" {
			t.Fatalf("non-sensitive header was altered: %q", h.Value)
		}
	}
	for _, h := range ev.Response.Headers {
		if strings.EqualFold(h.Name, "Set-Cookie") && h.Value != Redacted {
			t.Fatalf("Set-Cookie value not redacted: %q", h.Value)
		}
	}
	if !strings.Contains(ev.CurlCommand, Redacted) {
		t.Fatal("expected curl command to contain the redaction marker")
	}
	if strings.Contains(ev.CurlCommand, "super-secret-token") || strings.Contains(ev.CurlCommand, "highly-sensitive-value") {
		t.Fatalf("secret leaked into curl command: %q", ev.CurlCommand)
	}
}

func TestShellQuoteEscapesEmbeddedSingleQuotes(t *testing.T) {
	cases := map[string]string{
		"":              "''",
		"plain":         "'plain'",
		"a'b":           `'a'\''b'`,
		"'; rm -rf / #": `''\''; rm -rf / #'`,
		"''":            `''\'''\'''`,
	}
	for in, want := range cases {
		if got := shellQuote(in); got != want {
			t.Errorf("shellQuote(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCurlCommandQuotesEveryArgument(t *testing.T) {
	req := newReq(t, http.MethodGet, "https://target.example/search?q="+`'injected'`, nil)
	req.Header.Set("X-Evil", "'; rm -rf / #")
	b := Builder{}
	ev := b.Capture(req, nil, nil, nil)

	// Every argument curl receives must be produced by shellQuote, so a
	// shell parsing the full command line sees one opaque string per flag,
	// never a sequence it would interpret as a second command.
	if !strings.HasPrefix(ev.CurlCommand, "curl -sS -X 'GET'") {
		t.Fatalf("unexpected curl command prefix: %q", ev.CurlCommand)
	}
	if !strings.Contains(ev.CurlCommand, shellQuote("X-Evil: '; rm -rf / #")) {
		t.Fatalf("expected the header argument to be exactly shellQuote's output, got %q", ev.CurlCommand)
	}
}

func TestCaptureTruncatesLargeBodies(t *testing.T) {
	b := Builder{MaxBody: 10}
	req := newReq(t, http.MethodPost, "https://target.example/", nil)
	resp := &http.Response{StatusCode: 200, Header: http.Header{}}
	ev := b.Capture(req, []byte("0123456789ABCDEF"), resp, []byte("0123456789ABCDEF"))

	if !ev.Request.BodyTruncated || len(ev.Request.Body) != 10 {
		t.Fatalf("expected request body truncated to 10 bytes, got %q (truncated=%v)", ev.Request.Body, ev.Request.BodyTruncated)
	}
	if !ev.Response.BodyTruncated || len(ev.Response.Body) != 10 {
		t.Fatalf("expected response body truncated to 10 bytes, got %q (truncated=%v)", ev.Response.Body, ev.Response.BodyTruncated)
	}
}

func TestReadLimitedBoundsMemoryAndFlagsTruncation(t *testing.T) {
	data, truncated, err := ReadLimited(strings.NewReader("abcdefghij"), 4)
	if err != nil {
		t.Fatal(err)
	}
	if !truncated || string(data) != "abcd" {
		t.Fatalf("expected truncated 4-byte read, got %q truncated=%v", data, truncated)
	}

	data, truncated, err = ReadLimited(strings.NewReader("abc"), 10)
	if err != nil {
		t.Fatal(err)
	}
	if truncated || string(data) != "abc" {
		t.Fatalf("expected untruncated short read, got %q truncated=%v", data, truncated)
	}
}

func TestRestoreBodyAllowsRereading(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hello"))
	}))
	defer srv.Close()
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	data, _, err := ReadLimited(resp.Body, 100)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	RestoreBody(resp, data)

	again, err := readAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(again) != "hello" {
		t.Fatalf("expected body to be re-readable after RestoreBody, got %q", again)
	}
}

func readAll(r interface{ Read([]byte) (int, error) }) ([]byte, error) {
	buf := make([]byte, 0, 64)
	tmp := make([]byte, 64)
	for {
		n, err := r.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if err != nil {
			if err.Error() == "EOF" {
				return buf, nil
			}
			return buf, err
		}
	}
}

func TestIsSensitiveHeaderCaseInsensitive(t *testing.T) {
	for _, name := range []string{"authorization", "AUTHORIZATION", "Cookie", "X-Api-Key", "x-api-key"} {
		if !IsSensitiveHeader(name) {
			t.Errorf("expected %q to be treated as sensitive", name)
		}
	}
	for _, name := range []string{"Accept", "User-Agent", "Content-Type"} {
		if IsSensitiveHeader(name) {
			t.Errorf("did not expect %q to be treated as sensitive", name)
		}
	}
}
