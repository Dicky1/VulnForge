package oob

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHTTPListenerRecordsAndCorrelatesByHostLabel(t *testing.T) {
	store := NewStore()
	srv := httptest.NewServer(HTTPListener{Store: store})
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/callback", nil)
	req.Host = "tok12345.collab.example"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected default 200 response, got %d", resp.StatusCode)
	}

	hits := store.Lookup("tok12345")
	if len(hits) != 1 {
		t.Fatalf("expected exactly one interaction, got %d", len(hits))
	}
	if hits[0].Protocol != "http" {
		t.Errorf("expected protocol http, got %q", hits[0].Protocol)
	}
	if hits[0].SourceIP == "" {
		t.Error("expected a non-empty source IP")
	}
}

func TestHTTPListenerFallsBackToPathSegment(t *testing.T) {
	// Without a configured Domain, httptest's own IP:port host is itself
	// multi-label, so the listener must be told its base domain to know
	// that host isn't a token — here we simulate that by using the
	// domain-aware extractor directly against a configured domain, since a
	// real deployment's listener host (e.g. "collab.example") behaves the
	// same way: a bare request to "collab.example" must fall through to
	// path-based correlation, not be misread as token "collab".
	store := NewStore()
	srv := httptest.NewServer(HTTPListener{Store: store, Domain: "collab.example"})
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/tokABCDEF/xxe", nil)
	req.Host = "collab.example" // bare listener host: no token subdomain
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if hits := store.Lookup("tokABCDEF"); len(hits) != 1 {
		t.Fatalf("expected one interaction correlated by path segment, got %d", len(hits))
	}
}

func TestTokenFromHostAgainstDomain(t *testing.T) {
	cases := []struct{ host, domain, want string }{
		{"tok123.collab.example", "collab.example", "tok123"},
		{"TOK123.COLLAB.EXAMPLE", "collab.example", "tok123"},
		{"tok123.collab.example:8080", "collab.example", "tok123"},
		{"collab.example", "collab.example", ""},     // bare domain: not a token
		{"a.b.collab.example", "collab.example", ""}, // more than one extra label
		{"evil.example", "collab.example", ""},       // unrelated host
		{"tok123.collab.example", "", ""},            // no configured domain
	}
	for _, c := range cases {
		if got := tokenFromHostAgainstDomain(c.host, c.domain); got != c.want {
			t.Errorf("tokenFromHostAgainstDomain(%q, %q) = %q, want %q", c.host, c.domain, got, c.want)
		}
	}
}

func TestStoreWaitReturnsOnInteraction(t *testing.T) {
	store := NewStore()
	go func() {
		time.Sleep(20 * time.Millisecond)
		store.record("waittoken", Interaction{Token: "waittoken", Protocol: "http"})
	}()
	start := time.Now()
	hits := store.Wait(context.Background(), "waittoken", time.Second)
	if len(hits) != 1 {
		t.Fatalf("expected one interaction, got %d", len(hits))
	}
	if time.Since(start) >= time.Second {
		t.Error("Wait should have returned as soon as the interaction arrived, not waited the full timeout")
	}
}

func TestStoreWaitTimesOutWithoutInteraction(t *testing.T) {
	store := NewStore()
	hits := store.Wait(context.Background(), "nevercomes", 50*time.Millisecond)
	if len(hits) != 0 {
		t.Fatalf("expected no interactions, got %d", len(hits))
	}
}

func TestStoreBoundsInteractionsPerToken(t *testing.T) {
	store := NewStore()
	for i := 0; i < 100; i++ {
		store.record("flood", Interaction{Token: "flood"})
	}
	if got := len(store.Lookup("flood")); got != 50 {
		t.Fatalf("expected the store to cap at 50 interactions per token, got %d", got)
	}
}

func TestTokenFromHost(t *testing.T) {
	cases := map[string]string{
		"tok123.collab.example":      "tok123",
		"tok123.collab.example:8080": "tok123",
		"collab.example":             "collab",
		"nodots":                     "",
		"":                           "",
	}
	for in, want := range cases {
		if got := tokenFromHost(in); got != want {
			t.Errorf("tokenFromHost(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseDNSQuestionNameRejectsMalformed(t *testing.T) {
	if _, _, ok := parseDNSQuestionName([]byte{0x00, 0x01}); ok {
		t.Fatal("expected malformed/too-short message to be rejected")
	}
	// Header with QDCOUNT=0 should be rejected: nothing to correlate.
	msg := make([]byte, 12)
	if _, _, ok := parseDNSQuestionName(msg); ok {
		t.Fatal("expected a message with zero questions to be rejected")
	}
}

func TestParseDNSQuestionNameExtractsLabels(t *testing.T) {
	// Build a minimal query for "tok1.collab.example" + a trailing zero byte
	// and a 4-byte QTYPE/QCLASS, matching a standard DNS question section.
	msg := make([]byte, 12)
	msg[5] = 1 // QDCOUNT = 1
	appendLabel := func(s string) {
		msg = append(msg, byte(len(s)))
		msg = append(msg, []byte(s)...)
	}
	appendLabel("tok1")
	appendLabel("collab")
	appendLabel("example")
	msg = append(msg, 0x00)       // root label
	msg = append(msg, 0, 1, 0, 1) // QTYPE=A, QCLASS=IN

	name, _, ok := parseDNSQuestionName(msg)
	if !ok {
		t.Fatal("expected a valid question name to parse")
	}
	if name != "tok1.collab.example" {
		t.Fatalf("got %q", name)
	}
}

func TestDNSListenerRecordsQuery(t *testing.T) {
	store := NewStore()
	l, err := ListenDNS("127.0.0.1:0", store)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go l.Serve(ctx)

	// Build the same minimal query as above and send it over UDP.
	msg := make([]byte, 12)
	msg[5] = 1
	appendLabel := func(s string) {
		msg = append(msg, byte(len(s)))
		msg = append(msg, []byte(s)...)
	}
	appendLabel("dnstok")
	appendLabel("collab")
	appendLabel("example")
	msg = append(msg, 0x00)
	msg = append(msg, 0, 1, 0, 1)

	conn, err := net.Dial("udp", l.conn.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write(msg); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if hits := store.Lookup("dnstok"); len(hits) > 0 {
			if hits[0].Protocol != "dns" {
				t.Fatalf("expected protocol dns, got %q", hits[0].Protocol)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("expected a DNS interaction to be recorded within the deadline")
}
