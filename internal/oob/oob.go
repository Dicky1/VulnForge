// Package oob implements a minimal, self-hosted out-of-band (OOB)
// interaction listener for blackbox findings that cannot be confirmed
// in-band: blind SSRF, blind/async command injection, XXE, and similar
// classes where the payload engine (internal/payload) embeds a unique
// token as a DNS label or URL path and the only proof of exploitation is a
// callback reaching this listener.
//
// It deliberately does not depend on any third-party interaction service
// (e.g. interact.sh/Burp Collaborator) so it has no external dependency and
// works fully offline on a reachable host: an HTTP listener using only
// net/http, and a best-effort raw-UDP DNS query listener using only
// encoding/binary + net, parsing just enough of the DNS wire format to
// extract the queried name. A production deployment still needs the host
// running this listener to be reachable from the target (e.g. a public IP
// or a tunnel) and its hostname configured as payload.Engine.OOBCallbackHost;
// this package only records and correlates interactions, it does not manage
// network exposure or DNS delegation.
package oob

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Interaction is one recorded callback.
type Interaction struct {
	Token      string
	Protocol   string // "http" or "dns"
	SourceIP   string
	ReceivedAt time.Time
	RawRequest string // method+path+headers (http) or question name (dns), bounded in size
}

const maxRawRequestBytes = 2048

// Store is a thread-safe, in-memory record of interactions keyed by token.
// A token is the unique label the payload engine embeds in a callback
// value (e.g. "<token>.<oobHost>"), so lookups are by exact token, not by
// full hostname: this package extracts the leftmost DNS label itself.
type Store struct {
	mu    sync.Mutex
	byTok map[string][]Interaction
}

// NewStore returns an empty, ready-to-use Store.
func NewStore() *Store {
	return &Store{byTok: make(map[string][]Interaction)}
}

func (s *Store) record(token string, in Interaction) {
	if token == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	list := s.byTok[token]
	// Bound memory: keep at most the first 50 interactions per token.
	if len(list) >= 50 {
		return
	}
	s.byTok[token] = append(list, in)
}

// Lookup returns all interactions recorded so far for token, oldest first.
func (s *Store) Lookup(token string) []Interaction {
	s.mu.Lock()
	defer s.mu.Unlock()
	src := s.byTok[token]
	out := make([]Interaction, len(src))
	copy(out, src)
	return out
}

// Wait blocks (bounded by ctx/timeout) until at least one interaction is
// recorded for token, polling the store, or returns the empty slice if none
// arrives in time. This is the primary call used by an active scan step
// after sending an OOB-class payload: it should run concurrently with (or
// shortly after) the triggering request, bounded by a short per-target
// timeout so a non-vulnerable target doesn't stall the whole scan.
func (s *Store) Wait(ctx context.Context, token string, timeout time.Duration) []Interaction {
	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		if hits := s.Lookup(token); len(hits) > 0 {
			return hits
		}
		if time.Now().After(deadline) {
			return nil
		}
		select {
		case <-ctx.Done():
			return s.Lookup(token)
		case <-ticker.C:
		}
	}
}

// tokenFromHost extracts the leftmost DNS label from a host like
// "<token>.interactions.example.com" or "<token>.interactions.example.com:8080".
// It returns "" if host has fewer than two labels (nothing to correlate).
func tokenFromHost(host string) string {
	host = strings.ToLower(host)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 || labels[0] == "" {
		return ""
	}
	return labels[0]
}

// tokenFromHostAgainstDomain extracts a per-request token label from host,
// but only when host is exactly "<token>.<domain>" (case-insensitive,
// ignoring an optional port on either side). A host equal to domain itself,
// one with more than one extra label, or one that doesn't have domain as a
// suffix at all, yields no token — callers should fall back to path-based
// correlation instead of misreading the listener's own domain as a token.
func tokenFromHostAgainstDomain(host, domain string) string {
	host = strings.ToLower(host)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	domain = strings.ToLower(domain)
	if d, _, err := net.SplitHostPort(domain); err == nil {
		domain = d
	}
	if domain == "" || !strings.HasSuffix(host, "."+domain) {
		return ""
	}
	label := strings.TrimSuffix(host, "."+domain)
	if label == "" || strings.Contains(label, ".") {
		return ""
	}
	return label
}

// tokenFromPath extracts a token used as the first path segment, e.g. a
// callback shaped as "http://oob.example.com/<token>/xxe" where the
// callback host itself isn't per-token (useful when wildcard DNS for the
// listener's own domain isn't available, only a single A record is).
func tokenFromPath(path string) string {
	path = strings.TrimPrefix(path, "/")
	if path == "" {
		return ""
	}
	if i := strings.IndexByte(path, '/'); i >= 0 {
		return path[:i]
	}
	return path
}

// HTTPListener records inbound HTTP requests as interactions, correlating
// by subdomain label first and falling back to the first path segment.
type HTTPListener struct {
	Store *Store
	// Domain is the listener's own base callback domain (matching
	// payload.Engine.OOBCallbackHost, e.g. "collab.example"), used to tell
	// a genuine per-request token subdomain ("<token>.collab.example")
	// apart from a bare request to the listener's own host
	// ("collab.example", with no token label at all). When Domain is set,
	// a host-based token is only extracted when it has exactly one label
	// in front of Domain; a request whose Host is Domain itself (no extra
	// label) falls straight through to path-based correlation. When Domain
	// is left empty, HTTPListener falls back to the original leftmost-label
	// heuristic, which is only safe when the listener is reached
	// exclusively via per-token subdomains (never via a path-only callback
	// or a bare request to the listener's own host/IP).
	Domain string
	// ResponseStatus is returned to every caller; defaults to 200 so
	// probes that merely check "did the request succeed" don't themselves
	// create a detectable anomaly.
	ResponseStatus int
}

func (h HTTPListener) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var token string
	if h.Domain != "" {
		token = tokenFromHostAgainstDomain(r.Host, h.Domain)
	} else {
		token = tokenFromHost(r.Host)
	}
	if token == "" {
		token = tokenFromPath(r.URL.Path)
	}
	raw := captureRawHTTP(r)
	srcIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	if srcIP == "" {
		srcIP = r.RemoteAddr
	}
	h.Store.record(token, Interaction{
		Token:      token,
		Protocol:   "http",
		SourceIP:   srcIP,
		ReceivedAt: time.Now().UTC(),
		RawRequest: raw,
	})
	status := h.ResponseStatus
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
}

func captureRawHTTP(r *http.Request) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s %s %s\nHost: %s\n", r.Method, r.URL.RequestURI(), r.Proto, r.Host)
	for name, values := range r.Header {
		for _, v := range values {
			fmt.Fprintf(&sb, "%s: %s\n", name, v)
			if sb.Len() > maxRawRequestBytes {
				return sb.String()[:maxRawRequestBytes]
			}
		}
	}
	if r.Body != nil {
		body, _ := io.ReadAll(io.LimitReader(r.Body, maxRawRequestBytes))
		if len(body) > 0 {
			sb.WriteString("\n")
			sb.Write(body)
		}
	}
	if sb.Len() > maxRawRequestBytes {
		return sb.String()[:maxRawRequestBytes]
	}
	return sb.String()
}

// NewHTTPServer wraps an HTTPListener in an *http.Server bound to addr. The
// caller owns the returned server's lifecycle (call ListenAndServe in a
// goroutine, Shutdown/Close when done); this keeps the package free of
// global state and easy to run multiple independent listeners in tests.
func NewHTTPServer(addr string, store *Store) *http.Server {
	return NewHTTPServerWithDomain(addr, store, "")
}

// NewHTTPServerWithDomain is NewHTTPServer, but tells the listener its own
// base callback domain so it can tell a genuine per-token subdomain apart
// from a bare request to the listener's own host — see
// HTTPListener.Domain. Callers that configure payload.Engine.OOBCallbackHost
// should pass that same host here.
func NewHTTPServerWithDomain(addr string, store *Store, domain string) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           HTTPListener{Store: store, Domain: domain},
		ReadHeaderTimeout: 5 * time.Second,
	}
}

// DNSListener is a minimal, read-only DNS query listener: it parses just
// enough of an incoming UDP DNS query to extract the question name and
// record an interaction, then (optionally) replies with a generic
// NXDOMAIN-equivalent so the resolver doesn't hang. It implements no actual
// zone data and must not be exposed as a general-purpose resolver; it is
// only useful when this host's IP is already the authoritative nameserver
// for the configured OOB callback domain.
type DNSListener struct {
	Store *Store
	conn  *net.UDPConn
}

// ListenDNS binds a UDP socket on addr (e.g. ":53") and returns a
// *DNSListener ready to Serve. Binding :53 typically requires elevated
// privileges; callers running without them should use a high port and rely
// on external port-forwarding/NAT.
func ListenDNS(addr string, store *Store) (*DNSListener, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("oob: resolving DNS listen address: %w", err)
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, fmt.Errorf("oob: binding DNS listener: %w", err)
	}
	return &DNSListener{Store: store, conn: conn}, nil
}

// Close stops the listener.
func (d *DNSListener) Close() error {
	if d.conn == nil {
		return nil
	}
	return d.conn.Close()
}

// Serve reads queries until ctx is done or the socket errors/closes.
func (d *DNSListener) Serve(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		d.conn.Close()
	}()
	buf := make([]byte, 512)
	for {
		n, src, err := d.conn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return fmt.Errorf("oob: reading DNS query: %w", err)
		}
		msg := append([]byte(nil), buf[:n]...)
		go d.handleQuery(msg, src)
	}
}

func (d *DNSListener) handleQuery(msg []byte, src *net.UDPAddr) {
	name, qid, ok := parseDNSQuestionName(msg)
	if !ok {
		return
	}
	token := tokenFromHost(name)
	d.Store.record(token, Interaction{
		Token:      token,
		Protocol:   "dns",
		SourceIP:   src.IP.String(),
		ReceivedAt: time.Now().UTC(),
		RawRequest: name,
	})
	// Best-effort empty-answer (NOERROR, 0 answers) reply so the resolver
	// doesn't retry/hang; failure to reply is not an error for our purposes
	// since the interaction has already been recorded.
	if reply := buildEmptyDNSReply(msg, qid); reply != nil {
		_, _ = d.conn.WriteToUDP(reply, src)
	}
}

// parseDNSQuestionName extracts the QNAME from the first question of a DNS
// message using only the standard-library binary package — enough to read
// the label sequence, not a general DNS parser. It returns false if the
// message is too short or malformed to safely parse.
func parseDNSQuestionName(msg []byte) (name string, id uint16, ok bool) {
	const headerLen = 12
	if len(msg) < headerLen+1 {
		return "", 0, false
	}
	id = binary.BigEndian.Uint16(msg[0:2])
	qdCount := binary.BigEndian.Uint16(msg[4:6])
	if qdCount == 0 {
		return "", id, false
	}
	var labels []string
	i := headerLen
	for {
		if i >= len(msg) {
			return "", id, false
		}
		length := int(msg[i])
		if length == 0 {
			i++
			break
		}
		// Reject compression pointers (top two bits set): a question name
		// at the start of a freshly-parsed query is never compressed in
		// practice, and refusing them avoids any pointer-chasing logic
		// that could loop or read out of bounds.
		if length&0xC0 != 0 {
			return "", id, false
		}
		i++
		if i+length > len(msg) {
			return "", id, false
		}
		labels = append(labels, string(msg[i:i+length]))
		i += length
		if len(labels) > 32 {
			return "", id, false // defensive cap; real names are far shorter
		}
	}
	return strings.Join(labels, "."), id, true
}

// buildEmptyDNSReply builds a minimal NOERROR/0-answers response that
// mirrors the original question, so resolvers treat the token lookup as
// "no record" rather than retrying or erroring out. It reuses the original
// query bytes verbatim for the header+question section and only flips the
// QR bit and sets RA, which avoids re-encoding the question ourselves.
func buildEmptyDNSReply(query []byte, id uint16) []byte {
	if len(query) < 12 {
		return nil
	}
	reply := append([]byte(nil), query...)
	// Flags: QR=1 (response), RA=1 (recursion available), RCODE=0 (NOERROR).
	reply[2] = 0x80
	reply[3] = 0x80
	// ANCOUNT=NSCOUNT=ARCOUNT=0 already true for a bare query copy; only
	// QDCOUNT (bytes 4-5) is preserved from the original.
	binary.BigEndian.PutUint16(reply[0:2], id)
	return reply
}
