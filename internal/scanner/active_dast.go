package scanner

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/example/sast-dast-analyzer/internal/evidence"
	"github.com/example/sast-dast-analyzer/internal/models"
	"github.com/example/sast-dast-analyzer/internal/oob"
	"github.com/example/sast-dast-analyzer/internal/payload"
)

// ActiveDAST performs explicit opt-in, non-destructive active black-box
// testing: it injects internal/payload probes into the existing query
// parameters of a single authorized URL, reuses the same scope-enforcing,
// rate-limited transport as BaselineDAST (same-origin redirects only, the
// same request budget, the same optional bearer/cookie session), and
// attaches full redacted request/response evidence (internal/evidence) to
// every resulting finding. It never invents new parameters, paths, or
// request bodies — only values already present in the authorized URL are
// mutated — and it only ever issues GET requests. Callers must gate this
// behind an explicit "--active" style opt-in; BaselineDAST remains the
// default, passive-only scan path.
type ActiveDAST struct {
	Timeout      time.Duration
	MaxBodyBytes int64

	// OOBStore, if set, is consulted after each out-of-band-class attempt
	// (e.g. SSRFOutOfBand): ScanURL waits up to OOBWait for a matching
	// interaction before continuing to the next probe. If nil, OOB-class
	// attempts are still sent (so an externally-run listener can still
	// observe them) but ScanURL itself will not produce a finding for them;
	// correlate later via OOBStore.Lookup against the logged token.
	OOBStore *oob.Store
	// OOBCallbackHost is the externally reachable host used to build OOB
	// callback URLs (see payload.Engine.OOBCallbackHost). Leaving it empty
	// disables every OOB-class probe.
	OOBCallbackHost string
	// OOBWait bounds how long ScanURL waits for a callback per OOB attempt.
	// Defaults to 3s.
	OOBWait time.Duration
}

// MaxActiveDASTParams bounds how many existing query parameters a single
// ScanURL call will inject into, so a URL with an unexpectedly large query
// string cannot blow up the request budget unexpectedly.
const MaxActiveDASTParams = 25

var errActiveDASTNoParams = errors.New("active DAST requires at least one query parameter on the authorized URL to inject into")

// ScanURL runs the standard non-destructive active probe set
// (payload.Engine.GenerateAll, plus a boolean-based SQLi pair) against every
// existing query parameter of rawURL. options.MaxRequests/Interval bound
// active requests exactly as they bound passive ones: every attempt,
// including the one baseline request per parameter, consumes one unit of
// the same budget.
func (d ActiveDAST) ScanURL(ctx context.Context, rawURL string, options DASTRunOptions) ([]models.Finding, []models.ToolOutput, error) {
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, nil, fmt.Errorf("unsupported default HTTP transport")
	}
	return d.scanURLWithTransport(ctx, rawURL, options, base)
}

// The caller supplies a base transport; production uses the default system
// trust store. Tests use a transport trusting only a local TLS fixture (or
// a plain httptest.Server, where no custom trust is needed at all).
func (d ActiveDAST) scanURLWithTransport(ctx context.Context, rawURL string, options DASTRunOptions, base *http.Transport) ([]models.Finding, []models.ToolOutput, error) {
	scope, err := parseDASTURL(rawURL)
	if err != nil {
		return nil, nil, err
	}
	query := scope.Query()
	if len(query) == 0 {
		return nil, nil, errActiveDASTNoParams
	}
	if len(query) > MaxActiveDASTParams {
		return nil, nil, fmt.Errorf("active DAST supports at most %d query parameters per URL", MaxActiveDASTParams)
	}
	client, closeTransport, err := newActiveDASTClient(base, scope, options)
	if err != nil {
		return nil, nil, err
	}
	defer closeTransport()

	maxBody := d.MaxBodyBytes
	if maxBody <= 0 {
		maxBody = evidence.DefaultMaxBody
	}
	oobWait := d.OOBWait
	if oobWait <= 0 {
		oobWait = 3 * time.Second
	}
	evBuilder := evidence.Builder{MaxBody: maxBody}
	engine := payload.Engine{OOBCallbackHost: d.OOBCallbackHost}

	names := make([]string, 0, len(query))
	for name := range query {
		names = append(names, name)
	}
	sort.Strings(names)

	var findings []models.Finding
	var outputs []models.ToolOutput
	seenFinding := make(map[string]bool) // class+point: at most one finding per class per point

	send := func(reqURL *url.URL) (*http.Response, []byte, bool, *models.DASTEvidence, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL.String(), nil)
		if err != nil {
			return nil, nil, false, nil, err
		}
		req.Header.Set("User-Agent", "VulnForge/1.0 active-security-check")
		resp, err := client.Do(req)
		if err != nil {
			return nil, nil, false, nil, err
		}
		body, truncated, _ := evidence.ReadLimited(resp.Body, maxBody)
		resp.Body.Close()
		evidence.RestoreBody(resp, body)
		ev := evBuilder.Capture(req, nil, resp, body)
		return resp, body, truncated, ev, nil
	}

	for _, name := range names {
		if ctx.Err() != nil {
			return findings, outputs, ctx.Err()
		}
		point := payload.InjectionPoint{Kind: payload.PointQuery, Name: name}
		original := query.Get(name)

		baselineResp, baselineBody, _, _, err := send(cloneURLWithParam(scope, name, original))
		out := newActiveDASTOutput(scope)
		if err != nil {
			out.Endpoint.Error = classifyActiveDASTError(err)
			outputs = append(outputs, out)
			if errors.Is(err, errDASTRequestLimit) {
				return findings, outputs, nil
			}
			continue
		}
		out.ExitCode = 0
		out.Endpoint.StatusCode = baselineResp.StatusCode
		outputs = append(outputs, out)
		baselineBodyStr := string(baselineBody)

		attempts := engine.GenerateAll(point, payload.ContextUnknown)
		trueAttempt, falseAttempt := engine.SQLiBooleanBased(point, original)
		attempts = append(attempts, trueAttempt, falseAttempt)

		var trueBody, falseBody string
		var trueStatus, falseStatus int
		var haveTrue, haveFalse bool

		for _, attempt := range attempts {
			if ctx.Err() != nil {
				return findings, outputs, ctx.Err()
			}
			resp, body, _, ev, err := send(cloneURLWithParam(scope, name, attempt.Value))
			out := newActiveDASTOutput(scope)
			if err != nil {
				out.Endpoint.Error = classifyActiveDASTError(err)
				outputs = append(outputs, out)
				if errors.Is(err, errDASTRequestLimit) {
					return findings, outputs, nil
				}
				continue
			}
			out.ExitCode = 0
			out.Endpoint.StatusCode = resp.StatusCode
			outputs = append(outputs, out)
			ev.PayloadClass = string(attempt.Class)
			ev.InjectionPoint = attempt.Point.String()

			switch attempt.Class {
			case payload.ClassSQLiBoolean:
				if attempt.Value == trueAttempt.Value {
					trueBody, trueStatus, haveTrue = string(body), resp.StatusCode, true
				} else {
					falseBody, falseStatus, haveFalse = string(body), resp.StatusCode, true
				}
				continue
			case payload.ClassSSRFOOB, payload.ClassXXEOOB, payload.ClassCommandInjOOB:
				if d.OOBStore == nil || attempt.OOBToken == "" {
					continue
				}
				hits := d.OOBStore.Wait(ctx, attempt.OOBToken, oobWait)
				if len(hits) == 0 {
					continue
				}
				in := hits[0]
				ev.OOBToken = attempt.OOBToken
				ev.OOBInteraction = &models.OOBInteraction{Token: in.Token, Protocol: in.Protocol, SourceIP: in.SourceIP, ReceivedAt: in.ReceivedAt, RawRequest: in.RawRequest}
				findings = append(findings, oobFinding(attempt, ev))
				continue
			}

			if f, ok := detectActiveFinding(attempt, resp, string(body), baselineBodyStr, ev); ok {
				key := string(attempt.Class) + "|" + attempt.Point.String()
				if !seenFinding[key] {
					seenFinding[key] = true
					findings = append(findings, f)
				}
			}
		}

		if haveTrue && haveFalse {
			if f, ok := detectBooleanSQLi(point, trueBody, trueStatus, falseBody, falseStatus, baselineBodyStr); ok {
				findings = append(findings, f)
			}
		}
	}
	return findings, outputs, nil
}

func newActiveDASTOutput(scope *url.URL) models.ToolOutput {
	endpoint := &models.DASTEndpoint{RequestedURL: reportDASTURL(scope)}
	return models.ToolOutput{Tool: "active-dast", TargetURL: endpoint.RequestedURL, Endpoint: endpoint, ExitCode: -1}
}

func classifyActiveDASTError(err error) string {
	switch {
	case errors.Is(err, errDASTScope):
		return "redirect_out_of_scope"
	case errors.Is(err, errDASTRedirectLimit):
		return "redirect_limit"
	case errors.Is(err, errDASTRequestLimit):
		return "request_limit"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	default:
		return "request_failed"
	}
}

// cloneURLWithParam returns a copy of scope with the named query parameter
// set to value, leaving every other parameter untouched.
func cloneURLWithParam(scope *url.URL, name, value string) *url.URL {
	u := *scope
	q := scope.Query()
	q.Set(name, value)
	u.RawQuery = q.Encode()
	return &u
}

// newActiveDASTClient builds a scope- and rate-limited HTTP client
// identical to BaselineDAST's, except that it never auto-follows redirects:
// active probes (notably the open-redirect class) need the raw 3xx response
// and its unmodified Location header, not the final destination.
func newActiveDASTClient(base *http.Transport, scope *url.URL, options DASTRunOptions) (*http.Client, func(), error) {
	var header, value string
	switch options.SessionKind {
	case "":
	case "bearer", "cookie":
		if scope.Scheme != "https" {
			return nil, nil, fmt.Errorf("DAST sessions require an HTTPS origin")
		}
		if strings.TrimSpace(options.Session) == "" || strings.IndexFunc(options.Session, func(r rune) bool { return r < ' ' || r > '~' }) >= 0 {
			return nil, nil, fmt.Errorf("DAST session value must be non-empty printable ASCII")
		}
		header, value = "Cookie", options.Session
		if options.SessionKind == "bearer" {
			header, value = "Authorization", "Bearer "+options.Session
		}
	default:
		return nil, nil, fmt.Errorf("DAST session must be bearer or cookie")
	}
	timeout := 15 * time.Second
	if options.Interval < 0 || options.Interval > time.Minute {
		return nil, nil, fmt.Errorf("DAST interval must be between zero and one minute")
	}
	if options.MaxRequests < 1 || options.MaxRequests > 5000 {
		return nil, nil, fmt.Errorf("active DAST request limit must be 1-5000")
	}
	transport := base.Clone()
	if options.Direct {
		transport.Proxy = nil
	}
	transport.MaxResponseHeaderBytes = 1 << 20
	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{}
	} else {
		transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	}
	if transport.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		transport.TLSClientConfig.MinVersion = tls.VersionTLS12
	}
	transport.TLSClientConfig.InsecureSkipVerify = false
	run := &dastTransport{base: transport, scope: scope, interval: options.Interval, remaining: options.MaxRequests, sessionHeader: header, sessionValue: value}
	client := &http.Client{Timeout: timeout, Transport: run, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	return client, transport.CloseIdleConnections, nil
}

// dbErrorSignatures are substrings strongly associated with a database
// engine's raw error output leaking into an HTTP response: a strong signal
// of unsanitized query concatenation. Matching is case-insensitive.
var dbErrorSignatures = []string{
	"you have an error in your sql syntax",
	"warning: mysqli",
	"warning: mysql_",
	"unterminated quoted string",
	"unterminated quoted identifier",
	"pg_query(): query failed",
	"postgresql query failed",
	"sqlite3.operationalerror",
	"sqlite3::sqlexception",
	"ora-01756",
	"ora-00933",
	"microsoft odbc driver",
	"unclosed quotation mark after the character string",
	"system.data.sqlclient.sqlexception",
}

func detectActiveFinding(attempt payload.Attempt, resp *http.Response, body, baselineBody string, ev *models.DASTEvidence) (models.Finding, bool) {
	switch attempt.Class {
	case payload.ClassXSSReflected:
		if payload.ReflectsCanary(body, attempt) {
			return makeActiveFinding(attempt, ev, "Reflected Cross-Site Scripting (XSS)", models.SeverityHigh,
				"The injected marker for query parameter \""+attempt.Point.Name+"\" was reflected unescaped in the response body.",
				"Context-encode all user-supplied output for the context it is rendered in, and set a restrictive Content-Security-Policy."), true
		}
	case payload.ClassSQLiError:
		lower := strings.ToLower(body)
		for _, sig := range dbErrorSignatures {
			if strings.Contains(lower, sig) && !strings.Contains(strings.ToLower(baselineBody), sig) {
				return makeActiveFinding(attempt, ev, "SQL Injection (error-based)", models.SeverityCritical,
					"A database error signature appeared in the response after injecting a single quote into \""+attempt.Point.Name+"\", and was absent from the baseline response.",
					"Use parameterized queries/prepared statements for every value built from user input; never concatenate input into SQL text."), true
			}
		}
	case payload.ClassOpenRedirect:
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			loc := resp.Header.Get("Location")
			if loc != "" && redirectsOffHost(loc, resp.Request.URL) {
				return makeActiveFinding(attempt, ev, "Open Redirect", models.SeverityMedium,
					"Setting \""+attempt.Point.Name+"\" to an external URL caused a "+fmt.Sprint(resp.StatusCode)+" redirect to that external host.",
					"Validate redirect targets against an allow-list of relative paths or known-good hosts before issuing a redirect."), true
			}
		}
	case payload.ClassPathTraversal:
		if containsTraversalMarker(body) && !containsTraversalMarker(baselineBody) {
			return makeActiveFinding(attempt, ev, "Path Traversal", models.SeverityCritical,
				"The response for \""+attempt.Point.Name+"\" contains content characteristic of a well-known system file, absent from the baseline response.",
				"Resolve and canonicalize file paths derived from user input, and reject any path that escapes the intended base directory."), true
		}
	case payload.ClassSSTI:
		if strings.Contains(body, "49") && !strings.Contains(baselineBody, "49") {
			return makeActiveFinding(attempt, ev, "Server-Side Template Injection (SSTI)", models.SeverityCritical,
				"Submitting a template arithmetic probe via \""+attempt.Point.Name+"\" caused the evaluated result (49) to appear in the response, absent from the baseline.",
				"Never pass user-controlled input into a template string that is itself compiled/evaluated; use the templating engine's data-binding API instead."), true
		}
	case payload.ClassCRLFInjection:
		if len(resp.Header.Values(attempt.Canary)) > 0 {
			return makeActiveFinding(attempt, ev, "CRLF / HTTP Response Splitting", models.SeverityHigh,
				"Injecting a CRLF sequence into \""+attempt.Point.Name+"\" caused an attacker-controlled response header to be set.",
				"Strip or reject CR/LF characters from any user input that is reflected into a response header."), true
		}
	case payload.ClassHostHeaderInject:
		if strings.Contains(body, attempt.Canary) {
			return makeActiveFinding(attempt, ev, "Host Header Injection", models.SeverityMedium,
				"An attacker-controlled Host/X-Forwarded-Host value was reflected back in the response body.",
				"Validate the Host header against an allow-list of expected hostnames; do not trust it for link generation or cache keys."), true
		}
	}
	return models.Finding{}, false
}

func detectBooleanSQLi(point payload.InjectionPoint, trueBody string, trueStatus int, falseBody string, falseStatus int, baselineBody string) (models.Finding, bool) {
	if trueStatus != falseStatus && (trueStatus >= 400) != (falseStatus >= 400) {
		return makeBooleanSQLiFinding(point), true
	}
	// A true condition should resemble the original (unfiltered) response;
	// a false condition should differ noticeably from both. Require a
	// significant length delta to avoid flagging normal page variance.
	const minDelta = 32
	trueLen, falseLen, baseLen := len(trueBody), len(falseBody), len(baselineBody)
	closeToBaseline := absInt(trueLen-baseLen) < minDelta
	differsFromTrue := absInt(trueLen-falseLen) >= minDelta
	if closeToBaseline && differsFromTrue {
		return makeBooleanSQLiFinding(point), true
	}
	return models.Finding{}, false
}

func makeBooleanSQLiFinding(point payload.InjectionPoint) models.Finding {
	f := makeFinding("active-dast", "DAST-SQLI-BOOL", point.String(), 0,
		"Injecting a always-true condition into \""+point.Name+"\" reproduced the original response, while an always-false condition produced a materially different response.",
		string(models.SeverityCritical), "")
	f.Title = "SQL Injection (boolean-based blind)"
	f.Language = "web"
	f.Remediation = "Use parameterized queries/prepared statements for every value built from user input; never concatenate input into SQL text."
	f.DASTEvidence = &models.DASTEvidence{PayloadClass: string(payload.ClassSQLiBoolean), InjectionPoint: point.String()}
	return f
}

func absInt(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

func containsTraversalMarker(body string) bool {
	markers := []string{"root:x:0:0:", "root:*:0:0:", "[extensions]", "for 16-bit app support"}
	for _, m := range markers {
		if strings.Contains(body, m) {
			return true
		}
	}
	return false
}

// redirectsOffHost reports whether location (as sent by the server, which
// may be relative) resolves to a host different from reqURL's — the
// signature of an unsanitized open redirect, as opposed to a normal
// same-site redirect (e.g. adding a trailing slash or a login bounce).
func redirectsOffHost(location string, reqURL *url.URL) bool {
	target, err := url.Parse(location)
	if err != nil {
		return false
	}
	resolved := reqURL.ResolveReference(target)
	return !strings.EqualFold(resolved.Hostname(), reqURL.Hostname())
}

func makeActiveFinding(attempt payload.Attempt, ev *models.DASTEvidence, title string, sev models.Severity, desc, remediation string) models.Finding {
	f := makeFinding("active-dast", "DAST-"+strings.ToUpper(string(attempt.Class)), attempt.Point.String(), 0, desc, string(sev), "")
	f.Title = title
	f.Language = "web"
	f.Remediation = remediation
	f.DASTEvidence = ev
	return f
}

func oobFinding(attempt payload.Attempt, ev *models.DASTEvidence) models.Finding {
	class := string(attempt.Class)
	f := makeFinding("active-dast", "DAST-OOB-"+strings.ToUpper(class), attempt.Point.String(), 0,
		"An out-of-band callback was received after injecting an out-of-band probe into \""+attempt.Point.Name+"\", confirming the target fetched or resolved attacker-controlled input.",
		string(models.SeverityCritical), "")
	switch attempt.Class {
	case payload.ClassSSRFOOB:
		f.Title = "Server-Side Request Forgery (out-of-band confirmed)"
		f.Remediation = "Validate and allow-list any server-side outbound request target; block requests to internal/metadata address ranges."
	case payload.ClassXXEOOB:
		f.Title = "XML External Entity Injection (out-of-band confirmed)"
		f.Remediation = "Disable external entity and DTD processing in the XML parser."
	case payload.ClassCommandInjOOB:
		f.Title = "OS Command Injection (out-of-band confirmed)"
		f.Remediation = "Never pass user input to a shell; use exec APIs that take argument arrays without shell interpretation."
	}
	f.Language = "web"
	f.DASTEvidence = ev
	return f
}
