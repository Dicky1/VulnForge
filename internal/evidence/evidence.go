// Package evidence builds the redacted, size-bounded request/response
// evidence that VulnForge attaches to every blackbox (DAST) finding.
//
// It never stores raw secret values: headers and cookies known to carry
// credentials (Authorization, Cookie, Set-Cookie, X-Api-Key, etc.) are
// replaced with a fixed redaction marker, both in the captured headers and
// in the generated curl command. Bodies are capped to a caller-supplied
// byte limit so large responses don't bloat reports or leak more than a
// reviewer needs to confirm the finding.
package evidence

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/example/sast-dast-analyzer/internal/models"
)

// Redacted is substituted for any header or cookie value considered
// sensitive, both in stored evidence and in reproduction commands.
const Redacted = "[REDACTED]"

// DefaultMaxBody is used when Capture is called with maxBody <= 0.
const DefaultMaxBody = 4096

// sensitiveHeaders is matched case-insensitively against header names.
var sensitiveHeaders = map[string]bool{
	"authorization":       true,
	"cookie":              true,
	"set-cookie":          true,
	"x-api-key":           true,
	"x-auth-token":        true,
	"x-csrf-token":        true,
	"x-xsrf-token":        true,
	"proxy-authorization": true,
}

// IsSensitiveHeader reports whether a header name is treated as carrying a
// credential and therefore redacted in evidence and curl output.
func IsSensitiveHeader(name string) bool {
	return sensitiveHeaders[strings.ToLower(name)]
}

// Builder captures request/response evidence with a configured body cap.
type Builder struct {
	// MaxBody bounds how many bytes of each body are retained. Values <= 0
	// fall back to DefaultMaxBody.
	MaxBody int64
	// Now is used for the evidence timestamp; defaults to time.Now when nil,
	// overridable in tests for deterministic output.
	Now func() time.Time
}

func (b Builder) maxBody() int64 {
	if b.MaxBody <= 0 {
		return DefaultMaxBody
	}
	return b.MaxBody
}

func (b Builder) now() time.Time {
	if b.Now != nil {
		return b.Now()
	}
	return time.Now().UTC()
}

// Capture builds a *models.DASTEvidence populated with Request, Response,
// Timestamp and CurlCommand from a live exchange. req must be the exact
// request that was sent (req.Body is not consumed: pass the body bytes
// separately via reqBody, since the net/http request body is normally
// already drained by the transport). respBody is the response body bytes
// already read by the caller (callers typically use io.LimitReader before
// this point so large bodies are never fully buffered in memory).
func (b Builder) Capture(req *http.Request, reqBody []byte, resp *http.Response, respBody []byte) *models.DASTEvidence {
	ev := &models.DASTEvidence{
		Timestamp: b.now(),
	}
	if req != nil {
		ev.Method = req.Method
		ev.Request = b.captureRequest(req, reqBody)
		ev.CurlCommand = b.curlCommand(req, reqBody)
	}
	if resp != nil {
		ev.Response = b.captureResponse(resp, respBody)
	}
	return ev
}

func (b Builder) captureRequest(req *http.Request, body []byte) *models.RequestEvidence {
	r := &models.RequestEvidence{
		Method: req.Method,
		URL:    req.URL.String(),
	}
	r.Headers, r.RedactedHeaders = redactHeaders(req.Header)
	r.Body, r.BodyTruncated = truncate(body, b.maxBody())
	return r
}

func (b Builder) captureResponse(resp *http.Response, body []byte) *models.ResponseEvidence {
	r := &models.ResponseEvidence{StatusCode: resp.StatusCode}
	r.Headers, _ = redactHeaders(resp.Header)
	r.Body, r.BodyTruncated = truncate(body, b.maxBody())
	return r
}

func redactHeaders(h http.Header) (out []models.HTTPHeader, redactedNames []string) {
	names := make([]string, 0, len(h))
	for name := range h {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		for _, v := range h[name] {
			if IsSensitiveHeader(name) {
				out = append(out, models.HTTPHeader{Name: name, Value: Redacted})
				continue
			}
			out = append(out, models.HTTPHeader{Name: name, Value: v})
		}
		if IsSensitiveHeader(name) {
			redactedNames = append(redactedNames, name)
		}
	}
	return out, redactedNames
}

func truncate(body []byte, max int64) (string, bool) {
	if int64(len(body)) <= max {
		return string(body), false
	}
	if max < 0 {
		max = 0
	}
	return string(body[:max]), true
}

// curlCommand renders a reproducible, POSIX-shell-safe curl invocation for
// req. Every argument is single-quoted via shellQuote so header/body values
// can never break out of their argument or inject additional shell
// commands, regardless of their content. Sensitive header/cookie values are
// replaced with Redacted before quoting.
func (b Builder) curlCommand(req *http.Request, body []byte) string {
	var sb strings.Builder
	sb.WriteString("curl -sS -X ")
	sb.WriteString(shellQuote(req.Method))

	names := make([]string, 0, len(req.Header))
	for name := range req.Header {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		for _, v := range req.Header[name] {
			if IsSensitiveHeader(name) {
				v = Redacted
			}
			sb.WriteString(" -H ")
			sb.WriteString(shellQuote(fmt.Sprintf("%s: %s", name, v)))
		}
	}

	if len(body) > 0 {
		max := b.maxBody()
		truncated := false
		if int64(len(body)) > max {
			body = body[:max]
			truncated = true
		}
		sb.WriteString(" --data-raw ")
		sb.WriteString(shellQuote(string(body)))
		if truncated {
			sb.WriteString(" # body truncated for evidence")
		}
	}

	sb.WriteString(" ")
	sb.WriteString(shellQuote(req.URL.String()))
	return sb.String()
}

// shellQuote wraps s in single quotes for POSIX shells, escaping any
// embedded single quote as '\” (close quote, escaped quote, reopen quote).
// This makes it safe to place arbitrary, attacker-influenced byte strings
// (header values, payloads, URLs) into a shell command line without any
// risk of command injection via the generated evidence.
func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	var sb strings.Builder
	sb.WriteByte('\'')
	for i := 0; i < len(s); i++ {
		if s[i] == '\'' {
			sb.WriteString(`'\''`)
			continue
		}
		sb.WriteByte(s[i])
	}
	sb.WriteByte('\'')
	return sb.String()
}

// ReadLimited reads up to limit+1 bytes from r and reports whether the body
// was truncated, without ever buffering more than limit+1 bytes. Use this
// when capturing a body for evidence so a large or unbounded response
// cannot exhaust memory.
func ReadLimited(r io.Reader, limit int64) (data []byte, truncated bool, err error) {
	if limit < 0 {
		limit = 0
	}
	buf, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(buf)) > limit {
		return buf[:limit], true, nil
	}
	return buf, false, nil
}

// RestoreBody replaces resp.Body (which has typically already been read by
// ReadLimited) with a fresh reader over the captured bytes, so downstream
// code can still consume the body normally after evidence capture.
func RestoreBody(resp *http.Response, data []byte) {
	if resp == nil {
		return
	}
	resp.Body = io.NopCloser(bytes.NewReader(data))
}
