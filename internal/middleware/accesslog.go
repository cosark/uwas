package middleware

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/uwaserver/uwas/internal/logger"
	"github.com/uwaserver/uwas/internal/router"
)

// sensitiveQueryParams are query parameter names that may contain secrets
// and should be redacted in logs.
var sensitiveQueryParams = []string{
	"token", "key", "code", "password", "secret", "api_key", "apikey",
	"access_token", "auth", "credential", "private", "signature",
}

// SanitizeURI returns the request URI with sensitive query parameters redacted.
//
// Exported so callers outside this package that log a request URI reuse this
// one implementation instead of re-deriving the redaction rules. The
// Cloudflare-origin guard in internal/server used to log the raw RequestURI,
// sending secrets to stdout alongside this access log.
func SanitizeURI(r *http.Request) string { return sanitizeURI(r) }

// sanitizeURI returns the request URI with sensitive query parameters redacted.
func sanitizeURI(r *http.Request) string {
	if r.URL.RawQuery == "" {
		return r.URL.Path
	}

	// Parse explicitly and fail CLOSED, mirroring redactReferer below.
	// r.URL.Query() discards ParseQuery's error and silently skips any pair it
	// cannot unescape, so a sensitive param carrying a malformed escape
	// (token=abc%zz) vanished from the map entirely: the redaction loop never
	// saw it, needsRedaction stayed false, and the raw URI — secret included —
	// was written to the access log. A redaction control must not fail open.
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return r.URL.Path + "?[REDACTED]"
	}
	needsRedaction := false
	for param := range query {
		if isSensitiveQueryParam(param) {
			needsRedaction = true
			break
		}
	}

	if !needsRedaction {
		return r.URL.RequestURI()
	}

	// Redact sensitive params
	redacted := make(url.Values)
	for k, v := range query {
		if isSensitiveQueryParam(k) {
			redacted[k] = []string{"[REDACTED]"}
		} else {
			redacted[k] = v
		}
	}
	return r.URL.Path + "?" + redacted.Encode()
}

// isSensitiveQueryParam returns true if the parameter name suggests it may contain secrets.
func isSensitiveQueryParam(name string) bool {
	name = strings.ToLower(name)
	for _, sensitive := range sensitiveQueryParams {
		if strings.Contains(name, sensitive) {
			return true
		}
	}
	return false
}

// AccessLog logs each completed request in structured format.
//
// enabled reports whether the line should be written. It is a function, not a
// bool, because the middleware chain is built once at startup and never
// rebuilt: a bool captured here would pin the setting to whatever the config
// said at boot, so toggling it from the panel would persist to disk, survive a
// reload and still change nothing until the process restarted. Reading it per
// request costs one atomic load and lets reload take effect immediately.
//
// A nil enabled means on, which is what an absent access_log block has always
// meant. When it reports false the request is passed straight through without
// even wrapping the ResponseWriter, so the disabled path stays free.
func AccessLog(log *logger.Logger, enabled func() bool) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if enabled != nil && !enabled() {
				next.ServeHTTP(w, r)
				return
			}

			start := time.Now()

			// Wrap response writer to capture status + bytes
			rw := router.NewResponseWriter(w)
			defer router.ReleaseResponseWriter(rw)

			// A handler that panics never returns here, and Recovery answers it
			// with a 500 further out, so the line has to be written while the
			// panic unwinds or the failed request is missing from the log (F8810).
			completed := false
			defer func() {
				if completed {
					return
				}
				status := rw.StatusCode()
				if rw.BytesWritten() == 0 {
					status = http.StatusInternalServerError
				}
				writeAccessLine(log, r, w, rw, start, status)
			}()
			next.ServeHTTP(rw, r)
			completed = true

			writeAccessLine(log, r, w, rw, start, rw.StatusCode())
		})
	}
}

// writeAccessLine emits the per-request access log line.
func writeAccessLine(log *logger.Logger, r *http.Request, w http.ResponseWriter, rw *router.ResponseWriter, start time.Time, status int) {
	duration := time.Since(start)

	fields := []any{
		"method", r.Method,
		"host", clipLogField(r.Host, maxLogHostBytes),
		"uri", clipLogField(sanitizeURI(r), maxLogURIBytes), // redact sensitive query params, then bound
		"status", status,
		"bytes", rw.BytesWritten(),
		"duration_ms", duration.Milliseconds(),
		"ttfb_ms", rw.TTFB().Milliseconds(),
		"remote", clientIP(nil, r),
		"user_agent", clipLogField(r.Header.Get("User-Agent"), maxLogHeaderBytes),
		"request_id", w.Header().Get("X-Request-ID"),
	}
	if tp := r.Header.Get("Traceparent"); tp != "" {
		fields = append(fields, "traceparent", clipLogField(tp, maxLogTraceparentBytes))
	}
	if ref := r.Referer(); ref != "" {
		// Also redact sensitive info from Referer
		fields = append(fields, "referer", logReferer(ref))
	}
	// The level follows the status. Every request used to be Info,
	// so lowering global.log_level to quieten the stream also hid the
	// failures — the one part worth keeping. A 5xx is the server
	// breaking; everything else is telemetry.
	//
	// 4xx deliberately stays Info: scanner 404s are constant on any
	// public site and would put the noise straight back into warn.
	// Blocked requests are already reported at Warn by the security
	// and WAF guards.
	if status >= 500 {
		log.Error("request", fields...)
		return
	}
	log.Info("request", fields...)
}

// Upper bounds for request-controlled values written to a log line. The
// listener accepts headers up to global.timeouts.max_header_bytes (1 MiB by
// default), so without a bound one request could write a log line of that size
// (F14800). The bounds are generous for real values (a User-Agent is a few
// hundred bytes, a host name at most 253) and only shorten the logged copy; the
// request itself is untouched.
const (
	maxLogHeaderBytes      = 1024
	maxLogHostBytes        = 255
	maxLogURIBytes         = 4096
	maxLogTraceparentBytes = 128
)

// clipLogField shortens s to at most max bytes, cutting on a UTF-8 boundary and
// marking the cut so a truncated value is not mistaken for the original.
func clipLogField(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := max
	// Back off to the start of a rune so the logged value stays valid UTF-8.
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "...[truncated " + strconv.Itoa(len(s)-cut) + " bytes]"
}

// logReferer is the Referer as it may be logged: sensitive query parameters
// redacted first, then bounded. Every log line that records a Referer goes
// through it, not only the access log (F14801).
func logReferer(ref string) string {
	return clipLogField(redactReferer(ref), maxLogHeaderBytes)
}

// redactReferer redacts sensitive query params from the Referer header.
func redactReferer(ref string) string {
	if !strings.Contains(ref, "?") {
		return ref
	}

	parts := strings.SplitN(ref, "?", 2)
	if len(parts) != 2 {
		return ref
	}

	query, err := url.ParseQuery(parts[1])
	if err != nil {
		return parts[0] + "?[REDACTED]"
	}

	redacted := false
	for k := range query {
		if isSensitiveQueryParam(k) {
			query.Set(k, "[REDACTED]")
			redacted = true
		}
	}

	if !redacted {
		return ref
	}

	return parts[0] + "?" + query.Encode()
}
