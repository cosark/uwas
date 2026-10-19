package proxy

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// mirrorForwardedBackend is a real shadow backend reached over the wire, so the
// assertions below describe the headers a shadow would actually receive rather
// than an intermediate value.
type mirrorForwardedBackend struct {
	*httptest.Server
	hdr chan http.Header
}

func newMirrorForwardedBackend(t *testing.T) *mirrorForwardedBackend {
	t.Helper()
	pb := &mirrorForwardedBackend{hdr: make(chan http.Header, 4)}
	pb.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		pb.hdr <- r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(pb.Close)
	return pb
}

// wait returns the headers the backend saw, or nil if no request arrived.
func (pb *mirrorForwardedBackend) wait() http.Header {
	select {
	case h := <-pb.hdr:
		return h
	case <-time.After(5 * time.Second):
		return nil
	}
}

func mirrorForForwardedTest(backend string) *Mirror {
	return NewMirror(MirrorConfig{
		Enabled:               true,
		Backend:               backend,
		Percent:               100,
		AllowPrivateUpstreams: true,
	}, testLogger())
}

// hostileForwardedRequest carries everything a client can put on the wire to
// name the address, scheme, host or path prefix its backend should believe in.
func hostileForwardedRequest(t *testing.T, tlsConn bool) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "http://shadow.local/page?q=1", nil)
	r.RemoteAddr = "203.0.113.7:4242"
	r.Host = "example.com"
	if tlsConn {
		r.TLS = &tls.ConnectionState{}
	}
	r.Header.Set("X-Forwarded-For", "1.2.3.4")
	r.Header.Set("X-Real-IP", "1.2.3.4")
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Forwarded-Host", "evil.example")
	r.Header.Set("X-Forwarded-Port", "443")
	r.Header.Set("X-Forwarded-Prefix", "/admin")
	r.Header.Set("X-Forwarded-Scheme", "https")
	r.Header.Set("X-Forwarded-Server", "evil.example")
	r.Header.Set("Forwarded", `for=1.2.3.4;proto=https;host=evil.example`)
	r.Header.Set("User-Agent", "probe/1.0")
	return r
}

// TestMirrorDoesNotForwardClientSuppliedIdentityHeaders pins the header policy
// on the third egress path in this package. doMirror copies the original
// request's headers, so without laundering it forwards the client's own
// X-Forwarded-* and Forwarded to a backend that trusts them, letting the client
// name the address, scheme, host or path prefix its shadow sees. The HTTP path
// (handler.go) and the websocket tunnel both overwrite this set.
func TestMirrorDoesNotForwardClientSuppliedIdentityHeaders(t *testing.T) {
	pb := newMirrorForwardedBackend(t)
	m := mirrorForForwardedTest(pb.URL)

	m.doMirror(hostileForwardedRequest(t, false), nil)

	h := pb.wait()
	if h == nil {
		t.Fatal("shadow backend never received the mirrored request")
	}
	for _, tc := range []struct{ name, attacker string }{
		{"X-Forwarded-For", "1.2.3.4"},
		{"X-Real-IP", "1.2.3.4"},
		{"X-Forwarded-Proto", "https"},
		{"X-Forwarded-Host", "evil.example"},
		{"X-Forwarded-Port", "443"},
		{"X-Forwarded-Prefix", "/admin"},
		{"X-Forwarded-Scheme", "https"},
		{"X-Forwarded-Server", "evil.example"},
		{"Forwarded", `for=1.2.3.4;proto=https;host=evil.example`},
	} {
		if got := h.Get(tc.name); got == tc.attacker {
			t.Errorf("client-supplied %s=%q reached the shadow backend verbatim; "+
				"the shadow must not be told the scheme, host, address or path "+
				"prefix the client chose", tc.name, got)
		}
	}
}

// TestMirrorSetsAuthoritativeForwardedHeaders covers the secondary branch: the
// mirror states the real client address, scheme and host rather than dropping
// the values, so the shadow sees what the live backend sees.
func TestMirrorSetsAuthoritativeForwardedHeaders(t *testing.T) {
	for _, tc := range []struct {
		name     string
		tlsConn  bool
		wantProt string
	}{
		{"plain", false, "http"},
		{"https", true, "https"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pb := newMirrorForwardedBackend(t)
			m := mirrorForForwardedTest(pb.URL)

			m.doMirror(hostileForwardedRequest(t, tc.tlsConn), nil)

			h := pb.wait()
			if h == nil {
				t.Fatal("shadow backend never received the mirrored request")
			}
			if got, want := h.Get("X-Forwarded-For"), "203.0.113.7"; got != want {
				t.Errorf("X-Forwarded-For = %q, want %q (the real peer, not the client's)", got, want)
			}
			if got, want := h.Get("X-Real-IP"), "203.0.113.7"; got != want {
				t.Errorf("X-Real-IP = %q, want %q", got, want)
			}
			if got := h.Get("X-Forwarded-Proto"); got != tc.wantProt {
				t.Errorf("X-Forwarded-Proto = %q, want %q", got, tc.wantProt)
			}
			if got, want := h.Get("X-Forwarded-Host"), "example.com"; got != want {
				t.Errorf("X-Forwarded-Host = %q, want %q (the request's own Host)", got, want)
			}
		})
	}
}

// TestMirrorControlOrdinaryHeadersAndMarkerSurvive is the control: the mirror
// still forwards ordinary headers and its own X-Mirror marker, so a failure in
// the tests above would be the header policy rather than a broken harness.
func TestMirrorControlOrdinaryHeadersAndMarkerSurvive(t *testing.T) {
	pb := newMirrorForwardedBackend(t)
	m := mirrorForForwardedTest(pb.URL)

	m.doMirror(hostileForwardedRequest(t, false), []byte("hello"))

	h := pb.wait()
	if h == nil {
		t.Fatal("shadow backend never received the mirrored request")
	}
	if got := h.Get("X-Mirror"); got != "true" {
		t.Errorf("X-Mirror = %q, want \"true\"", got)
	}
	if got, want := h.Get("User-Agent"), "probe/1.0"; got != want {
		t.Errorf("User-Agent = %q, want %q (ordinary headers must still forward)", got, want)
	}
}

// TestMirrorControlSSRFGuardStillBlocks keeps the egress guard in view: the
// header fix must not be confusable with loosening the upstream policy.
func TestMirrorControlSSRFGuardStillBlocks(t *testing.T) {
	m := NewMirror(MirrorConfig{
		Enabled: true,
		Backend: "http://169.254.169.254",
		Percent: 100,
	}, testLogger())

	m.doMirror(hostileForwardedRequest(t, false), nil) // warns and returns; nothing sent
}
