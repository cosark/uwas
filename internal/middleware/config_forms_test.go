package middleware

import (
	"net/http/httptest"
	"testing"

	"github.com/uwaserver/uwas/internal/logger"
)

func hotlinkDecision(refs, exts []string, path, referer string) (bool, int) {
	g := HotlinkGuard(logger.New("error", "text"), refs, exts)
	r := httptest.NewRequest("GET", path, nil)
	r.Host = "site.test"
	if referer != "" {
		r.Header.Set("Referer", referer)
	}
	w := httptest.NewRecorder()
	ok := g(w, r)
	return ok, w.Code
}

// F13900: an allowed_referers entry written as a URL ("https://partner.com",
// the form a Referer header itself has) never matched, so the partner it named
// was refused as if it were a stranger.
func TestHotlinkAllowedReferersAcceptURLForms(t *testing.T) {
	for _, entry := range []string{"partner.com", "https://partner.com", "https://partner.com/", "HTTP://Partner.com/path", "partner.com:8443", "www.partner.com"} {
		ref := "https://partner.com/page"
		if entry == "partner.com:8443" {
			ref = "https://partner.com:8443/page"
		}
		if ok, code := hotlinkDecision([]string{entry}, nil, "/a.jpg", ref); !ok {
			t.Errorf("entry %q: partner referer refused (code %d)", entry, code)
		}
		if ok, _ := hotlinkDecision([]string{entry}, nil, "/a.jpg", "https://partner.com.evil.example/page"); ok {
			t.Errorf("entry %q: look-alike referer allowed", entry)
		}
		if ok, _ := hotlinkDecision([]string{entry}, nil, "/a.jpg", "https://evil.example/page"); ok {
			t.Errorf("entry %q: stranger allowed", entry)
		}
	}
	// An empty entry must not match anything (it used to match any referer
	// host ending in a dot).
	if ok, _ := hotlinkDecision([]string{""}, nil, "/a.jpg", "https://evil.example./page"); ok {
		t.Error("empty allowed_referers entry matched a referer")
	}
}

// F13901: docs/SPECIFICATION.md lists extensions without the dot ("jpg"). The
// guard compared them as raw path suffixes, so "jpg" also protected
// "/camera.mjpg" and "/notjpg".
func TestHotlinkExtensionsMeanFileExtensions(t *testing.T) {
	stranger := "https://evil.example/page"
	for _, exts := range [][]string{{"jpg"}, {".jpg"}, {"JPG"}} {
		if ok, _ := hotlinkDecision([]string{"partner.com"}, exts, "/a.jpg", stranger); ok {
			t.Errorf("extensions %v: /a.jpg not protected", exts)
		}
		if ok, _ := hotlinkDecision([]string{"partner.com"}, exts, "/A.JPG", stranger); ok {
			t.Errorf("extensions %v: /A.JPG not protected", exts)
		}
		for _, p := range []string{"/camera.mjpg", "/notjpg", "/images/jpg"} {
			if ok, code := hotlinkDecision([]string{"partner.com"}, exts, p, stranger); !ok {
				t.Errorf("extensions %v: %s refused (code %d), it has no .jpg extension", exts, p, code)
			}
		}
	}
}

// F13902: a path parameter ("/a.jpg;x=1") hid the extension from the guard
// while an upstream that strips path parameters still served the image.
func TestHotlinkSeesThroughPathParameters(t *testing.T) {
	stranger := "https://evil.example/page"
	for _, p := range []string{"/a.jpg;x=1", "/img;v=2/a.jpg", "/a.jpg;jsessionid=9"} {
		if ok, _ := hotlinkDecision([]string{"partner.com"}, nil, p, stranger); ok {
			t.Errorf("%s: hotlink protection skipped", p)
		}
	}
	// Control: a path that has no protected extension either way.
	if ok, _ := hotlinkDecision([]string{"partner.com"}, nil, "/page;x=1", stranger); !ok {
		t.Error("/page;x=1 refused")
	}
	// Multi-dot extensions keep working.
	if ok, _ := hotlinkDecision([]string{"partner.com"}, []string{".tar.gz"}, "/x/backup.tar.gz", stranger); ok {
		t.Error(".tar.gz not protected")
	}
	if ok, _ := hotlinkDecision([]string{"partner.com"}, []string{".tar.gz"}, "/x/backup.gz", stranger); !ok {
		t.Error("/x/backup.gz refused by a .tar.gz rule")
	}
	// A parameter that itself ends in a protected extension stays protected.
	if ok, _ := hotlinkDecision([]string{"partner.com"}, nil, "/download;v=2.zip", stranger); ok {
		t.Error("/download;v=2.zip lost its protection")
	}
}

// F13903: security.rate_limit.by accepted "header:" and "HEADER:" only, so the
// natural spelling "Header:X-Api-Key" silently counted per client address.
func TestRateLimitKeyPrefixIsCaseInsensitive(t *testing.T) {
	for _, by := range []string{"header:X-Api-Key", "Header:X-Api-Key", "HEADER:X-Api-Key", "hEaDeR:X-Api-Key", "header: X-Api-Key"} {
		if !KnownRateLimitKey(by) {
			t.Errorf("by=%q reported unknown", by)
		}
		rl := NewRateLimiter(t.Context(), 1, 60e9)
		rl.SetKeyBy(by)
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = "198.51.100.7:1"
		r.Header.Set("X-Api-Key", "k1")
		if got := rl.Key(r); got != "h:x-api-key:k1" {
			t.Errorf("by=%q: key %q, want the header bucket", by, got)
		}
	}
	// Controls: ip, empty and a form that really is unknown.
	rl := NewRateLimiter(t.Context(), 1, 60e9)
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "198.51.100.7:1"
	r.Header.Set("X-Api-Key", "k1")
	for _, by := range []string{"", "ip", "IP"} {
		rl.SetKeyBy(by)
		if got := rl.Key(r); got != "198.51.100.7" {
			t.Errorf("by=%q: key %q", by, got)
		}
	}
	if KnownRateLimitKey("hdr:X-Api-Key") || KnownRateLimitKey("header:") {
		t.Error("malformed by reported known")
	}
}
