package server

// FetchFragment builds the ESI sub-request's *http.Request from the src
// attribute captured out of the fragment body, where the ESI matcher
// src="([^"]+)" happily captures a literal newline. url.Parse rejects control
// characters, so the constructor fails; before the fix the error was discarded
// and the next line dereferenced the nil request, panicking the request.
// These tests pin the error-not-panic contract and the unaffected path.

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/uwaserver/uwas/internal/router"
)

func TestFetchFragmentControlCharSrcReturnsError(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("control-character ESI src panicked: %v", r)
		}
	}()
	s := &Server{} // the constructor error surfaces before any lookup; no wiring needed
	parent := httptest.NewRequest("GET", "http://parent.test/page", nil)
	_, _, _, err := s.FetchFragment("site.test", "/frag\nx", parent)
	if err == nil {
		t.Fatal("control-character ESI src accepted with no error")
	}
	if !strings.Contains(err.Error(), "ESI") {
		t.Fatalf("expected an ESI-prefixed error, got: %v", err)
	}
}

func TestFetchFragmentWellFormedSrcStillSubrequests(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("well-formed ESI src panicked: %v", r)
		}
	}()
	s := &Server{vhosts: router.NewVHostRouter(nil)}
	parent := httptest.NewRequest("GET", "http://parent.test/page", nil)
	_, _, _, err := s.FetchFragment("site.test", "/frag", parent)
	if err == nil || !strings.Contains(err.Error(), "domain not found") {
		t.Fatalf("expected the domain-not-found error, got: %v", err)
	}
}
