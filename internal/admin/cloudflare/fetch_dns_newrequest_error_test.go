package cloudflare

// Regression tests for the FetchDNSRecordsWithClient NewRequest fix.
//
// zoneID is interpolated raw into the request URL and arrives from the admin
// route's {id} path value. The NewRequest error used to be discarded, so a
// control character in the zone ID (e.g. %0A in the request path) left req
// nil and the next line panicked with a bare nil-pointer dereference — the
// admin request died without a JSON error. The helper now returns the
// NewRequest error; PurgeCacheWithClient handles the same discarded error for
// its API-derived zone IDs.

import (
	"errors"
	"net/http"
	"strings"
	"testing"
)

type noNetworkTransport struct{}

func (noNetworkTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("no network in test")
}

// A control character in the zone ID yields an error, not a panic.
func TestFetchDNSRecordsWithClientControlCharZoneIDReturnsError(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panic for control-character zone ID: %v", r)
		}
	}()
	client := &http.Client{Transport: noNetworkTransport{}}
	_, err := FetchDNSRecordsWithClient(client, "tok", "x\ny")
	if err == nil {
		t.Fatal("expected an error for a control-character zone ID, got nil")
	}
}

// A well-formed zone ID reaches the transport and surfaces its error.
func TestFetchDNSRecordsWithClientWellFormedZoneIDSurfacesTransportError(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("control path panicked: %v", r)
		}
	}()
	client := &http.Client{Transport: noNetworkTransport{}}
	_, err := FetchDNSRecordsWithClient(client, "tok", "good-zone-id")
	if err == nil {
		t.Fatal("expected the transport error to surface, got nil")
	}
	// The client wraps transport errors (*url.Error); match on the message.
	if !strings.Contains(err.Error(), "no network in test") {
		t.Fatalf("expected the transport error, got: %v", err)
	}
}
