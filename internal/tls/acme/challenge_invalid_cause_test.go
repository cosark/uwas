package acme

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// invalidChallenge is the body a CA returns for a failed validation: the
// challenge (or order) is "invalid" and carries the reason in its "error"
// problem document (RFC 8555 §7.1.5, §8.2).
func invalidChallenge(w http.ResponseWriter, _ *http.Request) {
	json.NewEncoder(w).Encode(map[string]any{
		"status": "invalid",
		"error": map[string]string{
			"type":   "urn:ietf:params:acme:error:unauthorized",
			"detail": "Invalid response from http://example.com/.well-known/acme-challenge/tok: 404",
		},
	})
}

// TestWaitForStatusReportsInvalidChallengeCause pins that an invalid challenge
// is reported with the CA's own reason. A failed HTTP-01 validation is the
// commonest way issuance fails, and "status became invalid" alone leaves the
// operator unable to tell a 404 on the token path from a DNS or firewall
// problem — the same gap the non-2xx branches of this file already close.
func TestWaitForStatusReportsInvalidChallengeCause(t *testing.T) {
	stub := newACMEStub(t, invalidChallenge)

	_, err := stub.client.waitForStatus(context.Background(), stub.orderURL, "valid", 5)
	if err == nil {
		t.Fatal("PROBLEM CONFIRMED: an invalid challenge returned no error")
	}
	want := "Invalid response from http://example.com/.well-known/acme-challenge/tok: 404"
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("EXPECTED: error carrying the CA's reason %q\nACTUAL: %q\nPROBLEM CONFIRMED", want, err.Error())
	}
	if !strings.Contains(err.Error(), "urn:ietf:params:acme:error:unauthorized") {
		t.Errorf("error %q does not name the problem type", err.Error())
	}
	if got := stub.polls(); got != 1 {
		t.Errorf("polled %d times, want exactly 1", got)
	}
}

// TestWaitForStatusInvalidWithoutProblemKeepsMessage is the control: an invalid
// status with no error document still stops at once with the plain message.
func TestWaitForStatusInvalidWithoutProblemKeepsMessage(t *testing.T) {
	stub := newACMEStub(t, func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"status": "invalid"})
	})

	_, err := stub.client.waitForStatus(context.Background(), stub.orderURL, "valid", 5)
	if err == nil || !strings.Contains(err.Error(), "status became invalid") {
		t.Fatalf("error = %v, want %q", err, "status became invalid")
	}
	if got := stub.polls(); got != 1 {
		t.Errorf("polled %d times, want exactly 1", got)
	}
}

// TestWaitForStatusInvalidProblemShapes covers the problem-document shapes the
// message is built from, and a malformed one that must not hide the failure.
func TestWaitForStatusInvalidProblemShapes(t *testing.T) {
	tests := []struct {
		name    string
		problem any
		wantSub string
	}{
		{"detail only", map[string]string{"detail": "no route to host"}, "no route to host"},
		{"type only", map[string]string{"type": "urn:x:dns"}, "urn:x:dns"},
		{"empty object", map[string]string{}, "status became invalid"},
		{"not an object", "boom", "status became invalid"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stub := newACMEStub(t, func(w http.ResponseWriter, _ *http.Request) {
				json.NewEncoder(w).Encode(map[string]any{"status": "invalid", "error": tt.problem})
			})
			_, err := stub.client.waitForStatus(context.Background(), stub.orderURL, "valid", 5)
			if err == nil || !strings.Contains(err.Error(), tt.wantSub) {
				t.Fatalf("error = %v, want it to contain %q", err, tt.wantSub)
			}
			if got := stub.polls(); got != 1 {
				t.Errorf("polled %d times, want exactly 1", got)
			}
		})
	}
}
