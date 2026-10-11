package alerting

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// F9700: a webhook URL that fails url.Parse in the SSRF pre-check (a pasted
// trailing newline) came back as a *url.Error whose text is the whole URL, and
// the delivery-failure log line printed it — the URL is a credential.
func TestWebhookPrecheckErrorOmitsURL(t *testing.T) {
	const secret = "T0K3N-s3cr3t-9700"
	a := New(true, "https://hooks.example.com/services/"+secret+"\n", nil, nil)
	err := a.sendWebhook(Alert{Level: "warning", Type: "t", Host: "h", Message: "m", Time: time.Now()})
	if err == nil {
		t.Fatal("want an error for an unparsable webhook URL")
	}
	if strings.Contains(err.Error(), secret) {
		t.Errorf("error leaks the webhook URL: %v", err)
	}
	if !strings.Contains(err.Error(), "invalid control character") {
		t.Errorf("error lost its cause: %v", err)
	}
}

func TestRedactURLErrorKeepsOtherErrors(t *testing.T) {
	plain := errors.New("blocked 127.0.0.1 (SSRF)")
	if got := redactURLError(plain); got != plain {
		t.Errorf("non-url error was rewritten: %v", got)
	}
	if redactURLError(nil) != nil {
		t.Error("nil must stay nil")
	}
}
