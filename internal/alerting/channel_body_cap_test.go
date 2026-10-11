package alerting

import (
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/uwaserver/uwas/internal/logger"
	"github.com/uwaserver/uwas/internal/notify"
)

// F13300: cron_failed carries the job's whole command line. Telegram refuses a
// sendMessage text over 4096 characters, so an over-long body must be cut
// before it reaches the channel; the history keeps the full text.
func channelDelivery(t *testing.T, msg string) (notify.Message, *Alerter) {
	t.Helper()
	var mu sync.Mutex
	var got notify.Message
	done := make(chan struct{}, 1)
	a := New(true, "", []notify.Channel{{Type: "telegram", Enabled: true}}, logger.New("error", "text"))
	a.sendChannel = func(_ notify.Channel, m notify.Message) error {
		mu.Lock()
		got = m
		mu.Unlock()
		done <- struct{}{}
		return nil
	}
	a.Alert(Alert{Level: "warning", Type: "cron_failed", Host: "a.example", Message: msg})
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("channel never received the alert")
	}
	mu.Lock()
	defer mu.Unlock()
	return got, a
}

func TestChannelBodyIsBounded(t *testing.T) {
	short := "cron job failed: backup.sh (exit 2)"
	if got, _ := channelDelivery(t, short); got.Body != short {
		t.Errorf("short body altered: %q", got.Body)
	}
	exact := strings.Repeat("x", maxChannelBody)
	if got, _ := channelDelivery(t, exact); got.Body != exact {
		t.Errorf("a body of exactly %d bytes was altered (len %d)", maxChannelBody, len(got.Body))
	}

	long := "cron job failed: " + strings.Repeat("echo 'a long inline script line';", 400) + " (exit 2)"
	got, a := channelDelivery(t, long)
	if len(got.Body) > maxChannelBody || len(got.Body) >= 4096 {
		t.Errorf("channel body is %d bytes, want <= %d", len(got.Body), maxChannelBody)
	}
	if !strings.HasSuffix(got.Body, "(truncated)") {
		t.Errorf("cut not marked: ...%q", got.Body[len(got.Body)-20:])
	}
	if hist := a.Alerts(); len(hist) != 1 || hist[0].Message != long {
		t.Errorf("history must keep the full message")
	}
}

func TestChannelBodyTruncationKeepsRunesIntact(t *testing.T) {
	// Every rune is 3 bytes, so the byte cut lands mid-rune unless the
	// truncation steps back to a rune start.
	msg := strings.Repeat("语", 5000)
	for _, max := range []int{maxChannelBody, maxChannelBody - 1, maxChannelBody - 2} {
		out := truncateForChannel(msg, max)
		if !utf8.ValidString(out) {
			t.Errorf("max=%d: result is not valid UTF-8", max)
		}
		if len(out) > max {
			t.Errorf("max=%d: result is %d bytes", max, len(out))
		}
	}
}
