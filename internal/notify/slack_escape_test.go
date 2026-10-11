package notify

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Slack message text is mrkdwn: <!channel>, <@U123> and <https://evil|label> act
// unless &, < and > are escaped. A cron_failed alert carries the cron command,
// which the operator did not write, so it must not reach Slack raw (F9900).
func TestSendSlackEscapesControlSequences(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var p map[string]string
		json.Unmarshal(b, &p)
		got = p["text"]
	}))
	defer srv.Close()

	send := func(m Message) string {
		t.Helper()
		got = ""
		if err := sendSlack(srv.URL, m); err != nil {
			t.Fatal(err)
		}
		return got
	}

	// Control: ordinary text is unchanged.
	if text := send(Message{Level: "info", Title: "Cert renewed", Body: "ok: 3 days (exit 0)", Source: "a.test"}); !strings.Contains(text, "ok: 3 days (exit 0)") {
		t.Errorf("plain text altered: %q", text)
	}

	for _, field := range []string{"title", "body", "source"} {
		m := Message{Level: "warning", Title: "t", Body: "b", Source: "s"}
		hostile := "x <!channel> <@U123> <https://evil.example|click> &amp; y"
		switch field {
		case "title":
			m.Title = hostile
		case "body":
			m.Body = hostile
		case "source":
			m.Source = hostile
		}
		text := send(m)
		for _, raw := range []string{"<!channel>", "<@U123>", "<https://evil.example|"} {
			if strings.Contains(text, raw) {
				t.Errorf("%s: Slack control sequence %q reached the message: %q", field, raw, text)
			}
		}
		// "&" is escaped first, so an already-escaped entity is not turned into markup.
		if !strings.Contains(text, "&amp;amp;") {
			t.Errorf("%s: ampersand not escaped: %q", field, text)
		}
	}

	if got := slackEscape(""); got != "" {
		t.Errorf("empty string: %q", got)
	}
}
