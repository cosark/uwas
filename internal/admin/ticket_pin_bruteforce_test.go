package admin

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/uwaserver/uwas/internal/config"
	"github.com/uwaserver/uwas/internal/logger"
	"github.com/uwaserver/uwas/internal/metrics"
	"github.com/uwaserver/uwas/internal/middleware"
)

// pinChain is the production handler chain of an admin API with an API key and
// a PIN configured.
func pinChain(t *testing.T, apiKey, pin string) http.Handler {
	t.Helper()
	cfg := &config.Config{Global: config.GlobalConfig{Admin: config.AdminConfig{
		Listen: "127.0.0.1:0", APIKey: apiKey, PinCode: pin,
	}}}
	s := New(cfg, logger.New("error", "text"), metrics.New())
	s.configPath = filepath.Join(t.TempDir(), "uwas.yaml")
	return middleware.RequestID()(s.authMiddleware(requireJSONMiddleware(s.mux)))
}

func pinDo(h http.Handler, method, path string, hdr map[string]string) (int, string) {
	r := httptest.NewRequest(method, path, strings.NewReader(""))
	r.RemoteAddr = "127.0.0.1:50000"
	r.Host = "127.0.0.1:9443"
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec.Code, rec.Body.String()
}

// F16100: the PIN guards destructive routes against a stolen API key, and
// requirePin counts wrong guesses toward a lockout. A ticket, though, is minted
// by POST /auth/ticket, which compared X-Pin-Code without counting a failure,
// and a ticket redeemed on a PIN-gated route says whether it carried the PIN
// (403 pin_required without a header, which records nothing, versus passing the
// gate). Together they were an unlimited guessing oracle for the 6-digit PIN.
func TestTicketMintCountsWrongPINTowardLockout(t *testing.T) {
	const key, pin = "api-key-1", "000250"

	// Control: guessing through the gated route itself locks out.
	h := pinChain(t, key, pin)
	blocked := -1
	for i := 0; i < 40; i++ {
		hdr := map[string]string{"Authorization": "Bearer " + key, "X-Requested-With": "XMLHttpRequest", "X-Pin-Code": fmt.Sprintf("%06d", i)}
		if code, _ := pinDo(h, "DELETE", "/api/v1/auth/users/x", hdr); code == http.StatusTooManyRequests {
			blocked = i
			break
		}
	}
	if blocked < 0 || blocked > 15 {
		t.Fatalf("control: direct PIN guessing was never locked out (first 429 at guess %d)", blocked)
	}

	// The oracle: mint with a guess, then redeem the ticket on a PIN-gated route
	// without a PIN header; a ticket minted with the right PIN passes the gate.
	h = pinChain(t, key, pin)
	found, locked := "", -1
	for i := 0; i < 400 && found == ""; i++ {
		guess := fmt.Sprintf("%06d", i)
		code, body := pinDo(h, "POST", "/api/v1/auth/ticket", map[string]string{
			"Authorization": "Bearer " + key, "X-Requested-With": "XMLHttpRequest", "X-Pin-Code": guess,
			"Content-Type": "application/json",
		})
		if code == http.StatusTooManyRequests {
			locked = i
			break
		}
		if code != 200 {
			t.Fatalf("mint %s = %d %s", guess, code, body)
		}
		ticket := body[strings.Index(body, `"ticket":"`)+len(`"ticket":"`):]
		ticket = ticket[:strings.Index(ticket, `"`)]
		code, body = pinDo(h, "DELETE", "/api/v1/auth/users/x?ticket="+ticket, map[string]string{"X-Requested-With": "XMLHttpRequest"})
		if code == http.StatusTooManyRequests {
			locked = i
			break
		}
		if !strings.Contains(body, "pin_required") {
			found = guess
		}
	}
	if found != "" {
		t.Fatalf("PIN recovered through the ticket oracle (%s) after %d guesses with no lockout", found, 251)
	}
	if locked < 0 || locked > 15 {
		t.Fatalf("ticket-based PIN guessing was never locked out (first 429 at guess %d)", locked)
	}
}

// A correct PIN at mint still yields a PIN-bound ticket, and no PIN at mint
// still yields an unbound one without counting as a failure.
func TestTicketMintPINSemanticsUnchanged(t *testing.T) {
	const key, pin = "api-key-2", "424242"
	h := pinChain(t, key, pin)
	hdr := func(pinHdr string) map[string]string {
		m := map[string]string{"Authorization": "Bearer " + key, "X-Requested-With": "XMLHttpRequest", "Content-Type": "application/json"}
		if pinHdr != "" {
			m["X-Pin-Code"] = pinHdr
		}
		return m
	}
	redeem := func(pinHdr string) string {
		code, body := pinDo(h, "POST", "/api/v1/auth/ticket", hdr(pinHdr))
		if code != 200 {
			t.Fatalf("mint = %d %s", code, body)
		}
		ticket := body[strings.Index(body, `"ticket":"`)+len(`"ticket":"`):]
		ticket = ticket[:strings.Index(ticket, `"`)]
		_, out := pinDo(h, "DELETE", "/api/v1/auth/users/x?ticket="+ticket, map[string]string{"X-Requested-With": "XMLHttpRequest"})
		return out
	}
	if out := redeem(pin); strings.Contains(out, "pin_required") {
		t.Errorf("ticket minted with the right PIN did not satisfy the gate: %s", out)
	}
	for i := 0; i < 30; i++ { // no PIN header: never a failure, never a lockout
		if out := redeem(""); !strings.Contains(out, "pin_required") {
			t.Fatalf("ticket minted without a PIN passed the gate: %s", out)
		}
	}
}
