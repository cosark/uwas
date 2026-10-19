package admin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/uwaserver/uwas/internal/dnsmanager"
)

// spellingProvider resolves zones case-insensitively and ignores a trailing
// dot, like the real providers, and reports record names lower-case.
type spellingProvider struct{ *stubProvider }

func (p spellingProvider) FindZoneByDomain(domain string) (*dnsmanager.Zone, error) {
	d := strings.ToLower(strings.TrimSuffix(domain, "."))
	if d == "example.com" || strings.HasSuffix(d, ".example.com") {
		return p.stubProvider.FindZoneByDomain("example.com")
	}
	return nil, errNotFound
}

func syncSpelling(t *testing.T, p *stubProvider, domain string) *httptest.ResponseRecorder {
	t.Helper()
	orig := testDNSProviderHook
	testDNSProviderHook = func() dnsmanager.Provider { return spellingProvider{p} }
	defer func() { testDNSProviderHook = orig }()
	fakeExternalHost(t, "api.ipify.org:443", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("203.0.113.10"))
	}))
	s := testServer()
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, httptest.NewRequest("POST", "/api/v1/dns/"+domain+"/sync", nil))
	return rec
}

func aRecords(t *testing.T, p *stubProvider) []string {
	t.Helper()
	recs, _ := p.ListRecords("z1")
	var out []string
	for _, r := range recs {
		if r.Type == "A" {
			out = append(out, r.Name+"="+r.Content)
		}
	}
	return out
}

// Domain access is decided on the canonical spelling of the host, so a sync
// requested as "Blog.Example.COM" or "blog.example.com." must find the
// provider's lower-case "blog.example.com" record and update it, not create a
// second A record next to it.
func TestDNSSyncMatchesExistingRecordAcrossHostSpelling(t *testing.T) {
	for _, spelling := range []string{"blog.example.com", "Blog.Example.COM", "blog.example.com."} {
		t.Run(spelling, func(t *testing.T) {
			p := newStubProvider()
			p.addZone("z1", "example.com")
			p.CreateRecord("z1", dnsmanager.Record{Type: "A", Name: "blog.example.com", Content: "198.51.100.2", TTL: 300})
			p.CreateRecord("z1", dnsmanager.Record{Type: "A", Name: "shop.example.com", Content: "198.51.100.3", TTL: 300})

			for i := 0; i < 2; i++ { // repeat call stays idempotent
				if rec := syncSpelling(t, p, spelling); rec.Code != 200 {
					t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
				}
			}
			got := aRecords(t, p)
			want := []string{"blog.example.com=203.0.113.10", "shop.example.com=198.51.100.3"}
			if strings.Join(got, ",") != strings.Join(want, ",") {
				t.Fatalf("EXPECTED: %v\nACTUAL: %v", want, got)
			}
		})
	}
}
