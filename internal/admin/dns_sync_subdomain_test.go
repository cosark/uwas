package admin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/uwaserver/uwas/internal/dnsmanager"
)

// subZoneProvider resolves any name under example.com to the example.com zone,
// like a real provider does for a subdomain, and stores zone-relative names
// ("@" for the apex) the way Hetzner and DigitalOcean report them.
type subZoneProvider struct{ *stubProvider }

func (p subZoneProvider) FindZoneByDomain(domain string) (*dnsmanager.Zone, error) {
	if domain == "example.com" || strings.HasSuffix(domain, ".example.com") {
		return p.stubProvider.FindZoneByDomain("example.com")
	}
	return nil, errNotFound
}

func syncDomain(t *testing.T, p *stubProvider, domain string) *httptest.ResponseRecorder {
	t.Helper()
	orig := testDNSProviderHook
	testDNSProviderHook = func() dnsmanager.Provider { return subZoneProvider{p} }
	defer func() { testDNSProviderHook = orig }()
	fakeExternalHost(t, "api.ipify.org:443", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("203.0.113.10"))
	}))
	s := testServer()
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, httptest.NewRequest("POST", "/api/v1/dns/"+domain+"/sync", nil))
	return rec
}

func contentOf(t *testing.T, p *stubProvider, name string) []string {
	t.Helper()
	recs, _ := p.ListRecords("z1")
	var out []string
	for _, r := range recs {
		if r.Name == name {
			out = append(out, r.Content)
		}
	}
	return out
}

// Syncing a subdomain must not rewrite the zone apex ("@") A record.
func TestDNSSyncSubdomainLeavesApexRecordAlone(t *testing.T) {
	p := newStubProvider()
	p.addZone("z1", "example.com")
	p.CreateRecord("z1", dnsmanager.Record{Type: "A", Name: "@", Content: "198.51.100.1", TTL: 300})

	rec := syncDomain(t, p, "blog.example.com")
	if rec.Code != 200 {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	if got := contentOf(t, p, "@"); len(got) != 1 || got[0] != "198.51.100.1" {
		t.Fatalf("EXPECTED: apex @ A record untouched (198.51.100.1)\nACTUAL: %v", got)
	}
}

// Control: syncing the apex itself still updates the "@" record.
func TestDNSSyncApexUpdatesApexRecord(t *testing.T) {
	p := newStubProvider()
	p.addZone("z1", "example.com")
	p.CreateRecord("z1", dnsmanager.Record{Type: "A", Name: "@", Content: "198.51.100.1", TTL: 300})

	rec := syncDomain(t, p, "example.com")
	if rec.Code != 200 {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	if got := contentOf(t, p, "@"); len(got) != 1 || got[0] != "203.0.113.10" {
		t.Fatalf("apex sync must update @ record, got %v", got)
	}
}

// Edge: an existing FQDN-named subdomain record is updated, apex untouched.
func TestDNSSyncSubdomainUpdatesOwnRecord(t *testing.T) {
	p := newStubProvider()
	p.addZone("z1", "example.com")
	p.CreateRecord("z1", dnsmanager.Record{Type: "A", Name: "@", Content: "198.51.100.1", TTL: 300})
	p.CreateRecord("z1", dnsmanager.Record{Type: "A", Name: "blog.example.com", Content: "198.51.100.2", TTL: 300})

	if rec := syncDomain(t, p, "blog.example.com"); rec.Code != 200 {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	if got := contentOf(t, p, "blog.example.com"); len(got) != 1 || got[0] != "203.0.113.10" {
		t.Fatalf("subdomain record not updated: %v", got)
	}
	if got := contentOf(t, p, "@"); len(got) != 1 || got[0] != "198.51.100.1" {
		t.Fatalf("apex changed: %v", got)
	}
}

// Edge: no subdomain record yet — one is created, apex untouched, repeat is idempotent.
func TestDNSSyncSubdomainCreatesRecordOnce(t *testing.T) {
	p := newStubProvider()
	p.addZone("z1", "example.com")
	p.CreateRecord("z1", dnsmanager.Record{Type: "A", Name: "@", Content: "198.51.100.1", TTL: 300})

	for i := 0; i < 2; i++ {
		if rec := syncDomain(t, p, "blog.example.com"); rec.Code != 200 {
			t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
		}
	}
	if got := contentOf(t, p, "blog.example.com"); len(got) != 1 || got[0] != "203.0.113.10" {
		t.Fatalf("expected exactly one created record, got %v", got)
	}
	if got := contentOf(t, p, "@"); len(got) != 1 || got[0] != "198.51.100.1" {
		t.Fatalf("apex changed: %v", got)
	}
}
