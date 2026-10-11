package uwastls

import (
	"context"
	"crypto/tls"
	"reflect"
	"sync"
	"testing"

	"github.com/uwaserver/uwas/internal/config"
)

const (
	idnUnicode = "bücher.example"
	idnPuny    = "xn--bcher-kva.example"
)

// F13000: browsers send the A-label form of an IDN host in SNI while the
// config may spell the host in Unicode. The handshake allowlist, certificate
// lookup and ACME identifiers all have to use the one A-label form.
func TestUnicodeConfiguredHostIsServedForPunycodeSNI(t *testing.T) {
	m := testManager(t, []config.Domain{{
		Host:    idnUnicode,
		Aliases: []string{"straße.example"},
		SSL:     config.SSLConfig{Mode: "auto"},
	}})
	cert, _, _ := generateTestCert(t, idnPuny)
	m.RegisterCert(idnUnicode, cert)

	// SNI spellings a client can send: A-label, upper case, trailing dot.
	for _, sni := range []string{idnPuny, "XN--BCHER-KVA.EXAMPLE", idnPuny + "."} {
		got, err := m.GetCertificate(&tls.ClientHelloInfo{ServerName: sni})
		if err != nil || got != cert {
			t.Errorf("SNI %q: cert=%v err=%v, want the registered certificate", sni, got == cert, err)
		}
	}
	// The alias is reachable by its A-label too (handshake allowed; no cert
	// yet, so the failure must not be a "not configured" rejection).
	if !m.isDomainConfigured("xn--strae-oqa.example") {
		t.Error("alias A-label rejected by the handshake allowlist")
	}
	// Control: a host nobody configured stays rejected.
	if m.isDomainConfigured("xn--other-xyz.example") {
		t.Error("unconfigured IDN host was allowed")
	}
	if !m.HasCert(idnPuny) || !m.HasCert(idnUnicode) {
		t.Error("HasCert does not find the certificate under both spellings")
	}
}

// ACME only accepts A-labels as DNS identifiers; a Unicode identifier makes
// newOrder fail, so a forced renewal must request the A-label.
func TestACMEIsAskedForTheALabel(t *testing.T) {
	m := testManager(t, []config.Domain{{Host: idnUnicode, SSL: config.SSLConfig{Mode: "auto"}}})
	var mu sync.Mutex
	var asked [][]string
	m.acmeObtainFunc = func(ctx context.Context, names []string) (*tls.Certificate, []byte, []byte, error) {
		mu.Lock()
		asked = append(asked, append([]string(nil), names...))
		mu.Unlock()
		return nil, nil, nil, context.Canceled
	}
	_ = m.RenewCert(context.Background(), idnUnicode)
	if want := [][]string{{idnPuny}}; !reflect.DeepEqual(asked, want) {
		t.Errorf("ACME names = %v, want %v", asked, want)
	}

	hosts := tlsHostsForDomain(config.Domain{Host: idnUnicode, Aliases: []string{"WWW.straße.example"}})
	for _, h := range hosts {
		if h != config.CanonicalHost(h) {
			t.Errorf("tlsHostsForDomain returned %q, not a canonical A-label", h)
		}
	}
}

// An earlier version stored a certificate under a directory named after the
// Unicode host; it must still be found under the A-label.
func TestLegacyUnicodeCertDirectoryStillLoads(t *testing.T) {
	m := testManager(t, []config.Domain{{Host: idnUnicode, SSL: config.SSLConfig{Mode: "auto"}}})
	cert, certPEM, keyPEM := generateTestCert(t, idnPuny)
	if err := m.storage.Save(idnUnicode, cert, keyPEM, certPEM); err != nil {
		t.Fatal(err)
	}
	m.LoadExistingCerts()
	if !m.HasCert(idnPuny) {
		t.Error("certificate stored under the Unicode directory is not found by its A-label")
	}
}

// Control: an ASCII host behaves as before (case and trailing dot folded).
func TestASCIIHostUnchangedByCanonicalization(t *testing.T) {
	m := testManager(t, []config.Domain{{Host: "plain.example", SSL: config.SSLConfig{Mode: "auto"}}})
	cert, _, _ := generateTestCert(t, "plain.example")
	m.RegisterCert("Plain.Example", cert)
	got, err := m.GetCertificate(&tls.ClientHelloInfo{ServerName: "PLAIN.example."})
	if err != nil || got != cert {
		t.Errorf("ASCII SNI: cert match=%v err=%v", got == cert, err)
	}
}
