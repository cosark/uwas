package uwastls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"

	"github.com/uwaserver/uwas/internal/config"
	"github.com/uwaserver/uwas/internal/logger"
)

type ocspFixture struct {
	cert   *tls.Certificate
	issuer *x509.Certificate
	key    *ecdsa.PrivateKey
	leaf   *x509.Certificate
	srv    *httptest.Server
	hits   atomic.Int32
}

func newOCSPFixture(t *testing.T, host string, withOCSPServer bool) *ocspFixture {
	t.Helper()
	f := &ocspFixture{}
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTpl := &x509.Certificate{
		SerialNumber: big.NewInt(100), Subject: pkix.Name{CommonName: "f7602 CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	f.issuer, _ = x509.ParseCertificate(caDER)
	f.key = caKey

	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.hits.Add(1)
		resp, err := ocsp.CreateResponse(f.issuer, f.issuer, ocsp.Response{
			Status: ocsp.Good, SerialNumber: f.leaf.SerialNumber,
			ThisUpdate: time.Now().Add(-time.Minute), NextUpdate: time.Now().Add(7 * 24 * time.Hour),
		}, f.key)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "application/ocsp-response")
		w.Write(resp)
	}))
	t.Cleanup(f.srv.Close)

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTpl := &x509.Certificate{
		SerialNumber: big.NewInt(200), Subject: pkix.Name{CommonName: host}, DNSNames: []string{host},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(80 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if withOCSPServer {
		leafTpl.OCSPServer = []string{f.srv.URL}
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTpl, f.issuer, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	f.leaf, _ = x509.ParseCertificate(leafDER)
	f.cert = &tls.Certificate{Certificate: [][]byte{leafDER, caDER}, PrivateKey: leafKey, Leaf: f.leaf}
	return f
}

func (f *ocspFixture) staple(t *testing.T, thisUpdate, nextUpdate time.Time) []byte {
	t.Helper()
	resp, err := ocsp.CreateResponse(f.issuer, f.issuer, ocsp.Response{
		Status: ocsp.Good, SerialNumber: f.leaf.SerialNumber, ThisUpdate: thisUpdate, NextUpdate: nextUpdate,
	}, f.key)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func stapleNextUpdate(t *testing.T, m *Manager, host string) (time.Time, bool) {
	t.Helper()
	v, _ := m.certs.Load(host)
	c := v.(*tls.Certificate)
	if len(c.OCSPStaple) == 0 {
		return time.Time{}, false
	}
	r, err := ocsp.ParseResponse(c.OCSPStaple, nil)
	if err != nil {
		t.Fatal(err)
	}
	return r.NextUpdate, true
}

// F7602: an OCSP staple used to be fetched once, when a certificate was
// issued. A certificate loaded from disk at start-up never got one, and the
// staple of a long-lived certificate ran out (OCSP responses last days,
// certificates months) while the server kept presenting it. The renewal pass
// now refreshes missing and stale staples.
func TestRenewalPassRefreshesOCSPStaples(t *testing.T) {
	m := NewManager(config.ACMEConfig{Storage: t.TempDir()}, nil, logger.New("error", "text"))

	// controls: a certificate without an OCSP responder URL is left alone,
	// and a staple that is still fresh is not replaced.
	noOCSP := newOCSPFixture(t, "noocsp.example", false)
	m.certs.Store("noocsp.example", noOCSP.cert)
	fresh := newOCSPFixture(t, "fresh.example", true)
	fresh.cert.OCSPStaple = fresh.staple(t, time.Now().Add(-time.Hour), time.Now().Add(6*24*time.Hour))
	m.certs.Store("fresh.example", fresh.cert)

	expired := newOCSPFixture(t, "expired.example", true)
	expired.cert.OCSPStaple = expired.staple(t, time.Now().Add(-10*24*time.Hour), time.Now().Add(-3*24*time.Hour))
	oldExpired := expired.cert
	m.certs.Store("expired.example", expired.cert)
	loaded := newOCSPFixture(t, "loaded.example", true) // as LoadExistingCerts leaves it: no staple
	m.certs.Store("loaded.example", loaded.cert)

	m.checkRenewals(context.Background())

	if _, ok := stapleNextUpdate(t, m, "noocsp.example"); ok {
		t.Error("a certificate without an OCSP responder must stay unstapled")
	}
	if n := fresh.hits.Load(); n != 0 {
		t.Errorf("a fresh staple was refetched (%d fetches)", n)
	}
	if next, ok := stapleNextUpdate(t, m, "expired.example"); !ok || !next.After(time.Now()) {
		t.Errorf("expired staple not replaced (stapled=%v nextUpdate=%v)", ok, next)
	}
	if _, ok := stapleNextUpdate(t, m, "loaded.example"); !ok {
		t.Error("certificate loaded without a staple did not get one")
	}

	// A certificate is shared with in-flight handshakes: the refresh swaps in
	// a copy and leaves the one they hold untouched.
	if oldNext, err := ocsp.ParseResponse(oldExpired.OCSPStaple, nil); err != nil || oldNext.NextUpdate.After(time.Now()) {
		t.Errorf("the shared certificate was mutated in place (err=%v)", err)
	}
	got, err := m.GetCertificate(&tls.ClientHelloInfo{ServerName: "expired.example"})
	if err != nil || got == oldExpired || len(got.OCSPStaple) == 0 {
		t.Errorf("handshake does not see the refreshed certificate (err=%v)", err)
	}
}

// A responder that fails leaves the existing certificate and staple in place.
func TestOCSPRefreshFailureKeepsCertificate(t *testing.T) {
	m := NewManager(config.ACMEConfig{Storage: t.TempDir()}, nil, logger.New("error", "text"))
	f := newOCSPFixture(t, "down.example", true)
	old := f.staple(t, time.Now().Add(-10*24*time.Hour), time.Now().Add(-3*24*time.Hour))
	f.cert.OCSPStaple = old
	m.certs.Store("down.example", f.cert)
	f.srv.Close()

	m.refreshOCSP(context.Background())

	v, _ := m.certs.Load("down.example")
	if v.(*tls.Certificate) != f.cert || string(f.cert.OCSPStaple) != string(old) {
		t.Error("a failed refresh replaced the certificate")
	}
}
